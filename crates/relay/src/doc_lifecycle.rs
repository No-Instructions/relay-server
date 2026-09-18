//! Document lifecycle ownership.
//!
//! This module owns document identity and lifecycle for the process:
//! `DocRegistry` is the only way a document enters or leaves memory, and
//! each resident doc is owned by a lifecycle actor whose mailbox order
//! decides every race between attachment and eviction. A caller either
//! observes a resident doc or waits until the transition that affects it
//! (a racing load, or an eviction's final store flush) has completed.
//!
//! Slot rules (the single-instance invariant):
//! - A doc is installed or removed only while holding the slot mutex, and
//!   only on a slot that is not `defunct`.
//! - A waiter that acquires the mutex and finds `defunct` retries from the
//!   map: the slot was removed while it waited.
//! - Slots are removed at eviction and on failed loads — nothing else
//!   removes them, so the registry holds no per-doc-id residue.
//!
//! Eviction rules (orphans are unrepresentable by message order):
//! - Only the actor decides eviction, by processing `Evict` in mailbox
//!   order: any attach granted before it makes `connections > 0` and the
//!   eviction is refused. An attach that reaches a dying actor gets no
//!   reply and retries through the slot mutex, which the evictor holds
//!   until the final flush is on the store and the slot is gone.
//! - A doc leaves memory only clean: the eviction flush loops until the
//!   dirty bit clears, and persistent store failure refuses the eviction
//!   instead of dropping unflushed state.

use dashmap::DashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot, watch, Mutex as AsyncMutex,
};
use y_sweet_core::{
    doc_sync::DocWithSyncKv,
    metrics::RelayMetrics,
    sync::awareness::Awareness,
    sync_kv::{PersistOutcome, SyncKv},
};

/// Result of one actor-supervised persist sub-task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistTaskResult {
    Persisted,
    /// The store had changed behind us (a direct write, e.g. a backfill)
    /// and this persist overwrote it. Written, but worth counting.
    Clobbered,
    Failed,
}

/// Result of one inline flush attempt in the evict/drain loops.
enum FlushStep {
    Progress,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    Socket,
    Http,
    Subdoc,
}

impl AttachKind {
    fn as_str(&self) -> &'static str {
        match self {
            AttachKind::Socket => "socket",
            AttachKind::Http => "http",
            AttachKind::Subdoc => "subdoc",
        }
    }
}

/// The actor-side view of a doc's lifecycle. `Loading` is a registry-slot
/// phase, so the observable states start at the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Active { connections: usize },
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictOutcome {
    Evicted,
    Refused,
    /// No resident doc under this id (never loaded, already evicted, or
    /// an eviction/failed load raced us).
    Absent,
}

/// Lifecycle knobs, shared by every actor the registry spawns.
#[derive(Clone, Copy)]
pub struct LifecycleConfig {
    pub checkpoint_freq: Duration,
    /// Whether idle docs are evicted at all. When false the idle deadline
    /// is never armed and docs stay resident for the process lifetime.
    pub doc_gc: bool,
}

impl LifecycleConfig {
    /// Idle deadline: how long a doc sits at zero connections before its
    /// actor requests eviction (matches the historical two-probe cadence).
    fn idle_timeout(&self) -> Duration {
        self.checkpoint_freq * 2
    }
}

/// Mailbox messages for a doc's lifecycle actor. Mailbox order is the
/// arbiter for attach-vs-evict races.
pub enum DocMsg {
    Attach {
        kind: AttachKind,
        /// Granted by the actor incrementing its count before replying. A
        /// dropped reply means the actor is evicting or gone: retry
        /// through the registry's slot mutex.
        reply: oneshot::Sender<()>,
    },
    Detach {
        kind: AttachKind,
    },
    /// Wake-up hint from the doc's clean→dirty edge. Flush scheduling
    /// re-reads the bit; an in-flight persist is tracked separately.
    Dirty,
    /// A subdoc pushing its snapshot into this (parent) doc's metadata
    /// index — cross-doc mutation goes through the owner's mailbox.
    UpdateSubdocSnapshot {
        child_id: String,
        snapshot: Vec<u8>,
    },
    Evict {
        reply: oneshot::Sender<EvictOutcome>,
    },
    /// Process-drain flush: persist until clean and report whether there
    /// was anything to flush. The doc stays resident.
    Drain {
        reply: oneshot::Sender<bool>,
    },
    /// Persist every change observed before this mailbox message. Used by
    /// protocols whose acknowledgement is also a durability promise.
    DurabilityBarrier {
        reply: oneshot::Sender<Result<(), String>>,
    },
}

/// Actor → registry sweeper messages.
enum Control {
    EvictRequest {
        doc_id: String,
        /// Identifies the requesting actor instance; a request from an
        /// instance that is no longer installed is stale and ignored.
        tx: UnboundedSender<DocMsg>,
    },
}

/// Handle to a doc's lifecycle actor. Cloned into the registry slot and
/// every guard; the actor exits when it evicts or the last sender is gone.
#[derive(Clone)]
pub struct DocHandle {
    tx: UnboundedSender<DocMsg>,
    state: watch::Receiver<LifecycleState>,
}

impl DocHandle {
    /// Ask the actor to grant an attachment. The `Attach` message is
    /// enqueued eagerly — before the returned future is first polled — so
    /// callers holding the future have already taken their place in the
    /// mailbox order that arbitrates against `Evict`. Resolving to `None`
    /// means the actor is evicting or gone: retry through the slot mutex.
    pub fn attach(
        &self,
        kind: AttachKind,
        doc: &Arc<DocWithSyncKv>,
    ) -> impl Future<Output = Option<AttachGuard>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let sent = self
            .tx
            .send(DocMsg::Attach {
                kind,
                reply: reply_tx,
            })
            .is_ok();
        let tx = self.tx.clone();
        let doc = Arc::clone(doc);
        async move {
            if !sent {
                return None;
            }
            reply_rx.await.ok()?;
            Some(AttachGuard {
                kind,
                awareness: doc.awareness(),
                doc,
                tx,
            })
        }
    }

    pub fn state(&self) -> watch::Receiver<LifecycleState> {
        self.state.clone()
    }
}

/// RAII attachment to a live doc. Dropping it detaches: the send is
/// unbounded and infallible from sync contexts, so accounting cannot be
/// lost by a caller forgetting a teardown path.
pub struct AttachGuard {
    kind: AttachKind,
    doc: Arc<DocWithSyncKv>,
    awareness: Arc<RwLock<Awareness>>,
    tx: UnboundedSender<DocMsg>,
}

impl AttachGuard {
    pub fn awareness(&self) -> Arc<RwLock<Awareness>> {
        Arc::clone(&self.awareness)
    }

    pub fn sync_kv(&self) -> Arc<SyncKv> {
        self.doc.sync_kv()
    }

    pub fn doc(&self) -> &Arc<DocWithSyncKv> {
        &self.doc
    }

    /// Make all document changes preceding this call durable. The lifecycle
    /// actor serializes this with its normal checkpoint worker, so a caller
    /// never races a second persist against an in-flight one.
    pub async fn durability_barrier(&self) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(DocMsg::DurabilityBarrier { reply: reply_tx })
            .map_err(|_| "document lifecycle actor is gone".to_string())?;
        reply_rx
            .await
            .map_err(|_| "document lifecycle actor stopped during flush".to_string())?
    }

    /// Route a subdoc's snapshot to this doc's actor (the guard here is a
    /// `Subdoc` pin held on the parent). Best-effort: a dead parent actor
    /// means the parent is gone and the snapshot has nowhere to live.
    pub fn send_subdoc_snapshot(&self, child_id: String, snapshot: Vec<u8>) {
        let _ = self
            .tx
            .send(DocMsg::UpdateSubdocSnapshot { child_id, snapshot });
    }
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let _ = self.tx.send(DocMsg::Detach { kind: self.kind });
    }
}

/// A resident doc: the instance plus its lifecycle actor's handle.
#[derive(Clone)]
pub(crate) struct Resident {
    pub doc: Arc<DocWithSyncKv>,
    pub handle: DocHandle,
}

/// The per-doc lifecycle actor: connection ledger, idle deadline, and
/// eviction authority. It owns the doc's exit: nothing leaves the
/// registry without this actor flushing it clean first.
struct DocActor {
    doc_id: String,
    doc: Arc<DocWithSyncKv>,
    mailbox: UnboundedReceiver<DocMsg>,
    /// The actor's own sender, used to identify this instance in
    /// `Control::EvictRequest`.
    tx: UnboundedSender<DocMsg>,
    ctl: UnboundedSender<Control>,
    state_tx: watch::Sender<LifecycleState>,
    sockets: usize,
    https: usize,
    subdocs: usize,
    /// Armed while idle (and `doc_gc`); firing sends one `EvictRequest`.
    idle_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    evict_requested: bool,
    /// At most one persist runs at a time, as a sub-task so the mailbox
    /// stays responsive.
    persist_inflight: Option<tokio::task::JoinHandle<PersistTaskResult>>,
    /// A dirty edge arrived while a persist was in flight; schedule a
    /// follow-up when it completes.
    persist_queued: bool,
    /// Armed when a dirty doc is inside the throttle window (or backing
    /// off after a persist error).
    persist_timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    last_persist_ok: tokio::time::Instant,
    persist_backoff: u32,
    cfg: LifecycleConfig,
    metrics: Arc<RelayMetrics>,
}

impl DocActor {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        doc_id: String,
        doc: Arc<DocWithSyncKv>,
        cfg: LifecycleConfig,
        metrics: Arc<RelayMetrics>,
        ctl: UnboundedSender<Control>,
    ) -> DocHandle {
        let (tx, mailbox) = unbounded_channel();
        let (state_tx, state_rx) = watch::channel(LifecycleState::Idle);
        metrics.record_lifecycle_transition("loading", "idle");
        let mut actor = DocActor {
            doc_id,
            doc,
            mailbox,
            tx: tx.clone(),
            ctl,
            state_tx,
            sockets: 0,
            https: 0,
            subdocs: 0,
            idle_deadline: None,
            evict_requested: false,
            persist_inflight: None,
            persist_queued: false,
            persist_timer: None,
            last_persist_ok: tokio::time::Instant::now(),
            persist_backoff: 0,
            cfg,
            metrics,
        };
        // A doc is born idle: loads that never attach (doc creation,
        // warm-ups) age out on the same deadline as any other idle doc.
        actor.arm_idle_deadline();
        // The dirty callback is rewired to this actor only after the doc
        // is constructed; catch any edge that fired before the rewire.
        if actor.doc.sync_kv().is_dirty() {
            actor.schedule_persist();
        }
        tokio::spawn(actor.run());
        DocHandle {
            tx,
            state: state_rx,
        }
    }

    fn connections(&self) -> usize {
        self.sockets + self.https + self.subdocs
    }

    fn arm_idle_deadline(&mut self) {
        if self.cfg.doc_gc {
            self.idle_deadline = Some(Box::pin(tokio::time::sleep(self.cfg.idle_timeout())));
        }
    }

    async fn run(mut self) {
        enum Event {
            Msg(Option<DocMsg>),
            IdleDeadline,
            PersistTimer,
            PersistDone(PersistTaskResult),
        }
        loop {
            let event = {
                let deadline = &mut self.idle_deadline;
                let timer = &mut self.persist_timer;
                let inflight = &mut self.persist_inflight;
                let mailbox = &mut self.mailbox;
                tokio::select! {
                    msg = mailbox.recv() => Event::Msg(msg),
                    _ = async {
                        match deadline {
                            Some(sleep) => sleep.as_mut().await,
                            None => std::future::pending().await,
                        }
                    } => Event::IdleDeadline,
                    _ = async {
                        match timer {
                            Some(sleep) => sleep.as_mut().await,
                            None => std::future::pending().await,
                        }
                    } => Event::PersistTimer,
                    joined = async {
                        match inflight {
                            Some(handle) => handle.await,
                            None => std::future::pending().await,
                        }
                    } => Event::PersistDone(joined.unwrap_or(PersistTaskResult::Failed)),
                }
            };
            match event {
                // Slot dropped and every guard gone; nothing left to own.
                Event::Msg(None) => break,
                Event::Msg(Some(msg)) => {
                    if self.handle_msg(msg).await {
                        break;
                    }
                }
                Event::IdleDeadline => {
                    // Hand the decision to the registry, which serializes
                    // eviction under the slot mutex. Do not re-arm; the
                    // request stays pending until an `Evict` (or an
                    // attach) resolves it.
                    self.idle_deadline = None;
                    if !self.evict_requested {
                        self.evict_requested = true;
                        let _ = self.ctl.send(Control::EvictRequest {
                            doc_id: self.doc_id.clone(),
                            tx: self.tx.clone(),
                        });
                    }
                }
                Event::PersistTimer => {
                    self.persist_timer = None;
                    if self.persist_inflight.is_none() && self.doc.sync_kv().is_dirty() {
                        self.start_persist();
                    }
                }
                Event::PersistDone(result) => {
                    self.persist_inflight = None;
                    match result {
                        PersistTaskResult::Persisted => {
                            self.last_persist_ok = tokio::time::Instant::now();
                            self.persist_backoff = 0;
                        }
                        PersistTaskResult::Clobbered => {
                            // A direct store write landed behind us and this
                            // persist overwrote it. The write did land, so
                            // this is a success like any other.
                            self.metrics.record_doc_persist_conflict();
                            self.last_persist_ok = tokio::time::Instant::now();
                            self.persist_backoff = 0;
                        }
                        PersistTaskResult::Failed => {
                            self.persist_backoff = (self.persist_backoff + 1).min(8);
                        }
                    }
                    if std::mem::take(&mut self.persist_queued) || self.doc.sync_kv().is_dirty() {
                        self.schedule_persist();
                    }
                }
            }
        }
    }

    /// Persist now if the throttle window allows it, otherwise arm the
    /// timer for the window boundary (with exponential backoff after
    /// persist errors, whose failure path never re-fires the dirty edge).
    fn schedule_persist(&mut self) {
        if self.persist_inflight.is_some() {
            self.persist_queued = true;
            return;
        }
        if !self.doc.sync_kv().is_dirty() {
            return;
        }
        let backoff = self
            .cfg
            .checkpoint_freq
            .saturating_mul(1 << self.persist_backoff.min(8));
        let due = self.last_persist_ok + backoff;
        if tokio::time::Instant::now() >= due {
            self.start_persist();
        } else if self.persist_timer.is_none() {
            self.persist_timer = Some(Box::pin(tokio::time::sleep_until(due)));
        }
    }

    fn start_persist(&mut self) {
        self.persist_timer = None;
        let sync_kv = self.doc.sync_kv();
        let doc_id = self.doc_id.clone();
        self.persist_inflight = Some(tokio::spawn(async move {
            match sync_kv.persist_checked().await {
                Ok(PersistOutcome::Persisted) => PersistTaskResult::Persisted,
                Ok(PersistOutcome::Clobbered) => PersistTaskResult::Clobbered,
                Err(e) => {
                    tracing::error!(?e, doc_id = %doc_id, "Error persisting");
                    PersistTaskResult::Failed
                }
            }
        }));
    }

    /// Returns true when the actor should exit (the doc was evicted).
    async fn handle_msg(&mut self, msg: DocMsg) -> bool {
        match msg {
            DocMsg::Attach { kind, reply } => {
                let was = self.connections();
                match kind {
                    AttachKind::Socket => self.sockets += 1,
                    AttachKind::Http => self.https += 1,
                    AttachKind::Subdoc => self.subdocs += 1,
                }
                if was == 0 {
                    self.idle_deadline = None;
                    self.metrics.record_lifecycle_transition("idle", "active");
                }
                self.publish();
                let _ = reply.send(());
                tracing::debug!(
                    doc_id = %self.doc_id,
                    kind = kind.as_str(),
                    connections = self.connections(),
                    "attach"
                );
                false
            }
            DocMsg::Detach { kind } => {
                let counter = match kind {
                    AttachKind::Socket => &mut self.sockets,
                    AttachKind::Http => &mut self.https,
                    AttachKind::Subdoc => &mut self.subdocs,
                };
                debug_assert!(*counter > 0, "detach without matching attach");
                *counter = counter.saturating_sub(1);
                if self.connections() == 0 {
                    self.metrics.record_lifecycle_transition("active", "idle");
                    self.idle_entry_flush();
                    self.arm_idle_deadline();
                }
                self.publish();
                tracing::debug!(
                    doc_id = %self.doc_id,
                    kind = kind.as_str(),
                    connections = self.connections(),
                    "detach"
                );
                false
            }
            DocMsg::Dirty => {
                self.schedule_persist();
                false
            }
            DocMsg::UpdateSubdocSnapshot { child_id, snapshot } => {
                // Mutating our own metadata marks the doc dirty, whose
                // edge callback enqueues a Dirty for the throttle.
                self.doc.update_subdoc_snapshot(&child_id, snapshot);
                false
            }
            DocMsg::Drain { reply } => {
                if let Some(inflight) = self.persist_inflight.take() {
                    let _ = inflight.await;
                }
                self.persist_timer = None;
                let was_dirty = self.doc.sync_kv().is_dirty();
                while self.doc.sync_kv().is_dirty() {
                    match self.flush_once().await {
                        FlushStep::Progress => {}
                        FlushStep::Error => {
                            // The process is dying; keep trying until the
                            // platform kill timeout bounds us, don't spin.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                self.last_persist_ok = tokio::time::Instant::now();
                let _ = reply.send(was_dirty);
                false
            }
            DocMsg::DurabilityBarrier { reply } => {
                let result = self.flush_for_durability().await;
                if result.is_err() && self.doc.sync_kv().is_dirty() {
                    self.schedule_persist();
                }
                let _ = reply.send(result);
                false
            }
            DocMsg::Evict { reply } => self.handle_evict(reply).await,
        }
    }

    /// Await any checkpoint already in flight, then persist until the dirty
    /// bit is clear. Unlike process drain, a failed attempt is reported to the
    /// live caller so it can withhold its protocol acknowledgement.
    async fn flush_for_durability(&mut self) -> Result<(), String> {
        self.persist_timer = None;

        if let Some(inflight) = self.persist_inflight.take() {
            let result = inflight.await.unwrap_or(PersistTaskResult::Failed);
            match result {
                PersistTaskResult::Persisted => {
                    self.last_persist_ok = tokio::time::Instant::now();
                    self.persist_backoff = 0;
                }
                PersistTaskResult::Clobbered => {
                    self.metrics.record_doc_persist_conflict();
                }
                PersistTaskResult::Failed => {
                    self.persist_backoff = (self.persist_backoff + 1).min(8);
                    return Err("checkpoint persist failed".to_string());
                }
            }
        }

        while self.doc.sync_kv().is_dirty() {
            match self.flush_once().await {
                FlushStep::Progress => {}
                FlushStep::Error => {
                    self.persist_backoff = (self.persist_backoff + 1).min(8);
                    return Err("durability flush failed".to_string());
                }
            }
        }

        self.persist_queued = false;
        self.last_persist_ok = tokio::time::Instant::now();
        self.persist_backoff = 0;
        Ok(())
    }

    /// One inline flush attempt for the evict/drain loops: persist with
    /// the lease check, overwriting — and counting — a direct store write
    /// that landed behind us.
    async fn flush_once(&mut self) -> FlushStep {
        // Stringify the error eagerly: the boxed store error is not Send.
        let outcome = self
            .doc
            .sync_kv()
            .persist_checked()
            .await
            .map_err(|e| e.to_string());
        match outcome {
            Ok(PersistOutcome::Persisted) => FlushStep::Progress,
            Ok(PersistOutcome::Clobbered) => {
                self.metrics.record_doc_persist_conflict();
                FlushStep::Progress
            }
            Err(error) => {
                tracing::error!(%error, doc_id = %self.doc_id, "Error persisting during flush");
                FlushStep::Error
            }
        }
    }

    /// Idle entry is a durability point: the machine may be suspended any
    /// time after the last connection drains, so whatever the checkpoint
    /// throttle is still holding gets flushed now, bypassing the window.
    fn idle_entry_flush(&mut self) {
        if !self.doc.sync_kv().is_dirty() {
            return;
        }
        self.metrics.record_doc_dirty_at_drain();
        if self.persist_inflight.is_some() {
            self.persist_queued = true;
        } else {
            self.start_persist();
        }
    }

    async fn handle_evict(&mut self, reply: oneshot::Sender<EvictOutcome>) -> bool {
        self.evict_requested = false;
        // Any attach granted ahead of this message in the mailbox has
        // already incremented the count — this check IS the un-evict.
        if self.connections() > 0 {
            tracing::info!(doc_id = %self.doc_id, "attach raced eviction; refusing evict");
            let _ = reply.send(EvictOutcome::Refused);
            return false;
        }
        self.idle_deadline = None;
        self.persist_timer = None;
        self.metrics.record_lifecycle_transition("idle", "evicting");
        if let Some(inflight) = self.persist_inflight.take() {
            let _ = inflight.await;
        }
        tracing::debug!(doc_id = %self.doc_id, "evicting doc");
        // Compact PUD before exit: dedup ids, clear ds. The mutations
        // create tombstones which yrs GC will clean up, and the update
        // observer marks SyncKv dirty so the compacted state persists in
        // the flush below.
        let result = self.doc.compact_user_data();
        if !result.is_empty() {
            tracing::debug!(
                ids_removed = result.ids_removed,
                ds_removed = result.ds_removed,
                "Compacted PermanentUserData"
            );
        }
        // Flush until clean: the final state must reach the store before
        // the registry clears the slot, or a reload would read a stale
        // snapshot and its next persist would roll the doc back. A doc
        // never leaves memory unflushed: persistent store failure keeps
        // it resident and retries on the next idle deadline. A direct
        // store write landing mid-eviction is overwritten and counted.
        let mut failures = 0;
        while self.doc.sync_kv().is_dirty() {
            match self.flush_once().await {
                FlushStep::Progress => {}
                FlushStep::Error => {
                    failures += 1;
                    if failures >= 3 {
                        self.metrics.record_lifecycle_transition("evicting", "idle");
                        self.arm_idle_deadline();
                        let _ = reply.send(EvictOutcome::Refused);
                        return false;
                    }
                }
            }
        }
        self.metrics.record_lifecycle_transition("evicting", "gone");
        let _ = reply.send(EvictOutcome::Evicted);
        // Returning true drops the actor and with it the doc instance.
        true
    }

    fn publish(&self) {
        let state = match self.connections() {
            0 => LifecycleState::Idle,
            n => LifecycleState::Active { connections: n },
        };
        let _ = self.state_tx.send(state);
    }
}

struct SlotState {
    doc: Option<Resident>,
    /// Set exactly once, under the slot mutex, when the slot is removed
    /// from the map. Tells mutex waiters their slot is dead.
    defunct: bool,
}

struct Slot {
    mu: AsyncMutex<()>,
    state: RwLock<SlotState>,
}

impl Slot {
    fn new() -> Self {
        Self {
            mu: AsyncMutex::new(()),
            state: RwLock::new(SlotState {
                doc: None,
                defunct: false,
            }),
        }
    }
}

pub struct DocRegistry {
    slots: Arc<DashMap<String, Arc<Slot>>>,
    ctl_tx: UnboundedSender<Control>,
    cfg: LifecycleConfig,
    metrics: Arc<RelayMetrics>,
}

impl DocRegistry {
    pub fn new(metrics: Arc<RelayMetrics>, cfg: LifecycleConfig) -> Self {
        let slots: Arc<DashMap<String, Arc<Slot>>> = Arc::new(DashMap::new());
        let (ctl_tx, ctl_rx) = unbounded_channel();
        Self::spawn_sweeper(Arc::clone(&slots), ctl_rx);
        Self {
            slots,
            ctl_tx,
            cfg,
            metrics,
        }
    }

    /// The sweeper serializes actor-requested evictions under the slot
    /// mutex, one at a time. A request from an actor instance that is no
    /// longer installed (evicted and reloaded since) is stale and ignored.
    fn spawn_sweeper(
        slots: Arc<DashMap<String, Arc<Slot>>>,
        mut ctl_rx: UnboundedReceiver<Control>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = ctl_rx.recv().await {
                match msg {
                    Control::EvictRequest { doc_id, tx } => {
                        let current = slots
                            .get(&doc_id)
                            .and_then(|s| s.value().state.read().unwrap().doc.clone());
                        let stale = match current {
                            Some(resident) => !resident.handle.tx.same_channel(&tx),
                            None => true,
                        };
                        if stale {
                            continue;
                        }
                        match Self::evict_in(&slots, &doc_id).await {
                            EvictOutcome::Evicted => {
                                tracing::debug!(doc_id = %doc_id, "idle doc evicted");
                            }
                            EvictOutcome::Refused => {
                                tracing::debug!(doc_id = %doc_id, "eviction refused; doc active again");
                            }
                            EvictOutcome::Absent => {}
                        }
                    }
                }
            }
        });
    }

    /// Lock-free view of a resident doc.
    pub fn peek(&self, doc_id: &str) -> Option<Arc<DocWithSyncKv>> {
        self.peek_resident(doc_id).map(|r| r.doc)
    }

    pub(crate) fn peek_resident(&self, doc_id: &str) -> Option<Resident> {
        let slot = self.slots.get(doc_id)?;
        let state = slot.state.read().unwrap();
        state.doc.clone()
    }

    pub fn is_resident(&self, doc_id: &str) -> bool {
        self.peek_resident(doc_id).is_some()
    }

    /// Snapshot of every resident doc, for shutdown flush passes. Docs
    /// mid-load are absent from slot state and therefore skipped: a
    /// loading doc is clean.
    pub fn resident_docs(&self) -> Vec<Arc<DocWithSyncKv>> {
        self.slots
            .iter()
            .filter_map(|entry| entry.value().state.read().unwrap().doc.clone())
            .map(|resident| resident.doc)
            .collect()
    }

    /// Number of slots (resident docs plus in-flight loads).
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Load (if needed) and attach in one step: the returned guard is the
    /// unit of connection accounting and the only license to touch the
    /// doc. Retries are bounded: any pass that reaches the load branch
    /// succeeds, so the budget is a formality.
    pub async fn attach<F, Fut>(
        &self,
        doc_id: &str,
        kind: AttachKind,
        loader: F,
    ) -> anyhow::Result<AttachGuard>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        let mut skip_fast_path = false;
        for _ in 0..4 {
            let resident = self.load_resident(doc_id, &loader, skip_fast_path).await?;
            match resident.handle.attach(kind, &resident.doc).await {
                Some(guard) => return Ok(guard),
                // The actor is evicting or gone. The fast path would keep
                // returning the same dying resident, so the retry
                // serializes on the slot mutex, which the evictor holds
                // until the slot clears (and which reclaims dead actors).
                None => skip_fast_path = true,
            }
        }
        anyhow::bail!("attach retry budget exceeded for doc {doc_id}")
    }

    pub async fn get_or_load<F, Fut>(
        &self,
        doc_id: &str,
        loader: F,
    ) -> anyhow::Result<Arc<DocWithSyncKv>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        Ok(self.get_or_load_resident(doc_id, &loader).await?.doc)
    }

    /// Return the resident doc for `doc_id`, or run `loader` to create it.
    /// Concurrent callers single-flight: exactly one runs the loader, the
    /// rest wait on the slot mutex and observe the result. A failed load
    /// removes the slot and returns the error to the caller that ran the
    /// loader; waiters retry with their own load rather than inheriting an
    /// error they can't distinguish from their own.
    async fn get_or_load_resident<F, Fut>(
        &self,
        doc_id: &str,
        loader: &F,
    ) -> anyhow::Result<Resident>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        self.load_resident(doc_id, loader, false).await
    }

    async fn load_resident<F, Fut>(
        &self,
        doc_id: &str,
        loader: &F,
        mut skip_fast_path: bool,
    ) -> anyhow::Result<Resident>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = anyhow::Result<DocWithSyncKv>>,
    {
        loop {
            // Fast path: no slot mutex.
            if !std::mem::take(&mut skip_fast_path) {
                if let Some(slot) = self.slots.get(doc_id) {
                    let resident = slot.state.read().unwrap().doc.clone();
                    if let Some(resident) = resident {
                        return Ok(resident);
                    }
                }
            }

            // Take (or create) the slot, dropping the shard guard before
            // awaiting the slot mutex.
            let slot = {
                let entry = self
                    .slots
                    .entry(doc_id.to_string())
                    .or_insert_with(|| Arc::new(Slot::new()));
                Arc::clone(entry.value())
            };
            let _guard = slot.mu.lock().await;

            {
                let state = slot.state.read().unwrap();
                if state.defunct {
                    // The slot was evicted or its load failed while we
                    // waited; start over from the map.
                    continue;
                }
                if let Some(resident) = state.doc.clone() {
                    if !resident.handle.tx.is_closed() {
                        return Ok(resident);
                    }
                    // The actor died without the registry noticing (it
                    // panicked): fall through, reclaim the slot, and load
                    // fresh below.
                    tracing::warn!(doc_id = %doc_id, "resident doc's actor is dead; reloading");
                }
            }

            if slot.state.read().unwrap().doc.is_some() {
                // Dead-actor branch from above: reclaim under the mutex.
                slot.state.write().unwrap().defunct = true;
                self.slots.remove_if(doc_id, |_, s| Arc::ptr_eq(s, &slot));
                continue;
            }

            match loader().await {
                Ok(doc) => {
                    let doc = Arc::new(doc);
                    let handle = DocActor::spawn(
                        doc_id.to_string(),
                        Arc::clone(&doc),
                        self.cfg,
                        self.metrics.clone(),
                        self.ctl_tx.clone(),
                    );
                    // Point the doc's dirty edge at its actor, which
                    // owns the persistence throttle. The actor re-checks
                    // the dirty bit at spawn, covering edges that fired
                    // before this rewire.
                    let dirty_tx = handle.tx.clone();
                    doc.sync_kv().set_dirty_callback(Box::new(move || {
                        let _ = dirty_tx.send(DocMsg::Dirty);
                    }));
                    let resident = Resident { doc, handle };
                    slot.state.write().unwrap().doc = Some(resident.clone());
                    return Ok(resident);
                }
                Err(err) => {
                    slot.state.write().unwrap().defunct = true;
                    self.slots.remove_if(doc_id, |_, s| Arc::ptr_eq(s, &slot));
                    return Err(err);
                }
            }
        }
    }

    /// One drain pass: broadcast a flush to every resident doc's actor
    /// and await the results. Returns how many docs had dirty state to
    /// flush. Docs stay resident; nothing about their lifecycle changes.
    pub async fn drain(&self) -> usize {
        let residents: Vec<Resident> = self
            .slots
            .iter()
            .filter_map(|entry| entry.value().state.read().unwrap().doc.clone())
            .collect();
        let mut replies = Vec::with_capacity(residents.len());
        for resident in residents {
            let (reply_tx, reply_rx) = oneshot::channel();
            if resident
                .handle
                .tx
                .send(DocMsg::Drain { reply: reply_tx })
                .is_ok()
            {
                replies.push(reply_rx);
            }
        }
        let mut flushed = 0;
        for reply in replies {
            if let Ok(true) = reply.await {
                flushed += 1;
            }
        }
        flushed
    }

    /// Drain until no resident doc is dirty. Used after the socket
    /// cutover at shutdown: detaches enqueued behind a drain pass can
    /// dirty-flush after it, so repeat until quiescent. With sockets
    /// closed there are no writers, so this terminates.
    pub async fn flush_until_clean(&self) -> usize {
        let mut total = 0;
        loop {
            total += self.drain().await;
            let any_dirty = self
                .slots
                .iter()
                .filter_map(|entry| entry.value().state.read().unwrap().doc.clone())
                .any(|resident| resident.doc.sync_kv().is_dirty());
            if !any_dirty {
                return total;
            }
            tokio::task::yield_now().await;
        }
    }

    /// Evict `doc_id` now (the sweeper's path, also exposed so tests and
    /// shutdown paths can drive eviction explicitly). Holds the slot
    /// mutex across the actor's final flush: a racing load waits until
    /// the store already holds the flushed bytes.
    pub async fn evict(&self, doc_id: &str) -> EvictOutcome {
        Self::evict_in(&self.slots, doc_id).await
    }

    async fn evict_in(slots: &DashMap<String, Arc<Slot>>, doc_id: &str) -> EvictOutcome {
        let Some(slot) = slots.get(doc_id).map(|s| Arc::clone(s.value())) else {
            return EvictOutcome::Absent;
        };
        let _guard = slot.mu.lock().await;

        let resident = {
            let state = slot.state.read().unwrap();
            if state.defunct {
                return EvictOutcome::Absent;
            }
            match state.doc.clone() {
                Some(resident) => resident,
                None => return EvictOutcome::Absent,
            }
        };

        let remove_slot = || {
            slot.state.write().unwrap().doc = None;
            slot.state.write().unwrap().defunct = true;
            slots.remove_if(doc_id, |_, s| Arc::ptr_eq(s, &slot));
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if resident
            .handle
            .tx
            .send(DocMsg::Evict { reply: reply_tx })
            .is_err()
        {
            // Dead actor: reclaim the slot; the doc was flushed at its
            // last idle entry or not at all — a panic loses the tail.
            tracing::warn!(doc_id = %doc_id, "evicting a dead actor's slot");
            remove_slot();
            return EvictOutcome::Absent;
        }
        match reply_rx.await {
            Ok(EvictOutcome::Evicted) => {
                remove_slot();
                EvictOutcome::Evicted
            }
            Ok(outcome) => outcome,
            Err(_) => {
                tracing::error!(doc_id = %doc_id, "actor died during eviction; flush state unknown");
                remove_slot();
                EvictOutcome::Absent
            }
        }
    }
}

/// A bare actor handle for harnesses that drive the socket path without
/// a registry (see `server.rs`'s in-memory socket tests).
#[cfg(test)]
pub(crate) fn test_actor_handle(doc: &Arc<DocWithSyncKv>, metrics: Arc<RelayMetrics>) -> DocHandle {
    let (ctl_tx, _ctl_rx) = unbounded_channel();
    DocActor::spawn(
        "test_doc".to_string(),
        Arc::clone(doc),
        LifecycleConfig {
            checkpoint_freq: Duration::from_secs(600),
            doc_gc: false,
        },
        metrics,
        ctl_tx,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{content_update, read_content, FailStore, GatedStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use y_sweet_core::store::{memory::MemoryStore, Store};

    fn test_metrics() -> Arc<RelayMetrics> {
        RelayMetrics::new_with_registry(&prometheus::Registry::new()).unwrap()
    }

    fn no_gc() -> LifecycleConfig {
        LifecycleConfig {
            checkpoint_freq: Duration::from_secs(600),
            doc_gc: false,
        }
    }

    /// Let actors drain their mailboxes (single-threaded test runtime).
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    async fn load_doc<S: Store + Clone + 'static>(
        store: &S,
        doc_id: &str,
    ) -> anyhow::Result<DocWithSyncKv> {
        DocWithSyncKv::new(
            doc_id,
            Some(Arc::new(Box::new(store.clone()) as Box<dyn Store>)),
            || (),
            None,
        )
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn single_flight_concurrent_loads_share_one_load() {
        let store = GatedStore::new();
        let registry = Arc::new(DocRegistry::new(test_metrics(), no_gc()));
        let loads = Arc::new(AtomicUsize::new(0));

        let docs = futures::future::join_all((0..8).map(|_| {
            let registry = registry.clone();
            let store = store.clone();
            let loads = loads.clone();
            async move {
                registry
                    .get_or_load("doc", || {
                        let store = store.clone();
                        let loads = loads.clone();
                        async move {
                            loads.fetch_add(1, Ordering::SeqCst);
                            load_doc(&store, "doc").await
                        }
                    })
                    .await
                    .unwrap()
            }
        }))
        .await;

        assert_eq!(loads.load(Ordering::SeqCst), 1, "loader must run once");
        assert_eq!(
            store.get_count("doc/data.ysweet"),
            1,
            "store must be read once"
        );
        for doc in &docs[1..] {
            assert!(
                Arc::ptr_eq(&docs[0], doc),
                "all callers must share one instance"
            );
        }
        assert_eq!(registry.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_load_propagates_to_all_waiters_and_clears_slot() {
        // Enough injected failures that every concurrent caller's own
        // load attempt fails (waiters retry with their own load).
        let store = FailStore::new(8);
        let registry = Arc::new(DocRegistry::new(test_metrics(), no_gc()));

        let results = futures::future::join_all((0..8).map(|_| {
            let registry = registry.clone();
            let store = store.clone();
            async move {
                registry
                    .get_or_load("doc", || {
                        let store = store.clone();
                        async move { load_doc(&store, "doc").await }
                    })
                    .await
            }
        }))
        .await;

        for result in &results {
            assert!(result.is_err(), "every caller must see its load fail");
        }
        assert_eq!(registry.len(), 0, "failed loads must not leave slots");

        // The failure budget is exhausted; a retry must succeed rather
        // than finding a wedged slot.
        registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .expect("retry after failed load must succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn evict_removes_slot_and_next_load_is_fresh() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics(), no_gc());

        let doc = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        doc.apply_update(&content_update("k", "v")).unwrap();

        let outcome = registry.evict("doc").await;
        assert_eq!(outcome, EvictOutcome::Evicted);
        assert_eq!(registry.len(), 0);
        assert!(!registry.is_resident("doc"));

        let reloaded = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        assert!(
            !Arc::ptr_eq(&doc, &reloaded),
            "a reload after eviction is a fresh instance"
        );
        assert_eq!(
            read_content(&reloaded, "k").as_deref(),
            Some("v"),
            "the eviction flush must land before the slot clears"
        );
    }

    /// Race 1, ordering branch: an attach granted ahead of the Evict in
    /// the mailbox makes the eviction refuse — the un-evict, decided
    /// purely by message order.
    #[tokio::test(start_paused = true)]
    async fn attach_queued_before_evict_wins_and_unevicts() {
        let store = MemoryStore::new();
        let registry = Arc::new(DocRegistry::new(test_metrics(), no_gc()));
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let doc = registry.get_or_load("doc", loader).await.unwrap();

        // The Attach message is enqueued eagerly when the future is
        // created, so it sits in the mailbox ahead of the Evict sent
        // below — the exact interleaving that used to orphan a doc.
        let resident = registry.peek_resident("doc").unwrap();
        let attach_fut = resident.handle.attach(AttachKind::Socket, &resident.doc);

        let outcome = registry.evict("doc").await;
        assert_eq!(
            outcome,
            EvictOutcome::Refused,
            "an attach queued ahead of the eviction must refuse it"
        );

        let guard = attach_fut.await.expect("the queued attach must be granted");
        assert!(
            Arc::ptr_eq(&doc, guard.doc()),
            "the un-evicted doc must be the same instance"
        );

        // The surviving attachment's writes reach the store on release.
        guard.doc().apply_update(&content_update("k", "v")).unwrap();
        drop(guard);
        settle().await;
        assert_eq!(registry.evict("doc").await, EvictOutcome::Evicted);
        let reloaded = registry.get_or_load("doc", loader).await.unwrap();
        assert_eq!(read_content(&reloaded, "k").as_deref(), Some("v"));
    }

    /// Races 1 (queue branch) and 2: an attach that arrives during an
    /// eviction waits on the slot mutex until the final persist is on the
    /// store, then loads a fresh instance carrying the flushed state.
    #[tokio::test(start_paused = true)]
    async fn attach_during_evict_waits_for_fresh_instance_with_flushed_state() {
        let store = GatedStore::new();
        let registry = Arc::new(DocRegistry::new(test_metrics(), no_gc()));
        let loader = {
            let store = store.clone();
            move || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            }
        };

        let doc = registry.get_or_load("doc", loader.clone()).await.unwrap();
        doc.apply_update(&content_update("k", "v")).unwrap();
        drop(doc);

        store.close_gate();
        let evict = tokio::spawn({
            let registry = registry.clone();
            async move { registry.evict("doc").await }
        });
        // Let the eviction reach the gated final PUT.
        settle().await;

        let attach = tokio::spawn({
            let registry = registry.clone();
            let loader = loader.clone();
            async move {
                registry
                    .attach("doc", AttachKind::Socket, loader)
                    .await
                    .unwrap()
            }
        });
        settle().await;
        assert!(
            !evict.is_finished(),
            "eviction must be parked on the gated final persist"
        );
        assert!(
            !attach.is_finished(),
            "a racing attach must wait for the final persist, not read stale bytes"
        );

        store.open_gate();
        assert_eq!(evict.await.unwrap(), EvictOutcome::Evicted);
        let guard = attach.await.unwrap();
        assert_eq!(
            read_content(guard.doc(), "k").as_deref(),
            Some("v"),
            "the racing attach must observe the eviction's final flush"
        );
    }

    /// Race 3: a task holding a guard dies; RAII detach releases the
    /// count and the doc becomes evictable — dead connections cannot pin.
    #[tokio::test(start_paused = true)]
    async fn dead_socket_task_cannot_pin_doc() {
        let store = MemoryStore::new();
        let registry = Arc::new(DocRegistry::new(test_metrics(), no_gc()));
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        let holder = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        settle().await;
        assert_eq!(
            registry.evict("doc").await,
            EvictOutcome::Refused,
            "a live holder must pin the doc"
        );

        holder.abort();
        settle().await;
        assert_eq!(
            registry.evict("doc").await,
            EvictOutcome::Evicted,
            "an aborted holder's guard must release its attachment"
        );
    }

    /// Race 4: the last detach flushes immediately — no throttle wait, no
    /// time advance — because the machine may be suspended any moment
    /// after the doc goes quiet.
    #[tokio::test(start_paused = true)]
    async fn idle_entry_flush_beats_park_window() {
        let metrics = test_metrics();
        let store = MemoryStore::new();
        let registry = DocRegistry::new(metrics.clone(), no_gc());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        guard.doc().apply_update(&content_update("k", "v")).unwrap();
        drop(guard);

        // No sleeps: virtual time must not advance, so only the
        // idle-entry flush can explain bytes reaching the store.
        settle().await;
        assert!(
            store.get_bytes("doc/data.ysweet").is_some(),
            "idle entry must flush before the park window opens"
        );
        assert_eq!(
            metrics
                .doc_dirty_at_drain_total
                .with_label_values(&[])
                .get(),
            1.0,
            "the dirty-at-drain metric moves to the actor's idle entry"
        );
    }

    /// The one timer test: the idle deadline itself sends the eviction
    /// request. Everything else drives eviction explicitly.
    #[tokio::test(start_paused = true)]
    async fn idle_deadline_timer_sends_evict() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(
            test_metrics(),
            LifecycleConfig {
                checkpoint_freq: Duration::from_millis(10),
                doc_gc: true,
            },
        );

        registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        assert!(registry.is_resident("doc"));

        // Past the 2×checkpoint_freq deadline plus sweeper handoff.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !registry.is_resident("doc"),
            "an idle doc must age out via the deadline"
        );
        assert_eq!(registry.len(), 0, "eviction must reclaim the slot");
    }

    /// With doc_gc off the deadline never arms and idle docs stay.
    #[tokio::test(start_paused = true)]
    async fn doc_gc_off_never_evicts() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(
            test_metrics(),
            LifecycleConfig {
                checkpoint_freq: Duration::from_millis(10),
                doc_gc: false,
            },
        );
        registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(registry.is_resident("doc"));
    }

    #[tokio::test(start_paused = true)]
    async fn slot_count_returns_to_zero_after_load_evict_cycles() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics(), no_gc());

        for round in 0..10 {
            registry
                .get_or_load("doc", || {
                    let store = store.clone();
                    async move { load_doc(&store, "doc").await }
                })
                .await
                .unwrap();
            assert_eq!(registry.len(), 1);
            assert_eq!(registry.evict("doc").await, EvictOutcome::Evicted);
            assert_eq!(
                registry.len(),
                0,
                "round {round}: eviction must fully reclaim the slot"
            );
        }
    }

    /// A direct store write landing under a live doc is detected and
    /// overwritten: for a resident doc the server's in-memory state is the
    /// authority. The clobber is counted so it is visible in metrics.
    #[tokio::test(start_paused = true)]
    async fn direct_store_write_is_clobbered_by_live_persist() {
        let metrics = test_metrics();
        let store = MemoryStore::new();
        let registry = DocRegistry::new(
            metrics.clone(),
            LifecycleConfig {
                checkpoint_freq: Duration::from_secs(10),
                doc_gc: false,
            },
        );
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        guard
            .doc()
            .apply_update(&content_update("live", "1"))
            .unwrap();

        // An operator backfill: a separate handle over the same store
        // key, writing directly (plain overwrite, as tools do). The live
        // doc's lease is now stale.
        let backfill = load_doc(&store, "doc").await.unwrap();
        backfill
            .apply_update(&content_update("backfill", "1"))
            .unwrap();
        backfill.sync_kv().persist().await.unwrap();

        // The live doc's throttled persist detects the direct write and
        // overwrites it.
        tokio::time::sleep(Duration::from_secs(11)).await;
        settle().await;

        assert_eq!(
            metrics
                .doc_persist_conflicts_total
                .with_label_values(&[])
                .get(),
            1.0,
            "the clobber must be observed"
        );
        assert_eq!(
            read_content(guard.doc(), "backfill"),
            None,
            "the direct write is not folded into the live doc"
        );

        // The store holds the live doc's state alone after eviction.
        drop(guard);
        settle().await;
        assert_eq!(registry.evict("doc").await, EvictOutcome::Evicted);
        let reloaded = registry.get_or_load("doc", loader).await.unwrap();
        assert_eq!(read_content(&reloaded, "live").as_deref(), Some("1"));
        assert_eq!(
            read_content(&reloaded, "backfill"),
            None,
            "the direct write was overwritten"
        );
    }

    /// Same behavior at the idle-entry flush: a direct write that landed
    /// while a connection was live is overwritten at its detach.
    #[tokio::test(start_paused = true)]
    async fn direct_store_write_is_clobbered_by_idle_entry_flush() {
        let metrics = test_metrics();
        let store = MemoryStore::new();
        let registry = DocRegistry::new(metrics.clone(), no_gc());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        guard
            .doc()
            .apply_update(&content_update("live", "1"))
            .unwrap();

        let backfill = load_doc(&store, "doc").await.unwrap();
        backfill
            .apply_update(&content_update("backfill", "1"))
            .unwrap();
        backfill.sync_kv().persist().await.unwrap();

        // The detach's idle-entry flush detects the direct write and
        // overwrites it.
        drop(guard);
        settle().await;

        assert!(
            metrics
                .doc_persist_conflicts_total
                .with_label_values(&[])
                .get()
                >= 1.0
        );
        assert_eq!(registry.evict("doc").await, EvictOutcome::Evicted);
        let reloaded = registry.get_or_load("doc", loader).await.unwrap();
        assert_eq!(read_content(&reloaded, "live").as_deref(), Some("1"));
        assert_eq!(
            read_content(&reloaded, "backfill"),
            None,
            "the direct write was overwritten"
        );
    }

    /// The actor owns the checkpoint throttle: bursts of dirtiness within
    /// one checkpoint window coalesce into a single store PUT.
    #[tokio::test(start_paused = true)]
    async fn active_persists_throttle_to_checkpoint_freq() {
        let store = GatedStore::new();
        let registry = DocRegistry::new(
            test_metrics(),
            LifecycleConfig {
                checkpoint_freq: Duration::from_secs(10),
                doc_gc: false,
            },
        );
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        let key = "doc/data.ysweet";

        // A burst of writes inside one window.
        for i in 0..5 {
            guard
                .doc()
                .apply_update(&content_update(&format!("k{i}"), "v"))
                .unwrap();
        }
        settle().await;
        assert_eq!(
            store.put_count(key),
            0,
            "writes inside the window must wait for the throttle"
        );

        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(
            store.put_count(key),
            1,
            "one window of writes must coalesce into one PUT"
        );

        // A second window.
        guard
            .doc()
            .apply_update(&content_update("later", "v"))
            .unwrap();
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(store.put_count(key), 2);
        assert!(store.stored(key).is_some());
    }

    /// A write racing an in-flight persist schedules a follow-up: the
    /// second write's bytes reach the store, single-writer, no loss.
    #[tokio::test(start_paused = true)]
    async fn dirty_during_inflight_persist_schedules_followup() {
        let store = GatedStore::new();
        let registry = DocRegistry::new(
            test_metrics(),
            LifecycleConfig {
                checkpoint_freq: Duration::from_secs(10),
                doc_gc: false,
            },
        );
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        let key = "doc/data.ysweet";

        guard
            .doc()
            .apply_update(&content_update("k1", "v1"))
            .unwrap();
        store.close_gate();
        // Reach the throttle boundary: the persist starts and parks on
        // the gate.
        tokio::time::sleep(Duration::from_secs(11)).await;

        // Dirty the doc while the persist is in flight.
        guard
            .doc()
            .apply_update(&content_update("k2", "v2"))
            .unwrap();
        settle().await;

        store.release(1);
        // The follow-up persist runs after the next throttle window.
        tokio::time::sleep(Duration::from_secs(11)).await;
        store.open_gate();
        settle().await;

        assert_eq!(
            store.put_count(key),
            2,
            "the racing write must get its own follow-up persist"
        );
        let reloaded = registry.evict("doc").await;
        assert_eq!(reloaded, EvictOutcome::Refused, "guard still held");
        drop(guard);
        settle().await;
        assert_eq!(registry.evict("doc").await, EvictOutcome::Evicted);
        let fresh = registry
            .get_or_load("doc", || {
                let store = store.clone();
                async move { load_doc(&store, "doc").await }
            })
            .await
            .unwrap();
        assert_eq!(read_content(&fresh, "k2").as_deref(), Some("v2"));
    }

    /// The drain broadcast flushes every dirty doc without waiting on the
    /// throttle and without evicting anything.
    #[tokio::test(start_paused = true)]
    async fn drain_broadcast_flushes_all_dirty_docs() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(
            test_metrics(),
            LifecycleConfig {
                checkpoint_freq: Duration::from_secs(600),
                doc_gc: false,
            },
        );

        let mut guards = Vec::new();
        for name in ["a", "b", "c"] {
            let store = store.clone();
            let guard = registry
                .attach(name, AttachKind::Socket, move || {
                    let store = store.clone();
                    let name = name.to_string();
                    async move { load_doc(&store, &name).await }
                })
                .await
                .unwrap();
            guards.push(guard);
        }
        guards[0]
            .doc()
            .apply_update(&content_update("k", "v"))
            .unwrap();
        guards[1]
            .doc()
            .apply_update(&content_update("k", "v"))
            .unwrap();

        let flushed = registry.drain().await;
        assert_eq!(flushed, 2, "both dirty docs must flush");
        assert!(store.get_bytes("a/data.ysweet").is_some());
        assert!(store.get_bytes("b/data.ysweet").is_some());
        assert!(
            store.get_bytes("c/data.ysweet").is_none(),
            "a clean doc has nothing to flush"
        );
        for name in ["a", "b", "c"] {
            assert!(registry.is_resident(name), "drain must not evict");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn attach_guard_drop_sends_detach_and_count_reaches_zero() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics(), no_gc());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let socket_guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        let http_guard = registry
            .attach("doc", AttachKind::Http, loader)
            .await
            .unwrap();
        settle().await;

        let resident = registry.peek_resident("doc").unwrap();
        assert_eq!(
            *resident.handle.state().borrow(),
            LifecycleState::Active { connections: 2 }
        );

        drop(socket_guard);
        settle().await;
        assert_eq!(
            *resident.handle.state().borrow(),
            LifecycleState::Active { connections: 1 }
        );

        drop(http_guard);
        settle().await;
        assert_eq!(*resident.handle.state().borrow(), LifecycleState::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn attach_kinds_tracked_independently() {
        let store = MemoryStore::new();
        let registry = DocRegistry::new(test_metrics(), no_gc());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let subdoc_guard = registry
            .attach("doc", AttachKind::Subdoc, loader)
            .await
            .unwrap();

        // Socket attachments come and go; the subdoc pin must keep the
        // doc Active throughout.
        for _ in 0..3 {
            let socket_guard = registry
                .attach("doc", AttachKind::Socket, loader)
                .await
                .unwrap();
            drop(socket_guard);
            settle().await;
            let resident = registry.peek_resident("doc").unwrap();
            assert_eq!(
                *resident.handle.state().borrow(),
                LifecycleState::Active { connections: 1 },
                "the subdoc pin alone must keep the doc active"
            );
        }

        drop(subdoc_guard);
        settle().await;
        let resident = registry.peek_resident("doc").unwrap();
        assert_eq!(*resident.handle.state().borrow(), LifecycleState::Idle);
    }

    #[tokio::test(start_paused = true)]
    async fn transition_metrics_emitted() {
        let metrics = test_metrics();
        let store = MemoryStore::new();
        let registry = DocRegistry::new(metrics.clone(), no_gc());
        let loader = || {
            let store = store.clone();
            async move { load_doc(&store, "doc").await }
        };

        let transitions = |from: &str, to: &str| {
            metrics
                .doc_lifecycle_transitions_total
                .with_label_values(&[from, to])
                .get()
        };

        let guard = registry
            .attach("doc", AttachKind::Socket, loader)
            .await
            .unwrap();
        settle().await;
        assert_eq!(transitions("loading", "idle"), 1.0, "actor birth");
        assert_eq!(transitions("idle", "active"), 1.0, "first attach");

        drop(guard);
        settle().await;
        assert_eq!(transitions("active", "idle"), 1.0, "last detach");

        assert_eq!(registry.evict("doc").await, EvictOutcome::Evicted);
        assert_eq!(transitions("idle", "evicting"), 1.0);
        assert_eq!(transitions("evicting", "gone"), 1.0);
    }
}
