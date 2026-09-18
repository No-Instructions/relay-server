//! Collapses a run of edits to one doc by one user into a single logged burst.
//!
//! A keystroke is one Yjs update, so typing a sentence produces dozens of
//! `Doc edited` lines that differ only in timestamp. The interesting unit for
//! an operator is the burst: who touched what, for how long, and how much
//! changed.
//!
//! The first edit of a burst logs immediately - a debounce that only reported
//! on quiesce would hide active editing for the whole window, which is the one
//! moment someone tailing the log wants to see. Everything after it accrues
//! here until the burst goes quiet, and the sweeper emits the totals.
//!
//! Bursts are keyed by doc *and* user: two people in one file are two bursts,
//! so neither line attributes the other's typing.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Quiet period after which a burst is considered finished. Chosen against real
/// traffic: continuous typing lands updates ~0.15s apart, while pauses to think
/// reach 9s, so a shorter window splits one editing session into several lines.
pub const BURST_QUIET: Duration = Duration::from_secs(10);

/// Identifies a burst. The doc id rather than the vpath: a rename mid-burst
/// would otherwise split it in two, and the vpath is only a display concern.
#[derive(Clone, PartialEq, Eq, Hash)]
struct _BurstKey {
    doc_id: String,
    user: String,
}

struct _Burst {
    /// Display fields, refreshed on every edit so the flushed line reports the
    /// vpath the doc had when editing stopped.
    vpath: String,
    /// The shared folder the doc belongs to; a doc id alone does not say which.
    channel: String,
    /// Every Yjs client id seen in the burst, so the summary can name the
    /// build(s) that produced it. A burst is one user, but a user may edit from
    /// more than one device.
    clients: BTreeSet<u64>,
    /// Edits after the leading one, which is logged rather than accrued.
    suppressed: u64,
    /// Bytes across the whole burst, leading edit included.
    bytes: usize,
    started: Instant,
    last_edit: Instant,
}

/// A burst that has gone quiet and is ready to log.
pub struct FinishedBurst {
    pub doc_id: String,
    pub user: String,
    pub vpath: String,
    pub channel: String,
    pub clients: Vec<u64>,
    /// Total edits in the burst, including the one already logged.
    pub edits: u64,
    pub bytes: usize,
    pub span: Duration,
}

/// Whether an edit should be logged now or folded into a pending burst.
pub enum Verdict {
    /// First edit for this doc+user; log it as it arrives.
    Leading,
    /// Burst already announced; the totals will come from the flush.
    Suppressed,
}

/// One recorded edit. A struct rather than positional arguments because four
/// of these fields are strings that would silently transpose.
pub struct Edit<'a> {
    pub doc_id: &'a str,
    pub user: &'a str,
    /// Stored for the eventual flush, so passing the resolved path (not "-")
    /// whenever it is known keeps the summary line useful.
    pub vpath: &'a str,
    pub channel: &'a str,
    pub clients: &'a [u64],
    pub bytes: usize,
}

#[derive(Default)]
pub struct EditBursts {
    bursts: Mutex<HashMap<_BurstKey, _Burst>>,
}

impl EditBursts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an edit, reporting whether the caller should log it.
    pub fn record(&self, edit: Edit) -> Verdict {
        self.record_at(edit, Instant::now())
    }

    /// `now` is a parameter so a caller can replay a recorded cadence against
    /// the same clock the sweep reads; reading it internally would leave the
    /// two disagreeing and flush bursts mid-run.
    fn record_at(&self, edit: Edit, now: Instant) -> Verdict {
        let Edit {
            doc_id,
            user,
            vpath,
            channel,
            clients,
            bytes,
        } = edit;
        let mut bursts = self.bursts.lock().unwrap();
        let key = _BurstKey {
            doc_id: doc_id.to_string(),
            user: user.to_string(),
        };
        match bursts.get_mut(&key) {
            Some(burst) => {
                burst.suppressed += 1;
                burst.bytes += bytes;
                burst.last_edit = now;
                burst.clients.extend(clients);
                if !vpath.is_empty() && vpath != "-" {
                    burst.vpath = vpath.to_string();
                }
                Verdict::Suppressed
            }
            None => {
                bursts.insert(
                    key,
                    _Burst {
                        vpath: vpath.to_string(),
                        channel: channel.to_string(),
                        clients: clients.iter().copied().collect(),
                        suppressed: 0,
                        bytes,
                        started: now,
                        last_edit: now,
                    },
                );
                Verdict::Leading
            }
        }
    }

    /// Removes and returns every burst quiet for at least `BURST_QUIET`.
    ///
    /// Bursts whose only edit was the leading one are dropped without being
    /// returned: that line already said everything, and a summary repeating it
    /// with `edits=1` would double the output this exists to reduce.
    pub fn take_finished(&self) -> Vec<FinishedBurst> {
        self.take_finished_as_of(Instant::now())
    }

    fn take_finished_as_of(&self, now: Instant) -> Vec<FinishedBurst> {
        let mut bursts = self.bursts.lock().unwrap();
        let quiet: Vec<_BurstKey> = bursts
            .iter()
            .filter(|(_, burst)| now.saturating_duration_since(burst.last_edit) >= BURST_QUIET)
            .map(|(key, _)| key.clone())
            .collect();

        quiet
            .into_iter()
            .filter_map(|key| {
                let burst = bursts.remove(&key)?;
                if burst.suppressed == 0 {
                    return None;
                }

                Some(FinishedBurst {
                    doc_id: key.doc_id,
                    user: key.user,
                    vpath: burst.vpath,
                    channel: burst.channel,
                    clients: burst.clients.into_iter().collect(),
                    edits: burst.suppressed + 1,
                    bytes: burst.bytes,
                    span: burst.last_edit.saturating_duration_since(burst.started),
                })
            })
            .collect()
    }

    /// Every pending burst, ignoring the quiet window, for shutdown.
    ///
    /// Without this a burst in flight when the server stops is never reported,
    /// which loses exactly the edits made just before a restart.
    pub fn drain_all(&self) -> Vec<FinishedBurst> {
        let mut bursts = self.bursts.lock().unwrap();
        bursts
            .drain()
            .filter(|(_, burst)| burst.suppressed > 0)
            .map(|(key, burst)| FinishedBurst {
                doc_id: key.doc_id,
                user: key.user,
                vpath: burst.vpath,
                channel: burst.channel,
                clients: burst.clients.into_iter().collect(),
                edits: burst.suppressed + 1,
                bytes: burst.bytes,
                span: burst.last_edit.saturating_duration_since(burst.started),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_leading(verdict: Verdict) -> bool {
        matches!(verdict, Verdict::Leading)
    }

    #[test]
    fn the_first_edit_logs_and_the_rest_do_not() {
        let bursts = EditBursts::new();
        assert!(is_leading(bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        })));
        assert!(!is_leading(bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        })));
        assert!(!is_leading(bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        })));
    }

    #[test]
    fn a_quiet_burst_reports_totals_including_the_leading_edit() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 11,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 3,
        });

        let finished = bursts.take_finished_as_of(Instant::now() + BURST_QUIET);
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0].edits, 3);
        assert_eq!(finished[0].bytes, 40);
        assert_eq!(finished[0].vpath, "/a.md");
    }

    #[test]
    fn a_burst_still_being_typed_is_not_flushed() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });

        assert!(bursts.take_finished().is_empty());
    }

    #[test]
    fn a_lone_edit_is_dropped_rather_than_summarized() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });

        assert!(bursts
            .take_finished_as_of(Instant::now() + BURST_QUIET)
            .is_empty());
    }

    #[test]
    fn two_users_in_one_doc_are_separate_bursts() {
        let bursts = EditBursts::new();
        assert!(is_leading(bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        })));
        assert!(is_leading(bursts.record(Edit {
            doc_id: "doc",
            user: "heather",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        })));
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "heather",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });

        let mut finished = bursts.take_finished_as_of(Instant::now() + BURST_QUIET);
        finished.sort_by(|a, b| a.user.cmp(&b.user));
        assert_eq!(finished.len(), 2);
        assert_eq!(finished[0].user, "alan");
        assert_eq!(finished[1].user, "heather");
    }

    #[test]
    fn a_later_edit_starts_a_new_burst_that_logs_again() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        assert_eq!(
            bursts
                .take_finished_as_of(Instant::now() + BURST_QUIET)
                .len(),
            1
        );

        assert!(is_leading(bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        })));
    }

    #[test]
    fn a_rename_mid_burst_reports_the_latest_vpath() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/before.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/after.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });

        let finished = bursts.take_finished_as_of(Instant::now() + BURST_QUIET);
        assert_eq!(finished[0].vpath, "/after.md");
    }

    #[test]
    fn an_unresolved_vpath_does_not_overwrite_a_known_one() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "-",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });

        let finished = bursts.take_finished_as_of(Instant::now() + BURST_QUIET);
        assert_eq!(finished[0].vpath, "/a.md");
    }

    #[test]
    fn replaying_the_observed_keystroke_cadence_yields_one_burst() {
        // Real gaps from a 69-edit / 26.2s typing run: continuous typing at
        // ~0.15s with pauses up to 9.34s, all inside one quiet window.
        let gaps_ms: [u64; 68] = [
            1400, 104, 42, 315, 199, 137, 160, 142, 1299, 174, 36, 201, 121, 132, 95, 512, 76, 100,
            121, 103, 80, 56, 76, 1309, 9335, 384, 216, 159, 80, 105, 138, 98, 135, 136, 96, 105,
            155, 112, 76, 123, 185, 125, 1875, 124, 96, 60, 232, 144, 399, 209, 120, 121, 157, 138,
            92, 99, 158, 67, 172, 128, 136, 116, 116, 184, 163, 336, 553, 1420,
        ];

        let bursts = EditBursts::new();
        let mut at = Instant::now();
        let mut leading = 0;
        if is_leading(bursts.record_at(
            Edit {
                doc_id: "doc",
                user: "alan",
                vpath: "/a.md",
                channel: "folder",
                clients: &[1],
                bytes: 26,
            },
            at,
        )) {
            leading += 1;
        }
        for gap in gaps_ms {
            at += Duration::from_millis(gap);
            // A sweep runs between edits; none should fire mid-burst.
            assert!(bursts.take_finished_as_of(at).is_empty());
            if is_leading(bursts.record_at(
                Edit {
                    doc_id: "doc",
                    user: "alan",
                    vpath: "/a.md",
                    channel: "folder",
                    clients: &[1],
                    bytes: 26,
                },
                at,
            )) {
                leading += 1;
            }
        }

        let finished = bursts.take_finished_as_of(at + BURST_QUIET);
        assert_eq!(leading, 1, "only the first edit should log immediately");
        assert_eq!(finished.len(), 1, "the run should collapse to one burst");
        assert_eq!(finished[0].edits, 69);
    }

    #[test]
    fn shutdown_drains_bursts_that_have_not_gone_quiet() {
        let bursts = EditBursts::new();
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 26,
        });
        bursts.record(Edit {
            doc_id: "doc",
            user: "alan",
            vpath: "/a.md",
            channel: "folder",
            clients: &[1],
            bytes: 14,
        });

        let drained = bursts.drain_all();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].edits, 2);
        assert_eq!(drained[0].bytes, 40);
        assert!(bursts.take_finished().is_empty());
    }
}
