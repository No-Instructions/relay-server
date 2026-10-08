use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, RwLock};
use y_sweet_core::api_types::Authorization;
use y_sweet_core::doc_connection::DocConnection;
use y_sweet_core::sync::{awareness::Awareness, Message};
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, Transact};

struct TrackingAllocator;
thread_local! {
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        track(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        track(size);
        System.realloc(ptr, layout, size)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}
fn track(size: usize) {
    let _ = ALLOCATED.try_with(|total| {
        if let Some(n) = total.get() {
            total.set(Some(n.saturating_add(size)));
        }
    });
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

#[tokio::test]
async fn hostile_sync_is_refused_before_mutating_the_document() {
    let awareness = Arc::new(RwLock::new(Awareness::new(Doc::new())));
    let connection = DocConnection::new(awareness.clone(), Authorization::Full, |_| {});
    let before = awareness.read().unwrap().doc().transact().state_vector();
    let messages: &[&[u8]] = &[
        // Six-byte sync step 1: framed state vector claiming millions of clients.
        &[0, 0, 3, 0xff, 0xff, 0x7f],
        // The reported six-byte hostile state vector, wrapped in sync framing.
        &[0, 0, 6, 0xff, 0xff, 0xff, 0x7f, 1, 1],
        // Payload length cannot fit in the message, for every sync subtype.
        &[0, 0, 0xff, 0xff, 0xff, 0x7f],
        &[0, 1, 0xff, 0xff, 0xff, 0x7f],
        &[0, 2, 0xff, 0xff, 0xff, 0x7f],
        // Valid framing around hostile step 2 and update block counts.
        &[0, 1, 8, 0xff, 0xff, 0xff, 0x7f, 1, 1, 0, 0],
        &[0, 2, 8, 0xff, 0xff, 0xff, 0x7f, 1, 1, 0, 0],
        // Clock overflow and zero-length GC, through the actual apply boundary.
        &[0, 2, 11, 1, 1, 5, 0xff, 0xff, 0xff, 0xff, 0x0f, 0, 2, 0],
        &[0, 2, 7, 1, 1, 5, 0, 0, 0, 0],
        // The server owns a separate awareness decoder.
        &[1, 4, 0xff, 0xff, 0xff, 0x7f],
        &[
            1, 11, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10, 0, 0,
        ],
    ];
    for bytes in messages {
        ALLOCATED.with(|total| total.set(Some(0)));
        let start = std::time::Instant::now();
        let result = connection.send(bytes).await;
        let elapsed = start.elapsed();
        let allocated = ALLOCATED.with(|total| total.replace(None).unwrap());
        assert!(result.is_err(), "accepted {bytes:?}");
        assert!(
            allocated < 64 * 1024,
            "requested {allocated} bytes for {bytes:?}"
        );
        eprintln!(
            "hostile sync: {} bytes, {allocated} allocated, {elapsed:?}",
            bytes.len()
        );
        let after = awareness.read().unwrap().doc().transact().state_vector();
        assert_eq!(before, after);
    }
    // Valid empty step 1, step 2 and update retain their normal behavior.
    for bytes in [&[0, 0, 1, 0][..], &[0, 1, 2, 0, 0], &[0, 2, 2, 0, 0]] {
        assert!(Message::decode_v1(bytes).is_ok());
        assert!(connection.send(bytes).await.is_ok());
    }
}
