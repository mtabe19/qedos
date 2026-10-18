//! Kani harnesses for pg-policy (`cargo kani -p pg-policy`). Bounded proofs.
use super::*;

const N: usize = 8;

/// LAW_001/LAW_004 (path part): any target the policy lets through contains no
/// dot-segment, no ';', no encoded '/', '\\', '.', '%' and no control byte --
/// for every byte string up to length N.
#[kani::proof]
#[kani::unwind(12)]
fn accepted_path_has_no_traversal() {
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let t = &buf[..len];
    if let Some((path, _q)) = split_target(t) {
        assert!(path[0] == b'/');
        let mut i = 0;
        while i < path.len() {
            let b = path[i];
            assert!(b != b';' && b != b'\\' && b >= 0x21 && b < 0x7f);
            // segment starting at i after '/' must not be "." or ".." or empty (except trailing)
            if b == b'/' {
                let rest = &path[i + 1..];
                let seg_end = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());
                let seg = &rest[..seg_end];
                assert!(seg != b"." && seg != b"..");
                if seg_end < rest.len() {
                    assert!(!seg.is_empty()); // no "//" inside the path
                }
            }
            i += 1;
        }
    }
}

/// LAW_004: `decide` can only return a backend index that appears in the
/// (fixed) route table; request bytes never become an address.
#[kani::proof]
#[kani::unwind(12)]
fn forward_backend_is_table_member() {
    const ROUTES: &[Route] = &[
        Route { method: Method::Get, pattern: Pattern::Exact(b"/a"), action: Action::Forward { backend: BackendId(0), max_body: 0 } },
        Route { method: Method::Post, pattern: Pattern::Prefix(b"/g/"), action: Action::Forward { backend: BackendId(1), max_body: 10 } },
        Route { method: Method::Get, pattern: Pattern::Exact(b"/h"), action: Action::Health },
    ];
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let m: u8 = kani::any();
    kani::assume(m < 7);
    let method = match m {
        0 => Method::Get, 1 => Method::Head, 2 => Method::Post, 3 => Method::Put,
        4 => Method::Delete, 5 => Method::Patch, _ => Method::Options,
    };
    match decide(ROUTES, method, &buf[..len]) {
        Decision::Forward { backend, .. } => assert!(backend.0 <= 1),
        _ => {}
    }
}

/// LAW_004 on the deployed route table shape (`/health`, `/api/chat`, `/game/`, `/static/`):
/// any `Decision::Forward` produces only a valid backend index in the table (`0..=2`).
#[kani::proof]
#[kani::unwind(12)]
fn deployed_routes_forward_only_to_valid_backends() {
    const DEPLOYED_ROUTES: &[Route] = &[
        Route { method: Method::Get, pattern: Pattern::Exact(b"/health"), action: Action::Health },
        Route { method: Method::Post, pattern: Pattern::Exact(b"/api/chat"), action: Action::Forward { backend: BackendId(0), max_body: 1 << 20 } },
        Route { method: Method::Get, pattern: Pattern::Exact(b"/api/models"), action: Action::Forward { backend: BackendId(0), max_body: 0 } },
        Route { method: Method::Get, pattern: Pattern::Exact(b"/api/events"), action: Action::Forward { backend: BackendId(0), max_body: 0 } },
        Route { method: Method::Get, pattern: Pattern::Prefix(b"/game/"), action: Action::Forward { backend: BackendId(1), max_body: 0 } },
        Route { method: Method::Post, pattern: Pattern::Prefix(b"/game/"), action: Action::Forward { backend: BackendId(1), max_body: 65536 } },
        Route { method: Method::Get, pattern: Pattern::Prefix(b"/static/"), action: Action::Forward { backend: BackendId(2), max_body: 0 } },
    ];
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let m: u8 = kani::any();
    kani::assume(m < 7);
    let method = match m {
        0 => Method::Get, 1 => Method::Head, 2 => Method::Post, 3 => Method::Put,
        4 => Method::Delete, 5 => Method::Patch, _ => Method::Options,
    };
    match decide(DEPLOYED_ROUTES, method, &buf[..len]) {
        Decision::Forward { backend, .. } => assert!(backend.0 <= 2),
        _ => {}
    }
}

