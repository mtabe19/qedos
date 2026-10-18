extern crate std;
use super::*;

const ROUTES: &[Route] = &[
    Route { method: Method::Get, pattern: Pattern::Exact(b"/health"), action: Action::Health },
    Route { method: Method::Post, pattern: Pattern::Exact(b"/api/chat"), action: Action::Forward { backend: BackendId(0), max_body: 1 << 20 } },
    Route { method: Method::Get, pattern: Pattern::Exact(b"/api/models"), action: Action::Forward { backend: BackendId(0), max_body: 0 } },
    Route { method: Method::Get, pattern: Pattern::Prefix(b"/game/"), action: Action::Forward { backend: BackendId(1), max_body: 0 } },
];

fn d(m: Method, t: &str) -> Decision {
    decide(ROUTES, m, t.as_bytes())
}

#[test]
fn routes() {
    assert_eq!(d(Method::Get, "/health"), Decision::Health);
    assert_eq!(d(Method::Head, "/health"), Decision::Health);
    assert_eq!(d(Method::Post, "/api/chat"), Decision::Forward { backend: BackendId(0), max_body: 1 << 20 });
    assert_eq!(d(Method::Post, "/api/chat?x=1"), Decision::Forward { backend: BackendId(0), max_body: 1 << 20 });
    assert_eq!(d(Method::Get, "/game/a/b.js"), Decision::Forward { backend: BackendId(1), max_body: 0 });
    assert_eq!(d(Method::Get, "/game/"), Decision::Forward { backend: BackendId(1), max_body: 0 });
}

#[test]
fn rejects() {
    assert_eq!(d(Method::Get, "/nope"), Decision::Reject(404));
    assert_eq!(d(Method::Get, "/health/"), Decision::Reject(404));
    assert_eq!(d(Method::Get, "/game"), Decision::Reject(404));
    assert_eq!(d(Method::Get, "/api/chat"), Decision::Reject(405));
    assert_eq!(d(Method::Delete, "/game/x"), Decision::Reject(405));
    assert_eq!(d(Method::Post, "/health"), Decision::Reject(405));
}

#[test]
fn traversal_and_evasions_are_400() {
    for t in [
        "/game/../api/chat", "/game/./x", "/game/..", "/game/.", "/game//x", "/game/%2e%2e/x",
        "/game/%2E%2E/x", "/game/.%2e/x", "/game/%2e/x", "/game/%2fx", "/game/%2Fx", "/game/%5cx",
        "/game/%5Cx", "/game/%00", "/game/%0a", "/game/%7f", "/game/%25", "/game/%c0%ae%c0%ae/x", "/game/%c0%af", "/game/%e0%80%ae", "/game/%f0%80%80%ae", "/game/%ed%a0%80", "/game/%f4%90%80%80", "/game/%ff", "/game/%c3", "/game/%c3a", "/game/%c3/%a9", "/game/%e2%82/%ac", "/game/..;/x", "/game/a;b", "/game/;", "/game/%", "/game/%4",
        "/game/%zz", "/game/a b", "/game/a\"b", "/game/<x>", "/game/a{b}", "/game/a|b", "/game/a^b",
        "/game/a`b", "/game/[x]", "/game/\u{e9}", "/game/a?b#c", "/game/x?%00", "/game/x?a b",
        "/game/x?%zz", "/game/x?\\", "/api/chat/../../health",
    ] {
        assert_eq!(d(Method::Get, t), Decision::Reject(400), "{t}");
    }
    // not rooted
    assert_eq!(d(Method::Get, "game/x"), Decision::Reject(400));
    assert_eq!(d(Method::Get, ""), Decision::Reject(400));
    assert_eq!(d(Method::Get, "http://evil/"), Decision::Reject(400));
}

#[test]
fn valid_utf8_escapes_allowed() {
    // é, €, 😀
    for t in ["/game/%c3%a9", "/game/%E2%82%AC", "/game/%f0%9f%98%80/x"] {
        assert!(matches!(d(Method::Get, t), Decision::Forward { .. }), "{t}");
    }
}

#[test]
fn query_is_never_routed() {
    // a query that looks like a path must not select a route
    assert_eq!(d(Method::Get, "/nope?/game/x"), Decision::Reject(404));
    assert_eq!(d(Method::Get, "/health?x=/game/"), Decision::Health);
}

/// Exhaustive-ish: for every 1..=3 byte path suffix, any non-Reject decision
/// only ever yields a backend id that exists in the route table (LAW_004).
#[test]
fn forward_targets_are_table_members() {
    let alphabet: &[u8] = b"/.%2e5cag?#\\ \x00\xff";
    let mut buf = std::vec![b'/', b'g', b'a', b'm', b'e', b'/'];
    let base = buf.len();
    fn rec(buf: &mut std::vec::Vec<u8>, base: usize, depth: usize, alphabet: &[u8]) {
        for m in [Method::Get, Method::Post, Method::Head, Method::Delete] {
            if let Decision::Forward { backend, .. } = decide(ROUTES, m, buf) {
                assert!(ROUTES.iter().any(|r| matches!(r.action, Action::Forward { backend: b, .. } if b == backend)));
            }
        }
        if depth == 0 {
            return;
        }
        for &c in alphabet {
            buf.push(c);
            rec(buf, base, depth - 1, alphabet);
            buf.pop();
        }
    }
    rec(&mut buf, base, 3, alphabet);
}
