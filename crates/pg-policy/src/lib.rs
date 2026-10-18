//! ProofGate policy engine: fixed routes, no dynamic destinations.
//!
//! The only output that can lead to an outbound connection is
//! `Decision::Forward { backend, .. }` where `backend` is an *index* into a
//! table of addresses fixed at build/config-load time. No byte of the request
//! is ever used to construct an address (LAW_001, LAW_004).
#![no_std]
#![forbid(unsafe_code)]

use pg_http::Method;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendId(pub u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern<'a> {
    /// Whole path must equal this string.
    Exact(&'a [u8]),
    /// Path must start with this string, which must end in '/'.
    Prefix(&'a [u8]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Answered locally by the proxy.
    Health,
    Forward { backend: BackendId, max_body: u64 },
}

#[derive(Clone, Copy, Debug)]
pub struct Route<'a> {
    pub method: Method,
    pub pattern: Pattern<'a>,
    pub action: Action,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Health,
    Forward { backend: BackendId, max_body: u64 },
    /// Reject with this HTTP status; nothing is forwarded (LAW_007).
    Reject(u16),
}

#[inline]
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn is_pchar_plain(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'-' | b'.' | b'_' | b'~'                                   // unreserved
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' // sub-delims
        | b':' | b'@')
}

/// Strict UTF-8 validator (RFC 3629: no overlongs, no surrogates, <= U+10FFFF)
/// fed one *decoded* byte at a time. Rejects `%c0%ae`-style dot encodings.
#[derive(Clone, Copy)]
struct Utf8 {
    /// continuation bytes still required
    need: u8,
    /// allowed range for the next continuation byte
    lo: u8,
    hi: u8,
}

impl Utf8 {
    fn new() -> Self {
        Utf8 { need: 0, lo: 0x80, hi: 0xbf }
    }
    fn feed(&mut self, b: u8) -> bool {
        if self.need == 0 {
            match b {
                0x00..=0x7f => {}
                0xc2..=0xdf => self.need = 1,
                0xe0 => { self.need = 2; self.lo = 0xa0; }
                0xe1..=0xec | 0xee..=0xef => self.need = 2,
                0xed => { self.need = 2; self.hi = 0x9f; }
                0xf0 => { self.need = 3; self.lo = 0x90; }
                0xf1..=0xf3 => self.need = 3,
                0xf4 => { self.need = 3; self.hi = 0x8f; }
                _ => return false,
            }
            true
        } else {
            if b < self.lo || b > self.hi {
                return false;
            }
            self.need -= 1;
            self.lo = 0x80;
            self.hi = 0xbf;
            true
        }
    }
    fn complete(&self) -> bool {
        self.need == 0
    }
}

/// Validate a `%XX` escape at `i`; returns the decoded byte.
fn pct(s: &[u8], i: usize) -> Option<u8> {
    if i + 2 >= s.len() {
        return None;
    }
    Some(hex(s[i + 1])? << 4 | hex(s[i + 2])?)
}

/// Split and validate an origin-form request target.
/// Returns `(path, query)` or `None` if the target is not acceptable.
///
/// Rejected: `;` in the path, dot segments (literal or `%2e`), empty segments except a single
/// trailing one, encoded `/`, `\`, NUL/control bytes, encoded `%`, characters
/// outside RFC 3986 `pchar`.
pub fn split_target(target: &[u8]) -> Option<(&[u8], &[u8])> {
    if target.first() != Some(&b'/') {
        return None;
    }
    let q = target.iter().position(|&b| b == b'?');
    let (path, query) = match q {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, &target[target.len()..]),
    };
    // ---- path
    let mut i = 0;
    let mut seg_start = 1; // after leading '/'
    let mut utf8 = Utf8::new();
    while i < path.len() {
        let b = path[i];
        if b == b'/' {
            if !utf8.complete() {
                return None;
            }
            if i != 0 {
                // end of a segment
                let seg = &path[seg_start..i];
                if seg.is_empty() || seg == b"." || seg == b".." {
                    return None;
                }
                seg_start = i + 1;
            }
            i += 1;
        } else if b == b'%' {
            let d = pct(path, i)?;
            if d < 0x20 || d == 0x7f || matches!(d, b'/' | b'\\' | b'.' | b'%') {
                return None;
            }
            if !utf8.feed(d) {
                return None;
            }
            i += 3;
        } else if b == b';' {
            // Path parameters (`..;x`, `;jsessionid`) are interpreted by some
            // backends as dot-segments or stripped, creating a parser
            // differential; no route needs them.
            return None;
        } else if is_pchar_plain(b) {
            if !utf8.complete() {
                return None; // ASCII inside an unfinished %-encoded sequence
            }
            i += 1;
        } else {
            return None;
        }
    }
    if !utf8.complete() {
        return None;
    }
    // last segment (may be empty only if path ends with '/')
    let last = &path[seg_start.min(path.len())..];
    if last == b"." || last == b".." {
        return None;
    }
    // ---- query
    let mut j = 0;
    while j < query.len() {
        let b = query[j];
        if b == b'%' {
            let d = pct(query, j)?;
            if d < 0x20 || d == 0x7f {
                return None;
            }
            j += 3;
        } else if is_pchar_plain(b) || b == b'/' || b == b'?' {
            j += 1;
        } else {
            return None;
        }
    }
    Some((path, query))
}

fn matches(p: &Pattern, path: &[u8]) -> bool {
    match p {
        Pattern::Exact(s) => path == *s,
        Pattern::Prefix(s) => path.starts_with(s),
    }
}

/// Decide what to do with a parsed request. Pure function of its inputs.
pub fn decide(routes: &[Route], method: Method, target: &[u8]) -> Decision {
    let (path, _query) = match split_target(target) {
        Some(x) => x,
        None => return Decision::Reject(400),
    };
    let mut path_seen = false;
    for r in routes {
        if !matches(&r.pattern, path) {
            continue;
        }
        path_seen = true;
        let method_ok = r.method == method || (r.method == Method::Get && method == Method::Head);
        if method_ok {
            return match r.action {
                Action::Health => Decision::Health,
                Action::Forward { backend, max_body } => Decision::Forward { backend, max_body },
            };
        }
    }
    Decision::Reject(if path_seen { 405 } else { 404 })
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
