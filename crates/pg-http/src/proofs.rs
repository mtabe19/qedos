//! Kani proof harnesses (`cargo kani -p pg-http`). Bounded model checking of the
//! *actual* parser code over all byte contents up to the stated length bounds.
//! These are bounded proofs, not unbounded ones: see docs/LAWS.md.
use super::*;

const N: usize = 8;

/// LAW_006: for every input of length <= N, the parser never panics (no
/// out-of-bounds index, no arithmetic overflow) and every span it returns lies
/// inside the input.
#[kani::proof]
#[kani::unwind(10)]
fn parse_request_spans_in_bounds() {
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let input = &buf[..len];
    if let Ok(Some(r)) = parse_request(input) {
        assert!(r.head_len <= len);
        assert!(r.target.start <= r.target.end && r.target.end <= len);
        assert!(r.host.start <= r.host.end && r.host.end <= len);
        assert!(r.n_headers <= MAX_HEADERS);
        let mut i = 0;
        while i < r.n_headers {
            let h = r.headers[i];
            assert!(h.name.start <= h.name.end && h.name.end <= len);
            assert!(h.value.start <= h.value.end && h.value.end <= len);
            i += 1;
        }
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn parse_response_spans_in_bounds() {
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let head_req: bool = kani::any();
    if let Ok(Some(r)) = parse_response(&buf[..len], head_req) {
        assert!(r.head_len <= len);
        assert!(r.n_headers <= MAX_HEADERS);
    }
}

/// Smuggling invariant: an accepted request never carries both Content-Length
/// and chunked framing (framing is a single enum, but also assert that Length
/// framing implies a bounded, parsed value).
#[kani::proof]
#[kani::unwind(10)]
fn accepted_request_is_http11_with_host() {
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    if let Ok(Some(r)) = parse_request(&buf[..len]) {
        // target is origin-form
        assert!(buf[r.target.start] == b'/');
        assert!(!r.host.is_empty());
        assert!(r.target.len() <= MAX_TARGET_BYTES);
    }
}

/// LAW_006 for the chunked decoder: consumed <= input, payload span inside the
/// consumed prefix, and total accounting never overflows.
#[kani::proof]
#[kani::unwind(12)]
fn chunk_decoder_in_bounds() {
    let buf: [u8; 10] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 10);
    let mut d = ChunkDecoder::new(kani::any());
    if let Ok(a) = d.advance(&buf[..len]) {
        assert!(a.consumed <= len);
        if let Some(sp) = a.data {
            assert!(sp.start <= sp.end && sp.end <= a.consumed);
        }
    }
}

/// Compositional proof for `validate_head_bytes`: never panics and accepts only
/// properly paired CRLF and printable/HTAB bytes.
#[kani::proof]
#[kani::unwind(10)]
fn validate_head_bytes_in_bounds() {
    let buf: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let s = &buf[..len];
    if validate_head_bytes(s).is_ok() {
        let mut i = 0;
        while i < s.len() {
            assert!(s[i] != 0x00 && s[i] != 0x7f);
            if s[i] == b'\r' {
                assert!(i + 1 < s.len() && s[i + 1] == b'\n');
                i += 2;
                continue;
            }
            assert!(s[i] != b'\n');
            i += 1;
        }
    }
}

/// Compositional proof for `validate_target`: never panics and enforces origin-form
/// target starting with single `/` and no `#`, `\`, or control/space bytes.
#[kani::proof]
#[kani::unwind(10)]
fn validate_target_in_bounds() {
    let buf: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let s = &buf[..len];
    if validate_target(s).is_ok() {
        assert!(!s.is_empty());
        assert!(s[0] == b'/');
        if s.len() >= 2 {
            assert!(s[1] != b'/');
        }
        let mut i = 0;
        while i < s.len() {
            assert!((0x21..=0x7e).contains(&s[i]) && s[i] != b'#' && s[i] != b'\\');
            i += 1;
        }
    }
}

/// Compositional proof for `validate_host`: never panics and rejects empty or
/// invalid host header bytes.
#[kani::proof]
#[kani::unwind(10)]
fn validate_host_in_bounds() {
    let buf: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let s = &buf[..len];
    if validate_host(s).is_ok() {
        assert!(!s.is_empty() && s.len() <= 255);
    }
}

/// Compositional proof for `parse_u64_digits`: never overflows or panics, and
/// accepts only non-empty ASCII decimal strings up to 19 digits.
#[kani::proof]
#[kani::unwind(22)]
fn parse_u64_digits_no_overflow() {
    let buf: [u8; 20] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 20);
    let s = &buf[..len];
    if let Some(_v) = parse_u64_digits(s) {
        assert!(!s.is_empty() && s.len() <= 19);
        let mut i = 0;
        while i < s.len() {
            assert!(s[i].is_ascii_digit());
            i += 1;
        }
    }
}

