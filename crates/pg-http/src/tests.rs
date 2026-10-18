extern crate std;
use super::*;
use std::vec::Vec;

fn ok(s: &str) -> Request {
    parse_request(s.as_bytes()).expect("parse error").expect("partial")
}
fn err(s: &str) -> ParseError {
    parse_request(s.as_bytes()).expect_err("should reject")
}

const GET: &str = "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n";

#[test]
fn simple_get() {
    let r = ok(GET);
    assert_eq!(r.method, Method::Get);
    assert_eq!(r.target.slice(GET.as_bytes()), b"/health");
    assert_eq!(r.framing, Framing::None);
    assert!(r.keep_alive);
    assert_eq!(r.head_len, GET.len());
}

#[test]
fn partial_returns_none() {
    for n in 0..GET.len() {
        assert!(parse_request(&GET.as_bytes()[..n]).unwrap().is_none(), "n={n}");
    }
}

#[test]
fn pipelined_bytes_not_consumed() {
    let s = std::format!("{GET}GET /x HTTP/1.1\r\nHost: a\r\n\r\n");
    let r = ok(&s);
    assert_eq!(r.head_len, GET.len());
}

#[test]
fn content_length_and_chunked() {
    let r = ok("POST /api/chat HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n");
    assert_eq!(r.framing, Framing::Length(12));
    let r = ok("POST /api/chat HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert_eq!(r.framing, Framing::Chunked);
    let r = ok("POST /api/chat HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: CHUNKED\r\n\r\n");
    assert_eq!(r.framing, Framing::Chunked);
}

#[test]
fn smuggling_cl_te_rejected() {
    let e = err("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert_eq!(e, ParseError::BadFraming);
    let e = err("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n");
    assert_eq!(e, ParseError::BadFraming);
}

#[test]
fn smuggling_duplicate_cl_rejected() {
    // even identical duplicates are rejected
    assert_eq!(err("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"), ParseError::BadFraming);
    assert_eq!(err("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"), ParseError::BadFraming);
}

#[test]
fn smuggling_bad_cl_values() {
    for v in ["+5", "-1", "5 5", "0x10", "5,5", "", "1e3", "99999999999999999999", " "] {
        let s = std::format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {v}\r\n\r\n");
        assert!(parse_request(s.as_bytes()).is_err(), "accepted CL {v:?}");
    }
}

#[test]
fn smuggling_te_variants_rejected() {
    for v in ["chunked, gzip", "gzip, chunked", "identity", "gzip", "chunked;q=1", "xchunked", "chunke", "chunked,"] {
        let s = std::format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {v}\r\n\r\n");
        assert!(parse_request(s.as_bytes()).is_err(), "accepted TE {v:?}");
    }
    // duplicate TE
    assert!(parse_request(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
}

#[test]
fn smuggling_header_syntax() {
    // space before colon
    assert!(parse_request(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n").is_err());
    assert!(parse_request(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n").is_err());
    // obs-fold
    assert!(parse_request(b"POST / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n").is_err());
    assert!(parse_request(b"POST / HTTP/1.1\r\nHost: a\r\n Content-Length: 5\r\n\r\n").is_err());
    // bare LF / bare CR
    assert!(parse_request(b"GET / HTTP/1.1\nHost: a\n\n\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\nX: y\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\rX: y\r\n\r\n").is_err());
    // NUL / control in value or name
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\r\nX\x01: a\r\n\r\n").is_err());
    // empty header name, no colon
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n").is_err());
}

#[test]
fn request_line_strictness() {
    assert!(parse_request(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n").is_err()); // double space
    assert!(parse_request(b"GET / HTTP/1.1 \r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b" GET / HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"get / HTTP/1.1\r\nHost: a\r\n\r\n").is_err()); // lowercase method
    assert_eq!(err("GET / HTTP/1.0\r\nHost: a\r\n\r\n"), ParseError::UnsupportedVersion);
    assert_eq!(err("GET / HTTP/2.0\r\nHost: a\r\n\r\n"), ParseError::UnsupportedVersion);
    assert_eq!(err("GET / HTTP/1.2\r\nHost: a\r\n\r\n"), ParseError::UnsupportedVersion);
    assert_eq!(err("GET / http/1.1\r\nHost: a\r\n\r\n"), ParseError::Malformed);
}

#[test]
fn forbidden_and_unknown_methods() {
    assert_eq!(err("CONNECT example.com:443 HTTP/1.1\r\nHost: a\r\n\r\n"), ParseError::ForbiddenMethod);
    assert_eq!(err("TRACE / HTTP/1.1\r\nHost: a\r\n\r\n"), ParseError::ForbiddenMethod);
    assert_eq!(err("BREW / HTTP/1.1\r\nHost: a\r\n\r\n"), ParseError::UnknownMethod);
    assert_eq!(err("PROPFIND / HTTP/1.1\r\nHost: a\r\n\r\n"), ParseError::UnknownMethod);
}

#[test]
fn target_forms() {
    // forward-proxy absolute-form, authority, asterisk are refused
    assert!(parse_request(b"GET http://evil/ HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"GET evil:80 HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"GET //evil/x HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"GET /a#frag HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"GET /a\\b HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request(b"GET /a\x7f HTTP/1.1\r\nHost: a\r\n\r\n").is_err());
    assert!(parse_request("GET /あ HTTP/1.1\r\nHost: a\r\n\r\n".as_bytes()).is_err());
    let long = std::format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "a".repeat(3000));
    assert_eq!(err(&long), ParseError::TargetTooLong);
}

#[test]
fn host_rules() {
    assert!(parse_request(b"GET / HTTP/1.1\r\n\r\n").is_err()); // missing
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n").is_err()); // dup
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: \r\n\r\n").is_err()); // empty
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a@b\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n").is_err());
    assert!(parse_request(b"GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n").is_ok());
}

#[test]
fn upgrade_expect_refused() {
    assert_eq!(err("GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), ParseError::Unsupported);
    assert_eq!(err("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\n\r\n"), ParseError::Unsupported);
    assert_eq!(err("POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n"), ParseError::ExpectationFailed);
}

#[test]
fn head_limits() {
    let mut s = std::string::String::from("GET / HTTP/1.1\r\nHost: a\r\n");
    for i in 0..MAX_HEADERS {
        s.push_str(&std::format!("X-{i}: v\r\n"));
    }
    s.push_str("\r\n");
    assert_eq!(err(&s), ParseError::HeadTooLarge); // 64 + Host > 64
    let big = std::format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n\r\n", "a".repeat(20_000));
    assert_eq!(err(&big), ParseError::HeadTooLarge);
    // incomplete but already over limit
    let partial = std::format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}", "a".repeat(20_000));
    assert_eq!(parse_request(partial.as_bytes()).unwrap_err(), ParseError::HeadTooLarge);
}

#[test]
fn connection_close() {
    assert!(!ok("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").keep_alive);
    assert!(!ok("GET / HTTP/1.1\r\nHost: a\r\nConnection: Keep-Alive, Close\r\n\r\n").keep_alive);
}

#[test]
fn never_panics_on_prefixes_and_mutations() {
    // deterministic pseudo-fuzz: every prefix and single-byte mutation of seeds
    let seeds: [&[u8]; 3] = [
        b"POST /api/chat HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\nConnection: close\r\n\r\n",
        b"POST /api/chat HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET /game/x?y=1 HTTP/1.1\r\nHost: a.b:1\r\nX-A: b\r\n\r\n",
    ];
    for seed in seeds {
        for n in 0..=seed.len() {
            let _ = parse_request(&seed[..n]);
        }
        for i in 0..seed.len() {
            for b in 0u8..=255 {
                let mut v: Vec<u8> = seed.to_vec();
                v[i] = b;
                let _ = parse_request(&v);
                let _ = parse_response(&v, false);
            }
        }
    }
}

// ---- responses ----

#[test]
fn response_framing() {
    let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", false).unwrap().unwrap();
    assert_eq!(r.framing, Framing::Length(5));
    let r = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", false).unwrap().unwrap();
    assert_eq!(r.framing, Framing::Chunked);
    let r = parse_response(b"HTTP/1.1 200 OK\r\n\r\n", false).unwrap().unwrap();
    assert_eq!(r.framing, Framing::UntilClose);
    let r = parse_response(b"HTTP/1.1 204 No Content\r\n\r\n", false).unwrap().unwrap();
    assert_eq!(r.framing, Framing::None);
    let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", true).unwrap().unwrap();
    assert_eq!(r.framing, Framing::None);
    assert!(parse_response(b"HTTP/1.1 100 Continue\r\n\r\n", false).is_err());
    assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", false).is_err());
    assert!(parse_response(b"HTTP/1.1 2000 OK\r\n\r\n", false).is_err());
    assert!(parse_response(b"garbage\r\n\r\n", false).is_err());
}

// ---- chunked ----

fn run_chunked(input: &[u8], step: usize) -> Result<(Vec<u8>, usize, bool), ChunkError> {
    let mut d = ChunkDecoder::new(1 << 20);
    let mut out = Vec::new();
    let mut consumed_total = 0;
    let mut i = 0;
    while i < input.len() {
        let end = (i + step).min(input.len());
        let mut piece = &input[i..end];
        loop {
            let a = d.advance(piece)?;
            if let Some(sp) = a.data {
                out.extend_from_slice(sp.slice(piece));
            }
            consumed_total += a.consumed;
            piece = &piece[a.consumed..];
            if a.done || piece.is_empty() {
                break;
            }
        }
        if d.is_done() {
            break;
        }
        i = end;
    }
    Ok((out, consumed_total, d.is_done()))
}

#[test]
fn chunked_decode_all_split_points() {
    let msg = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nEXTRA";
    for step in 1..=msg.len() {
        let (out, consumed, done) = run_chunked(msg, step).unwrap();
        assert_eq!(out, b"hello world");
        assert!(done);
        assert_eq!(consumed, msg.len() - 5, "step {step}");
    }
}

#[test]
fn chunked_rejects() {
    for bad in [
        &b"5;ext=1\r\nhello\r\n0\r\n\r\n"[..],       // extension
        b"g\r\n",                                    // non-hex
        b"\r\n",                                     // empty size
        b"5\nhello\r\n0\r\n\r\n",                    // bare LF
        b"5\r\nhelloXX0\r\n\r\n",                    // missing CRLF after data
        b"0\r\nTrailer: x\r\n\r\n",                  // trailers
        b"-1\r\n",
        b"11111111111111111\r\n",                    // 17 digits
        b" 5\r\nhello\r\n0\r\n\r\n",
    ] {
        assert!(run_chunked(bad, 1).is_err(), "accepted {:?}", std::string::String::from_utf8_lossy(bad));
    }
}

#[test]
fn chunked_limit() {
    let mut d = ChunkDecoder::new(10);
    assert_eq!(d.advance(b"b\r\n").unwrap_err(), ChunkError::TooLarge);
}
