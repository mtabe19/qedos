//! ProofGate signed configuration format and Ed25519 verification (LAW_011).
//!
//! * `#![no_std]`, zero allocation, `#![forbid(unsafe_code)]`.
//! * Provides both a compact deterministic binary signed configuration format
//!   (`SignedConfig`) for seL4 protection domains (`policy_pd` calls
//!   [`verify_and_parse`] at boot before activating any route or backend) and
//!   pure-Rust RFC 8032 Ed25519 verification usable by both seL4 PDs and the
//!   Linux host proxy (`pg-proxy`).
#![no_std]
#![forbid(unsafe_code)]

pub mod ed25519;

pub use ed25519::{public_key_from_seed, sign_ed25519, verify_ed25519, Sha512};
use pg_http::Method;
use pg_policy::{Action, BackendId, Pattern, Route};

/// Pinned Ed25519 public key corresponding to `config/keys/config-signing-pub.pem`.
pub const PUBLIC_KEY: [u8; 32] = [
    0x7f, 0xfc, 0x2b, 0xb3, 0x7c, 0x19, 0xb1, 0xb7,
    0x16, 0xff, 0x6e, 0x9f, 0xea, 0x5d, 0xb5, 0xcb,
    0x6a, 0xc8, 0x75, 0x8e, 0x99, 0xa8, 0xb0, 0x61,
    0xf3, 0xfc, 0x73, 0x5e, 0x63, 0xcb, 0x5e, 0x71,
];

/// Binary signed config magic header (`"PGS1"`).
pub const MAGIC: [u8; 4] = *b"PGS1";
/// Binary signed config format version.
pub const VERSION: u8 = 1;
/// Ed25519 signature size in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Header size in bytes (`magic[4] + version[1] + n_backends[1] + n_routes[1] + reserved[1]`).
pub const HEADER_LEN: usize = 8;

#[cfg(kani)]
pub const MAX_BACKENDS: usize = 2;
#[cfg(not(kani))]
pub const MAX_BACKENDS: usize = 8;

#[cfg(kani)]
pub const MAX_ROUTES: usize = 2;
#[cfg(not(kani))]
pub const MAX_ROUTES: usize = 16;

pub const MAX_PATTERN_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    TooShort,
    BadMagic,
    UnsupportedVersion,
    BadSignature,
    TooManyBackends,
    TooManyRoutes,
    Malformed,
    InvalidBackend,
    InvalidRoute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BackendSpec {
    pub ipv4: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct SignedConfig<'a> {
    pub backends: [BackendSpec; MAX_BACKENDS],
    pub n_backends: usize,
    pub routes: [Route<'a>; MAX_ROUTES],
    pub n_routes: usize,
}

impl<'a> SignedConfig<'a> {
    pub fn backends(&self) -> &[BackendSpec] {
        &self.backends[..self.n_backends]
    }

    pub fn routes(&self) -> &[Route<'a>] {
        &self.routes[..self.n_routes]
    }
}

fn decode_method(b: u8) -> Option<Method> {
    match b {
        0 => Some(Method::Get),
        1 => Some(Method::Head),
        2 => Some(Method::Post),
        3 => Some(Method::Put),
        4 => Some(Method::Delete),
        5 => Some(Method::Patch),
        6 => Some(Method::Options),
        _ => None,
    }
}

pub fn encode_method(m: Method) -> u8 {
    match m {
        Method::Get => 0,
        Method::Head => 1,
        Method::Post => 2,
        Method::Put => 3,
        Method::Delete => 4,
        Method::Patch => 5,
        Method::Options => 6,
    }
}

fn validate_pattern_bytes(pat: &[u8], is_prefix: bool) -> bool {
    if pat.is_empty() || pat.len() > MAX_PATTERN_LEN {
        return false;
    }
    if pat[0] != b'/' {
        return false;
    }
    if pat.len() >= 2 && pat[1] == b'/' {
        return false;
    }
    if is_prefix && pat[pat.len() - 1] != b'/' {
        return false;
    }
    let mut i = 0;
    while i < pat.len() {
        let b = pat[i];
        if !(0x21..=0x7e).contains(&b) || b == b'?' || b == b'#' || b == b'\\' || b == b';' {
            return false;
        }
        i += 1;
    }
    true
}

/// Parse and validate an unsigned binary config payload (`blob` without the 64-byte signature trailer).
/// Private/internal helper: callers must use [`verify_and_parse`] or [`verify_and_parse_with`] (LAW_011).
pub fn parse_unverified<'a>(payload: &'a [u8]) -> Result<SignedConfig<'a>, ConfigError> {
    if payload.len() < HEADER_LEN {
        return Err(ConfigError::TooShort);
    }
    if payload[0] != MAGIC[0]
        || payload[1] != MAGIC[1]
        || payload[2] != MAGIC[2]
        || payload[3] != MAGIC[3]
    {
        return Err(ConfigError::BadMagic);
    }
    if payload[4] != VERSION {
        return Err(ConfigError::UnsupportedVersion);
    }
    let n_backends = payload[5] as usize;
    let n_routes = payload[6] as usize;
    if payload[7] != 0 {
        return Err(ConfigError::Malformed);
    }
    if n_backends > MAX_BACKENDS {
        return Err(ConfigError::TooManyBackends);
    }
    if n_routes == 0 || n_routes > MAX_ROUTES {
        return Err(ConfigError::TooManyRoutes);
    }

    let mut pos = HEADER_LEN;
    let mut backends = [BackendSpec::default(); MAX_BACKENDS];
    let mut bi = 0;
    while bi < n_backends {
        if pos + 6 > payload.len() {
            return Err(ConfigError::Malformed);
        }
        let ipv4 = [payload[pos], payload[pos + 1], payload[pos + 2], payload[pos + 3]];
        let port = u16::from_be_bytes([payload[pos + 4], payload[pos + 5]]);
        if port == 0 {
            return Err(ConfigError::InvalidBackend);
        }
        backends[bi] = BackendSpec { ipv4, port };
        pos += 6;
        bi += 1;
    }

    let dummy_route = Route {
        method: Method::Get,
        pattern: Pattern::Exact(b"/"),
        action: Action::Health,
    };
    let mut routes = [dummy_route; MAX_ROUTES];
    let mut ri = 0;
    while ri < n_routes {
        if pos + 13 > payload.len() {
            return Err(ConfigError::Malformed);
        }
        let method = decode_method(payload[pos]).ok_or(ConfigError::InvalidRoute)?;
        let pat_kind = payload[pos + 1];
        let act_kind = payload[pos + 2];
        let backend_id = payload[pos + 3];
        let max_body = u64::from_be_bytes([
            payload[pos + 4],
            payload[pos + 5],
            payload[pos + 6],
            payload[pos + 7],
            payload[pos + 8],
            payload[pos + 9],
            payload[pos + 10],
            payload[pos + 11],
        ]);
        let pat_len = payload[pos + 12] as usize;
        pos += 13;

        if pos + pat_len > payload.len() {
            return Err(ConfigError::Malformed);
        }
        let pat_bytes = &payload[pos..pos + pat_len];
        pos += pat_len;

        let is_prefix = match pat_kind {
            0 => false,
            1 => true,
            _ => return Err(ConfigError::InvalidRoute),
        };
        if !validate_pattern_bytes(pat_bytes, is_prefix) {
            return Err(ConfigError::InvalidRoute);
        }
        let pattern = if is_prefix {
            Pattern::Prefix(pat_bytes)
        } else {
            Pattern::Exact(pat_bytes)
        };

        let action = match act_kind {
            0 => {
                if backend_id != 0 || max_body != 0 {
                    return Err(ConfigError::InvalidRoute);
                }
                Action::Health
            }
            1 => {
                if (backend_id as usize) >= n_backends {
                    return Err(ConfigError::InvalidRoute);
                }
                Action::Forward {
                    backend: BackendId(backend_id),
                    max_body,
                }
            }
            _ => return Err(ConfigError::InvalidRoute),
        };

        routes[ri] = Route {
            method,
            pattern,
            action,
        };
        ri += 1;
    }

    if pos != payload.len() {
        return Err(ConfigError::Malformed);
    }

    Ok(SignedConfig {
        backends,
        n_backends,
        routes,
        n_routes,
    })
}

/// Verify `blob`'s trailing 64-byte signature using `verify_fn` before parsing any config bytes (LAW_011).
pub fn verify_and_parse_with<'a, F>(
    blob: &'a [u8],
    pubkey: &[u8; 32],
    verify_fn: F,
) -> Result<SignedConfig<'a>, ConfigError>
where
    F: FnOnce(&[u8; 32], &[u8], &[u8; 64]) -> bool,
{
    if blob.len() < HEADER_LEN + SIGNATURE_LEN {
        return Err(ConfigError::TooShort);
    }
    let payload_len = blob.len() - SIGNATURE_LEN;
    let payload = &blob[..payload_len];
    let sig_slice = &blob[payload_len..];
    let mut sig = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        sig[i] = sig_slice[i];
        i += 1;
    }
    if !verify_fn(pubkey, payload, &sig) {
        return Err(ConfigError::BadSignature);
    }
    parse_unverified(payload)
}

/// Verify the Ed25519 signature at the end of `blob` against `pubkey` and parse the
/// binary configuration (LAW_011).
pub fn verify_and_parse<'a>(
    blob: &'a [u8],
    pubkey: &[u8; 32],
) -> Result<SignedConfig<'a>, ConfigError> {
    verify_and_parse_with(blob, pubkey, verify_ed25519)
}

/// Serialize `backends` and `routes` into the deterministic binary payload format in `out`.
/// Returns the number of payload bytes written.
pub fn encode_payload(
    backends: &[BackendSpec],
    routes: &[Route<'_>],
    out: &mut [u8],
) -> Result<usize, ConfigError> {
    if backends.len() > MAX_BACKENDS {
        return Err(ConfigError::TooManyBackends);
    }
    if routes.is_empty() || routes.len() > MAX_ROUTES {
        return Err(ConfigError::TooManyRoutes);
    }
    if out.len() < HEADER_LEN {
        return Err(ConfigError::TooShort);
    }
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = VERSION;
    out[5] = backends.len() as u8;
    out[6] = routes.len() as u8;
    out[7] = 0;
    let mut pos = HEADER_LEN;

    let mut bi = 0;
    while bi < backends.len() {
        let b = backends[bi];
        if b.port == 0 {
            return Err(ConfigError::InvalidBackend);
        }
        if pos + 6 > out.len() {
            return Err(ConfigError::TooShort);
        }
        out[pos..pos + 4].copy_from_slice(&b.ipv4);
        out[pos + 4..pos + 6].copy_from_slice(&b.port.to_be_bytes());
        pos += 6;
        bi += 1;
    }

    let mut ri = 0;
    while ri < routes.len() {
        let r = routes[ri];
        let (pat_kind, pat_bytes) = match r.pattern {
            Pattern::Exact(s) => (0u8, s),
            Pattern::Prefix(s) => (1u8, s),
        };
        if !validate_pattern_bytes(pat_bytes, pat_kind == 1) {
            return Err(ConfigError::InvalidRoute);
        }
        let (act_kind, backend_id, max_body) = match r.action {
            Action::Health => (0u8, 0u8, 0u64),
            Action::Forward { backend, max_body } => {
                if (backend.0 as usize) >= backends.len() {
                    return Err(ConfigError::InvalidRoute);
                }
                (1u8, backend.0, max_body)
            }
        };
        if pos + 13 + pat_bytes.len() > out.len() {
            return Err(ConfigError::TooShort);
        }
        out[pos] = encode_method(r.method);
        out[pos + 1] = pat_kind;
        out[pos + 2] = act_kind;
        out[pos + 3] = backend_id;
        out[pos + 4..pos + 12].copy_from_slice(&max_body.to_be_bytes());
        out[pos + 12] = pat_bytes.len() as u8;
        pos += 13;
        out[pos..pos + pat_bytes.len()].copy_from_slice(pat_bytes);
        pos += pat_bytes.len();
        ri += 1;
    }

    Ok(pos)
}

/// Encode and sign a binary configuration blob (`payload || Ed25519_sig`) into `out`.
pub fn encode_and_sign(
    backends: &[BackendSpec],
    routes: &[Route<'_>],
    seed: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, ConfigError> {
    let payload_len = encode_payload(backends, routes, out)?;
    if payload_len + SIGNATURE_LEN > out.len() {
        return Err(ConfigError::TooShort);
    }
    let sig = sign_ed25519(seed, &out[..payload_len]);
    out[payload_len..payload_len + SIGNATURE_LEN].copy_from_slice(&sig);
    Ok(payload_len + SIGNATURE_LEN)
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a 128-character ASCII hex string (ignoring trailing whitespace) into a 64-byte Ed25519 signature.
pub fn parse_hex_sig(mut hex_bytes: &[u8]) -> Option<[u8; 64]> {
    while let [first, rest @ ..] = hex_bytes {
        if matches!(*first, b' ' | b'\t' | b'\r' | b'\n') {
            hex_bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = hex_bytes {
        if matches!(*last, b' ' | b'\t' | b'\r' | b'\n') {
            hex_bytes = rest;
        } else {
            break;
        }
    }
    if hex_bytes.len() != 128 {
        return None;
    }
    let mut sig = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        let hi = hex_nibble(hex_bytes[i * 2])?;
        let lo = hex_nibble(hex_bytes[i * 2 + 1])?;
        sig[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(sig)
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
