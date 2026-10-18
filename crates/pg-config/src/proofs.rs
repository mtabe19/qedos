//! Kani proof harnesses for `pg-config` (`cargo kani -p pg-config`).
//! Bounded model checking of LAW_011 (unverified/tampered config is always
//! rejected before parsing) and LAW_006/LAW_004 (binary config parser never
//! panics/OOBs and only produces valid backend indices).
use super::*;

const N_PAYLOAD: usize = 24;
const N_BLOB: usize = HEADER_LEN + SIGNATURE_LEN + 4;

/// LAW_011: Any configuration blob whose signature check fails is unconditionally
/// rejected with `Err(ConfigError::BadSignature)` (or `TooShort`) and never
/// produces an accepted `SignedConfig`.
#[kani::proof]
#[kani::unwind(68)]
fn unverified_blob_always_rejected() {
    let blob: [u8; N_BLOB] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N_BLOB);
    let pubkey: [u8; 32] = kani::any();
    let sig_ok: bool = kani::any();

    let res = verify_and_parse_with(&blob[..len], &pubkey, |_pk, _msg, _sig| sig_ok);
    if !sig_ok {
        assert!(matches!(
            res,
            Err(ConfigError::TooShort | ConfigError::BadSignature)
        ));
    }
}

/// LAW_006 / LAW_004: For every binary payload up to `N_PAYLOAD` bytes,
/// `parse_unverified` never panics (no OOB slice or arithmetic overflow), and
/// any accepted route table only references backend indices `< n_backends` and
/// non-empty rooted patterns.
#[kani::proof]
#[kani::unwind(26)]
fn parse_blob_in_bounds() {
    let buf: [u8; N_PAYLOAD] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N_PAYLOAD);
    if let Ok(cfg) = parse_unverified(&buf[..len]) {
        assert!(cfg.n_backends <= MAX_BACKENDS);
        assert!(cfg.n_routes >= 1 && cfg.n_routes <= MAX_ROUTES);
        let mut bi = 0;
        while bi < cfg.n_backends {
            assert!(cfg.backends[bi].port != 0);
            bi += 1;
        }
        let mut ri = 0;
        while ri < cfg.n_routes {
            let r = cfg.routes[ri];
            match r.pattern {
                Pattern::Exact(p) => {
                    assert!(!p.is_empty() && p[0] == b'/');
                }
                Pattern::Prefix(p) => {
                    assert!(!p.is_empty() && p[0] == b'/' && p[p.len() - 1] == b'/');
                }
            }
            if let Action::Forward { backend, .. } = r.action {
                assert!((backend.0 as usize) < cfg.n_backends);
            }
            ri += 1;
        }
    }
}
