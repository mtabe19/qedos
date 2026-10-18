# QEDOS

**QEDOS** is a formally verified, PQC-hybrid-only HTTPS reverse-proxy OS appliance running on **seL4 + Microkit 2.3.1 (`x86_64_generic`)** with a matching Linux reference proxy.
Enforces **TLS 1.3 + `X25519MLKEM768` + `TLS_AES_256_GCM_SHA384` only**, strict `#![no_std]` / `#![forbid(unsafe_code)]` HTTP/1.1 parsing (`pg-http`), fixed-route policy (`pg-policy`), Ed25519 signed configuration (`pg-config`, `LAW_011`), 5 isolated seL4 Protection Domains (`tcp_pd`, `tls_pd`, `http_pd`, `policy_pd`, `connector_pd`), Kani bounded proofs (`13/13` harnesses passing), and Microkit Viper capability verification (`LAW_008`, `LAW_012`).

**Read `docs/STATUS.md` first** — it separates what is verified from what remains hardware-dependent.

* `docs/ARCHITECTURE.md` — stages A–D (all verified), seL4 multi-PD architecture & shared-memory rings
* `docs/SECURITY.md` — guarantees and limits (X.509 auth is *not* post-quantum)
* `docs/LAWS.md` — `LAW_001..012`: specification, Kani / Viper / test evidence, and assumptions
* `docs/RESULTS.md` — TLS, HTTP, seL4 multi-PD, Kani, and C10K measurement results

## Quick start (no root needed)
```sh
scripts/build-openssl.sh            # pinned OpenSSL 3.6.1 for host (sha256-checked), once
scripts/build-openssl-sel4.sh       # freestanding OpenSSL 3.6.1 for seL4 tls_pd, once
scripts/gen-dev-cert.sh             # self-signed localhost cert (tests only)
scripts/sign-config.sh              # Ed25519-sign host (.sig) and seL4 (proxy.sconf) configs
cargo build --release
scripts/build-sel4.sh               # build seL4 multi-PD image (build/sel4/loader.img) + Viper (.vpr)

# Verification & test suites:
cargo test                                         # unit tests (pg-http, pg-policy, pg-config)
scripts/check-laws.sh                              # static checks + Viper capability audit (LAW_005/008/011/012)
python3 tests/test_tls.py                          # TEST_TLS_001..010
python3 tests/test_http.py                         # 34 HTTP + Ed25519 signed-config (LAW_011) tests
python3 tests/test_sel4.py                         # SEL4_001..006 end-to-end multi-PD seL4 tests in QEMU
python3 tests/perf.py                              # PERF_001..008 at 10 000 connections (host reference)
cargo kani -p pg-policy && cargo kani -p pg-http && cargo kani -p pg-config   # 13/13 Kani bounded proofs
```
