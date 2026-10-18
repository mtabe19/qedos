# Security laws — specification, evidence, and scope

Legend:
* **PROVEN-BOUNDED** = Kani model checking of the real Rust code (`13/13` harnesses pass, 0 failures), for inputs up to the stated length bound.
* **VIPER-AUDITED** = Microkit `--viper-output` formal capability/memory invariant export (`build/sel4/viper/*.vpr`) + `scripts/check-caps.py` verification on `build/sel4/proofgate.system` and PD ELFs.
* **TESTED** = automated tests on both the Linux host reference proxy (`tests/test_tls.py`, `tests/test_http.py`, `tests/perf.py`) and the seL4 multi-PD OS image in QEMU (`tests/test_sel4.py`).

| Law | Spec (informal) | Evidence today | Assumptions | Not proven / scope limits |
|---|---|---|---|---|
| `LAW_001` only fixed routes reachable | `decide()` returns `Health`, `Forward(table index)` or `Reject`; path hygiene rejects dot-segments, `;`, `//`, encoded `/ \ . %`, controls, overlong UTF-8 | **PROVEN-BOUNDED** `pg-policy::proofs::accepted_path_has_no_traversal` (≤8 B, 0 failed); **TESTED** unit tests + 34 HTTP tests + `SEL4_004/005` + `PERF_008` (18 513 hostile probes, 0 backend violations) | Kani bound | inputs >8 B in Kani (covered by unit/fuzz/integration tests) |
| `LAW_002` TLS ≥1.3 only | handshake with <1.3 never completes | **TESTED** `TEST_TLS_002` (host) + `SEL4_002` (seL4 `tls_pd`); config `min=max=TLS1_3_VERSION` + post-handshake `SSL_version` re-check | OpenSSL 3.6.1 correct | no formal proof of OpenSSL C code |
| `LAW_003` only `X25519MLKEM768` | no other key-exchange group negotiated | **TESTED** `TEST_TLS_003/004/006/007/008` (host) + `SEL4_001/003` (seL4 `tls_pd`) + `test_tls_shim_runner`; `set1_groups_list` + post-handshake `SSL_get0_group_name` re-check | OpenSSL 3.6.1 correct | group name read from OpenSSL |
| `LAW_004` no client-chosen backend | backend address only from fixed table | **PROVEN-BOUNDED** `forward_backend_is_table_member` & `deployed_routes_forward_only_to_valid_backends` (`pg-policy`); **TESTED** `SEL4_004` (seL4 `connector_pd`) + `PERF_008` | signed config key trusted | Kani bound ≤8 B |
| `LAW_005` no shell/exec path | no process-spawn API reachable from HTTP input | **STATIC CHECK** `scripts/check-laws.sh` across `crates/*` and `sel4/*`; **VERIFIED ON seL4** (`build/sel4/loader.img` has no shell or process-creation syscall) | — | on Linux host mode, the host OS itself has a shell |
| `LAW_006` parser stays in bounds | no OOB / arithmetic overflow for any input | `#![forbid(unsafe_code)]` in `pg-http`, `pg-policy`, `pg-config`; **PROVEN-BOUNDED** `pg-http` **8/8 harnesses pass** (`parse_request_spans_in_bounds`, `parse_response_spans_in_bounds`, `accepted_request_is_http11_with_host`, `chunk_decoder_in_bounds`, plus 4 validator harnesses; logs in `build/kani/`) | Kani bounds (`N=18..20`, `MAX_HEADERS=2` under Kani) | inputs larger than Kani bound rely on safe Rust bounds checks (`panic=abort`) |
| `LAW_007` rejected ⇒ not forwarded | parse error or `Reject` ⇒ no backend connect | **VIPER-AUDITED & TESTED**: on seL4, `http_pd` has no channel to `connector_pd` or `tcp_pd`, and `policy_pd` notifies `connector_pd` only on `Decision::Forward`; verified by `SEL4_005`, `test_http.py`, `PERF_008` | `policy_pd` C glue (~30 lines) | — |
| `LAW_008` TLS key not reachable from HTTP layer | private key mapped only in `tls_pd` | **VIPER-AUDITED** (`build/sel4/viper/tls_pd.vpr` vs `http_pd.vpr`, `policy_pd.vpr`, `connector_pd.vpr`, `tcp_pd.vpr` + ELF scan in `scripts/check-caps.py`) and **TESTED** `TEST_TLS_010`, `SEL4_006` | seL4 kernel + Microkit initializer | not satisfied when running the single-process Linux reference proxy |
| `LAW_009` resources freed after close | connection state & heap reclaimed on close | **TESTED** `PERF_007` (host: 10k conns → active 0, fds 6→6, RSS 9.3 MB) + `test_tls_shim_runner` (seL4 `libc_shim` coalescing heap: 0 bytes leaked across repeated TLS 1.3 `X25519MLKEM768` handshakes) | — | no formal heap proof |
| `LAW_010` no unauthenticated admin op | no dynamic route/admin endpoint exists | **VERIFIED** by code inspection (`pg-policy` and `pg-config` have no admin routes or runtime mutation API) | — | config updates require reboot with newly signed image |
| `LAW_011` only signed config applied | Ed25519 signature verified against pinned `PUBLIC_KEY` before applying routes/backends | **PROVEN-BOUNDED** `pg-config` **2/2 harnesses pass** (`unverified_blob_always_rejected`, `parse_blob_in_bounds`); **TESTED** `test_signed_config_law_011` (`tests/test_http.py`) + `SEL4_001` (`policy_pd` verifies `shm_signed_config` at boot) | Ed25519 private key security | — |
| `LAW_012` minimal capabilities for proxy | each PD holds only its required shm/channel caps; no app PD holds IRQ/ioport/TCB caps | **VIPER-AUDITED** (`build/sel4/viper/*.vpr` + `scripts/check-caps.py` + `SEL4_006`) | Microkit tool & CapDL initializer | — |

Reproduce all checks:
```sh
cargo test
cargo kani -p pg-policy && cargo kani -p pg-http && cargo kani -p pg-config
scripts/check-laws.sh
python3 tests/test_tls.py && python3 tests/test_http.py && python3 tests/test_sel4.py
```
