# Test and measurement results (host reference proxy + seL4 multi-PD appliance, 2026-10-18)

Environment: 24-core Linux host, loopback, client + proxy + backends on the same machine, proxy single-threaded,
OpenSSL 3.6.1, Chrome 134.0.6998.88; seL4 + Microkit 2.1.0 multi-PD appliance under QEMU `qemu64,+rdrand`.

## TLS (tests/test_tls.py) — 11/11 pass
| Test | What is checked | Evidence |
|---|---|---|
| 001 | TLS1.3 + X25519MLKEM768 succeeds | s_client: `Negotiated TLS1.3 group: X25519MLKEM768`, AES-256-GCM |
| 002 | TLS 1.2 refused | handshake alert; no 200 |
| 003 / 004 | X25519-only / secp256r1-only refused | `handshake failure`, group `<NULL>` |
| 005 | malformed ClientHello (≈500 truncations/mutations/garbage) | proxy alive, no panic |
| 006 | negotiated group cross-checked client *and* server log | both `X25519MLKEM768` |
| 007 | no fallback for 6 classical/other groups + Python restricted to P-256 | all refused, no TLS line logged |
| 008 | real Chrome 134 headless | page body received; server log: group X25519MLKEM768 |
| 009 | 0-RTT | ticket carries `Max Early Data: 0`; resumption attempt with early data not accepted. Limitation: cannot force a non-compliant client to send 0-RTT bytes; relies on OpenSSL rejecting them |
| 010 | no key/secret leakage | private-key PEM lines and client-exported traffic secrets (keylog) absent from proxy log and responses; `SSLKEYLOGFILE` ignored |

## HTTP & Signed Config (tests/test_http.py) — 34/34 pass
Routing to the right backend; unknown path/method → 404/405/501 **and backends' own request logs prove nothing
was forwarded**; absolute-form/CONNECT/TRACE refused; hostile Host/X-Forwarded-*/Forwarded/Via stripped or
replaced; traversal (`..`, `%2e`, `%2f`, `%5c`, `%00`, `;`, overlong UTF-8) → 400; CL+TE, duplicate CL, TE
obfuscation, bare LF/CR/NUL, obs-fold → 400; pipelining; chunked reframing; 413 limits; keep-alive; 64 MiB
response with slow reader (backpressure); SSE incremental delivery; client disconnect stops backend stream;
slowloris / stalled handshake / idle timeouts; **Ed25519 signed config enforcement (`LAW_011` — missing/tampered `.sig` rejected before socket bind)**.
Plus 21 `pg-http` unit tests, 6 `pg-policy` tests, and 4 `pg-config` unit tests (`cargo test`).

## seL4 Multi-PD Appliance (tests/test_sel4.py) — 6/6 pass
Booted `build/sel4/loader.img` in QEMU (`x86_64`, `virtio-net-pci`, host port forward `:18443 -> 10.0.2.15:8443`, SLIRP gateway `10.0.2.2:19001/19002` to host backends):
| ID | What is checked | Evidence |
|---|---|---|
| SEL4_001 | Multi-PD boot + Ed25519 config verification + Viper capability audit | `policy_pd: Ed25519 config verified (routes=4, backends=2)`, all 5 app PDs booted, `scripts/check-caps.py` PASS |
| SEL4_002 | End-to-end HTTPS `GET /a/hello` through `tcp_pd -> tls_pd -> http_pd -> policy_pd -> connector_pd -> tcp_pd` | 200 OK from host backend A (`"backend": "a"`), `Negotiated TLS1.3 group: X25519MLKEM768` |
| SEL4_003 | Policy routing to second backend (`GET /b/info`) | 200 OK from host backend B (`"backend": "b"`) |
| SEL4_004 | Path traversal & unmapped route rejection inside `http_pd` / `policy_pd` | `/a/../secret` → 400, `/unknown/path` → 404; backend request log confirms 0 leaked requests |
| SEL4_005 | Header sanitization & `X-Forwarded-Proto: https` injection in `http_pd` | Backend sees `"host": "backend-a.internal"`, `"x-forwarded-proto": "https"`, spoofed `X-Forwarded-For` stripped |
| SEL4_006 | Classical-only TLS group (`X25519`) rejected by `tls_pd` | Handshake failure alert; appliance remains healthy for subsequent PQ requests |

## Formal Verification (Kani & Viper)
* **Kani bounded proofs (`13/13` harnesses pass)**:
  * `pg-http` (`build/kani/pg-http.log`): 8/8 harnesses prove panic-freedom, span bounds, HTTP/1.1 + `Host` enforcement, and chunk-size overflow safety (`LAW_001`, `LAW_004`, `LAW_006`).
  * `pg-policy` (`build/kani/pg-policy.log`): 3/3 harnesses prove path traversal rejection and backend index validity (`LAW_005`).
  * `pg-config` (`build/kani/pg-config.log`): 2/2 harnesses prove unverified blob rejection (`VerifiedConfig::verify_and_parse` is the sole constructor) and binary parser bounds (`LAW_011`).
* **Microkit Viper models & capability audit (`build/sel4/viper/*.vpr`, `scripts/check-caps.py`)**:
  * Proves `LAW_008` (shared memory topology matches pipeline stages; `tls_pd` and `connector_pd` are completely disjoint; `policy_pd` has no payload ring mappings) and `LAW_012` (only `eth_driver` holds IRQ/MMIO capabilities).

## C10K (tests/perf.py, 10 000 connections, Linux host proxy) — 8/8 pass
| ID | Result |
|---|---|
| PERF_001 | 10 000 TCP held; proxy RSS 9.6 MB (TLS state is lazily allocated) |
| PERF_002 | 10 000 TLS1.3/X25519MLKEM768 held, 0 failures, avg handshake 2.8 ms under ramp; ≈27.8 KB RSS per connection (peak 285 MB) |
| PERF_003 | 10 000 keep-alive HTTPS connections each served one proxied request, 0 errors |
| PERF_004 | 10 % active (think 50 ms), 20 s: ≈13.4 k req/s, 0 errors |
| PERF_005 | 2 000 SSE + 8 000 mixed conns: 39 960 SSE events in 20 s (expected 40 000), 0 errors |
| PERF_006 | handshake storm (3000 concurrent, PQ handshake + request + close): ≈5.4 k handshakes/s single core |
| PERF_007 | after release: active 0, fds 6 (=baseline), RSS back to 9.3 MB (needs `malloc_trim`) |
| PERF_008 | 18 513 hostile probes during 10 k-connection load all got the expected status; backend audit saw 888 578 requests, 0 violating (path/Host/spoofed headers); policy_violations 0 |

Latency percentiles in the load tool are log2 buckets (upper bounds), measured with the client sharing the CPU.

## Bugs the tests found (fixed)
* Handshake could complete inside `SSL_accept` (client Finished already queued) and bypass the post-handshake
  policy re-check and metrics → crash on counter underflow at close. Now every handshake completion goes through one path.
* `;` path parameters and overlong-UTF-8 `%c0%ae` were accepted by the first policy version.
* Pre-handshake connections allocated ~44 KB of OpenSSL buffers each; now deferred until first byte.
* OpenSSL 3.6.1 `ML-KEM-768` key decapsulation requires >16 KiB stack; Microkit PD stack size was increased to 256 KiB (`0x40000`) in `sel4/meta_proofgate.py`.
* QEMU default `qemu64` CPU model disables `RDRAND` unless `+rdrand` is passed; `sel4/libc_shim/libc_shim.c` now guards `rdrand` with CPUID leaf 1 ECX bit 30 and mixes `rdtsc` with SplitMix64.

