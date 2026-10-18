# QEDOS Test Report (macOS, 2026-10-18)

Environment: macOS (Darwin 25.5.0, Apple Silicon), QEMU 11.1.2 (Homebrew), rustc/cargo 1.99.0, Python 3.12.2,
pinned OpenSSL 3.6.1 built by `scripts/build-openssl.sh`. seL4 image: prebuilt `build/sel4/loader.img.gz`.

## Results

| Step | Command | Result |
|---|---|---|
| 1 | `qemu-system-x86_64 --version` | Was not installed; `brew install qemu` completed, now 11.1.2 |
| 2 | `python3 tests/test_sel4.py` | PASS: SEL4_001 to SEL4_006 (all 6) |
| 3 | `cargo test --workspace --exclude pg-load` | PASS: pg-config 3, pg-http 21, pg-policy 6, pg-proxy 0; 30 passed, 0 failed |
| 4 | `python3 scripts/check-caps.py` | PASS: 12 PDs, 14 channels, 12 Viper models (LAW_008, LAW_011, LAW_012) |

## Problems found and fixes

1. **`scripts/check-caps.py` failed on a fresh macOS checkout** with `missing build/sel4/http_pd.elf`.
   Only `loader.img.gz` and `sel4_32.elf.gz` are committed, not the per-PD ELFs. Because `tests/test_sel4.py`
   runs this audit first (SEL4_006), the whole seL4 suite was blocked.
   Fix: when the per-PD ELFs are absent, the LAW_008 private-key check scans the flattened boot image instead.
   It requires exactly one PEM private key, located at the `.tls_keystore` layout offset (certificate slot 2048 bytes
   before the key). When all ELFs exist, the original per-ELF scan runs unchanged. The system-description
   and Viper checks are untouched.
2. **`cargo test` failed in `openssl-sys`** (`third_party/openssl-install/include` missing). `.cargo/config.toml`
   pins the in-tree OpenSSL 3.6.1. No code change; ran `scripts/build-openssl.sh` as the README Quick start says.
   The Homebrew OpenSSL (3.6.5) was deliberately not substituted, to keep the pinned build.

## Not run

* `tests/test_tls.py`, `tests/test_http.py`, `tests/perf.py`, `cargo kani`: outside the requested scope.
  `pg-proxy` reads `/proc` for stats, so the host proxy suites are expected to be Linux-oriented.
* The seL4 image was not rebuilt (needs the Linux cross-toolchain); results are for the committed prebuilt image.
* `third_party/` is git-ignored, so the OpenSSL build is not part of the diff.

## Addendum: aarch64 port (same day)

| Step | Command | Result |
|---|---|---|
| aarch64 image | `QEDOS_ARCH=aarch64 scripts/build-sel4.sh` | builds (QEMU virt and Pi 4) |
| aarch64 seL4 suite | `QEDOS_ARCH=aarch64 python3 tests/test_sel4.py` | PASS: SEL4_001 to SEL4_006 on QEMU virt |
| Pi 4 audit | `QEDOS_SEL4_DIR=build/sel4-rpi4b_1gb python3 scripts/check-caps.py` | PASS (12 PDs, 15 channels, 12 Viper models) |
| x86_64 regression | `python3 tests/test_sel4.py` | PASS: all 6 (prebuilt image, not rebuilt) |

Not verified: Pi 4 hardware boot, entropy quality (placeholder, see `docs/AARCH64.md`), rebuilt x86_64 image. Details in `docs/AARCH64.md`.
