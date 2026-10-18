# QEDOS on aarch64 (QEMU virt verified, Raspberry Pi 4 image builds, hardware untested)

## Status

| Target | Build | Boot / tests |
|---|---|---|
| `qemu_virt_aarch64` (QEMU, Cortex-A53, virtio-net) | OK | PASS: `SEL4_001..006` (same suite as x86_64) |
| `rpi4b_1gb` (Raspberry Pi 4, GENET NIC) | OK, capability audit PASS | **Not run.** No Pi hardware; QEMU `raspi4b` has no GENET Ethernet |
| x86_64 (`x86_64_generic`) | Source changed, prebuilt image still passes | The x86_64 image was **not rebuilt** here (its toolchain is not on macOS) |

## Build and run (macOS or Linux, no root)

```sh
brew install qemu lld llvm rustup dtc && rustup target add aarch64-unknown-none
python3 -m venv third_party/venv && third_party/venv/bin/pip install sdfgen   # sdfgen 0.35.x
# Microkit SDK 2.3.1 for your host -> third_party/microkit/microkit-sdk-2.3.1
scripts/build-openssl.sh                                  # host OpenSSL for cargo test
QEDOS_ARCH=aarch64 scripts/build-sel4.sh                  # fetches headers, OpenSSL, sDDF; builds build/sel4-qemu_virt_aarch64
QEDOS_ARCH=aarch64 python3 tests/test_sel4.py             # SEL4_001..006 in QEMU (TCG, boot ~1 min)
QEDOS_ARCH=aarch64 QEDOS_BOARD=rpi4b_1gb scripts/build-sel4.sh   # Pi 4 image (build/sel4-rpi4b_1gb/loader.img)
QEDOS_SEL4_DIR=build/sel4-rpi4b_1gb python3 scripts/check-caps.py
```

New helpers: `scripts/build-sddf.sh` (pins sDDF `12f6667`), `scripts/fetch-aarch64-headers.sh`
(glibc headers only, SHA-256 pinned, needed because the libc shim implements the glibc ABI),
`tools/run-aarch64.sh`. x86_64 outputs stay in `build/sel4`; aarch64 goes to `build/sel4-<board>`.

## Changes needed for the port

* **Memory ordering (real bug class).** `PG_FENCE()` was only a compiler barrier, which is enough on x86 TSO
  but not on aarch64. It is now `dmb ish` on aarch64 (unchanged on x86_64).
* **Time.** Under seL4 hypervisor mode an EL0 read of `CNTVCT_EL0` faults the PD. `tcp_pd` now publishes the
  sDDF timer value in `shm_tcp_tls->now_ns` (appended after the slots, so offsets are unchanged) and `tls_pd`
  feeds it to `libc_shim_set_clock_ns()`. No-op on x86_64.
* **OpenSSL** cross-built with `linux-aarch64`; shim gained `usleep`, aarch64 `getrandom` syscall number, `brk` for abort.
* **System generator** takes `--board`/`--dtb`. Pi 4 uses a higher `paddr_top` (sDDF default 32 MiB collides with the image).
* Rust PDs needed no change (`aarch64-unknown-none`).

## Known blockers before any real deployment

1. **Entropy is NOT secure on aarch64.** Cortex-A53/A72 have no hardware RNG instruction and EL0 cannot probe
   one. The shim mixes a timer value through SplitMix64, which is predictable. TLS ephemeral keys (and so the
   PQC handshake's secrecy) are only as good as that. The build prints a `#warning`. Needed: an entropy PD
   (virtio-rng on QEMU, bcm2835 RNG on Pi 4) feeding `tls_pd`. **Do not expose this build to a network you do not control.**
2. **Pi 4 is unverified on hardware:** GENET driver bring-up, boot procedure (U-Boot load address, `config.txt`,
   UART pins), and the 1 GB RAM fit. Follow the Microkit manual's Raspberry Pi 4B section; I did not verify it.
3. The `x86_64` shim/PD edits are syntax-checked for x86 only; rebuild that image on Linux and rerun the suite.
4. Performance on real Cortex-A72 is unmeasured (QEMU TCG numbers mean nothing).
