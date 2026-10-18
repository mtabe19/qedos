# Plan: QEDOS on bare-metal AMD64 (USB boot)

Status: investigation only, nothing here is implemented or tested on hardware.
Findings come from this repository, the sDDF checkout (`12f6667`), the Microkit 2.3.1 SDK, and public seL4 pages.

## Why the current image cannot just be written to a USB stick

| Gap | Evidence |
|---|---|
| Not a bootable disk | `build/sel4/loader.img` is passed to QEMU as `-initrd` with `sel4_32.elf` as `-kernel` (`tools/run-echo.sh`). No bootloader, no partition table. |
| Only NIC driver for x86 is virtio | sDDF network drivers: dwmac, genet, imx, meson, virtio, zynqmp-gem. No Intel, Realtek or Broadcom driver. |
| Hardware addresses are QEMU's | `sel4/meta_proofgate.py` hard-codes virtio BAR at `0xFE000000`, DMA rings at `0x7A000000`, IOAPIC pin 11, serial port `0x3F8`. The driver looks for PCI bus 0, device 2, function 0. |
| Debug console is COM1 only | Many current PCs have no COM port. |
| CPU features assumed | QEMU is started with `fsgsbase, pdpe1gb, xsave, xsaveopt, rdrand`. |

Good news: `sel4_32.elf` contains both Multiboot 1 and Multiboot 2 headers, so GRUB can load it.
x86_64 has `RDRAND`, so the entropy problem of the aarch64 port does not apply.
sdfgen supports `IrqMsi` and `IrqIoapic`, and sDDF has `pc99` serial and `tsc_hpet` timer drivers.

## Phases

1. **Pick the machine (decide first).** Desktop or mini-PC with Intel I210 or I350 (igb) NIC, a real or PCIe COM port,
   HPET, VT-d, UEFI with legacy/CSM option. Avoid Realtek-only boards, laptops and Wi-Fi-only machines.
2. **Prove the boot path in QEMU, no new driver.** Build a GRUB disk image (`multiboot2 sel4_32.elf`, `module2 loader.img`)
   and boot it from a virtual disk under both SeaBIOS and OVMF (UEFI) without `-kernel`. Acceptance: `SEL4_001..006`.
   Reason: seL4 users report GRUB on UEFI placing the module where the kernel does not expect it.
3. **Collect real facts with a Linux live USB** on the target: `lspci -vvnn`, `/proc/iomem`, `dmesg | grep -i -E 'hpet|tsc'`,
   ACPI tables (`acpidump`), serial ports. Output decides BAR addresses, IRQ or MSI, RAM layout, DMA ring address.
4. **Parametrise the generator.** Move the hard-coded values in `meta_proofgate.py` into a per-machine profile file.
   Use MSI where the NIC supports it instead of a fixed IOAPIC pin. Rings must live in RAM that really exists there.
5. **Write an Intel NIC driver for sDDF (largest item).** Target igb (I210/I350). Recent QEMU emulates `igb`, so development
   and tests run in QEMU first. Needs: PCI BAR map, descriptor rings in physically contiguous DMA memory, link and MAC setup,
   interrupts, no offloads at first. Check upstream sDDF before starting, because I could not confirm whether one is in progress.
6. **Platform bring-up on the real machine.** Serial first (debug kernel prints on COM1; use a PCIe serial card or
   AMT/IPMI serial-over-LAN if absent). Timer: HPET legacy routing plus TSC frequency detection; the driver falls back to a
   much slower HPET-only path if TSC detection fails.
7. **USB media and bring-up.** `grub-install` for the chosen firmware mode, FAT partition with kernel and `loader.img`.
   Fallback when GRUB misbehaves: PXE, which the seL4 documentation names as the usual method.
8. **Re-run `SEL4_001..006` against the real NIC** from another machine on the LAN, then repeat the Kani/Viper audit steps unchanged.

## Security issue to decide before calling it "verified"

Without an IOMMU, a DMA-capable NIC can read and write all RAM, including the TLS key held by `tls_pd`. This bypasses the
capability isolation the project claims (LAW_008, LAW_012). QEMU hides this. The kernel image contains VT-d code
(`acpi_dmar_scan`), but I found no way to grant IO page tables to a PD through the Microkit system description, so IOMMU
protection is **unverified and probably not available today**. Either document the NIC as inside the trusted base on bare
metal (add to `docs/SECURITY.md`) or invest in seL4/Microkit IOMMU work.

## Rough effort (my estimate, not measured)

| Item | Size |
|---|---|
| GRUB boot image + QEMU UEFI/BIOS tests | days |
| Hardware profile + generator changes | days |
| Intel igb sDDF driver | weeks |
| Real-machine bring-up (serial, IRQ, timer) | days to weeks, highest uncertainty |
| IOMMU isolation | open research/engineering |

## Cheaper alternatives

* Run the existing image under KVM or another hypervisor with virtio-net: no new work, but not bare metal.
* Raspberry Pi 4: sDDF already has the Ethernet driver (`genet`), but the aarch64 build needs an entropy driver first (`docs/AARCH64.md`).
