/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * ENA (AWS Elastic Network Adapter) driver for seL4 Microkit / sDDF.
 * mtabe19/qedos fork, Stage E (docs/STAGE_E_EC2.md 5-5).
 *
 * Step M5-1: find the ENA on PCI, reset it, bring up the admin queue in polling mode and print the
 * device attributes (MAC address, MTU, queue limits).
 * Step M5-2: one TX and one RX queue (descriptors in host memory, one descriptor per packet), connected
 * to the sDDF net virtualisers.
 * Step M5-3: MSI-X. Microkit allows one MSI per PCI device, so MSI-X entries 0 (management), 1 (TX CQ)
 * and 2 (RX CQ) all get the same address/data and arrive as one IRQ (channel ENA_IRQ_CH). A periodic
 * timeout (POLL_INTERVAL_NS) remains as a fallback and for the statistics.
 *
 * Register layout and admin command formats come from ena_defs/ (Amazon, BSD-3-Clause, see
 * ena_defs/README.md). The init sequence follows ena_com.c of the same source: ena_com_dev_reset(),
 * ena_com_validate_version(), ena_com_admin_init() and ena_com_get_feature_ex().
 *
 * Machine profile (sel4/meta_proofgate.py --profile ec2-t3):
 *   - PCI 00:05.0, configuration space through I/O ports 0xCF8 (id 1) / 0xCFC (id 2)
 *   - BAR0 (16 KiB at 0xfebf4000 with legacy BIOS boot) mapped uncached at ENA_BAR0_VADDR
 *   - DMA memory "hw_net_rings" (64 KiB at paddr 0x7A000000) mapped at ENA_DMA_VADDR
 *   - timer client (timeouts during bring-up, fallback polling, statistics)
 *   - MSI IRQ: pcidev 00:05.0, vector ENA_MSI_VECTOR, channel ENA_IRQ_CH
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <os/sddf.h>
#include <sddf/network/queue.h>
#include <sddf/network/config.h>
#include <sddf/resources/device.h>
#include <sddf/timer/client.h>
#include <sddf/timer/config.h>
#include <sddf/util/fence.h>
#include <sddf/util/printf.h>
#include <sddf/util/util.h>

/* ena_defs/ expects these from the platform layer (same definitions as ena_plat.h of the reference) */
#ifndef GENMASK
#define GENMASK(h, l) (((~0U) - (1U << (l)) + 1) & (~0U >> (32 - 1 - (h))))
#endif
#include "ena_defs/ena_includes.h"

__attribute__((__section__(".device_resources"), used)) device_resources_t device_resources;
__attribute__((__section__(".net_driver_config"))) net_driver_config_t config;
__attribute__((__section__(".timer_client_config"))) timer_client_config_t timer_config;

#define LOG_ENA(...) do{ sddf_printf("ENA|INFO: "); sddf_printf(__VA_ARGS__); }while(0)
#define LOG_ENA_ERR(...) do{ sddf_printf("ENA|ERROR: "); sddf_printf(__VA_ARGS__); }while(0)

/* ---- machine profile (must match sel4/meta_proofgate.py, profile ec2-t3) ---- */
#define ENA_PCI_BUS 0
#define ENA_PCI_DEV 5
#define ENA_PCI_FUNC 0
#define ENA_BAR0_PADDR 0xFEBF4000UL /* EC2 t3, legacy BIOS (SeaBIOS) boot; 0xc0400000 under UEFI */
#define ENA_BAR0_VADDR 0x60000000UL
#define ENA_DMA_VADDR 0x70000000UL
#define ENA_DMA_PADDR 0x7A000000UL
#define ENA_DMA_SIZE 0x10000UL

#define PCI_IOPORT_ADDR_ID 1
#define PCI_IOPORT_ADDR 0xCF8
#define PCI_IOPORT_DATA_ID 2
#define PCI_IOPORT_DATA 0xCFC

#define AMAZON_VENDOR_ID 0x1d0f
#define ENA_DEVICE_ID_PF 0xec20
#define ENA_DEVICE_ID_PF_RSERV0 0xec21

/* PCI revision bit 0: the device does not support readless register reads (ena.h of the reference) */
#define ENA_MMIO_DISABLE_REG_READ 0x1

/* ---- DMA memory layout inside hw_net_rings ---- */
#define ENA_ADMIN_QUEUE_DEPTH 32
#define ENA_ASYNC_QUEUE_DEPTH 16
#define DMA_OFF_AQ 0x0000      /* 32 * 64 B */
#define DMA_OFF_ACQ 0x0800     /* 32 * 64 B */
#define DMA_OFF_AENQ 0x1000    /* 16 * 64 B */
#define DMA_OFF_MMIO_RESP 0x1400
#define DMA_OFF_HOST_INFO 0x2000 /* struct ena_admin_host_info */
#define DMA_OFF_TX_SQ 0x3000     /* IO_QUEUE_DEPTH * 16 B */
#define DMA_OFF_TX_CQ 0x4000     /* IO_QUEUE_DEPTH * 8 B */
#define DMA_OFF_RX_SQ 0x5000     /* IO_QUEUE_DEPTH * 16 B */
#define DMA_OFF_RX_CQ 0x6000     /* IO_QUEUE_DEPTH * 16 B */

/* ---- I/O queues (M5-2) ---- */
#define IO_QUEUE_DEPTH 256 /* power of two, device limit 1024 */
#define ENA_MTU 1500       /* sDDF buffers are NET_BUFFER_SIZE (2048) bytes */
#define POLL_INTERVAL_NS (100ULL * NS_IN_MS) /* fallback only (M5-3); 1 ms polling in M5-2 */
#define STATS_INTERVAL_NS (5ULL * NS_IN_S)
#define TRACE_FRAMES 6 /* print the first frames in each direction */
/* ena_admin_host_info.os_type: there is no value for seL4; use the one of the FreeBSD driver this one
 * follows (ENA_ADMIN_OS_FREEBSD in ena_plat.h of the reference) */
#define QEDOS_ENA_OS_TYPE 4
#define QEDOS_ENA_DRIVER_VERSION 0x000301 /* 1.3.0 (major | minor << 8 | sub_minor << 16) */

/* ---- MSI-X (M5-3), must match sel4/meta_proofgate.py, profile ec2-t3 ---- */
#define ENA_IRQ_CH 16
#define ENA_MSI_VECTOR 106
/* seL4 delivers Microkit/seL4 MSI vector v at CPU vector v + 0x30 (IRQ_INT_OFFSET 0x20 + 16 PIC lines,
 * include/plat/pc99/plat/machine.h of the seL4 used by Microkit 2.3.0) */
#define SEL4_X86_MSI_CPU_VECTOR(v) ((v) + 0x30)
#define MSI_ADDR_APIC0 0xFEE00000u /* fixed destination: local APIC ID 0 (the only CPU in use) */
#define MSIX_ENTRY_MGMT 0
#define MSIX_ENTRY_TX 1
#define MSIX_ENTRY_RX 2
#define MSIX_ENTRIES_USED 3
#define PCI_CAP_ID_MSIX 0x11

#define MMIO_READ_TIMEOUT_NS (10ULL * NS_IN_MS)
#define REG_READ_FAILED 0xFFFFFFFFu
#define DEFAULT_ADMIN_TIMEOUT_NS (3ULL * NS_IN_S)

/* Minimal controller version (ena_com.c of the reference: 0.0.1) */
#define MIN_ENA_CTRL_VER 0x000001

_Static_assert(sizeof(struct ena_admin_aq_entry) == 64, "AQ entry must be 64 bytes");
_Static_assert(sizeof(struct ena_admin_acq_entry) == 64, "ACQ entry must be 64 bytes");
_Static_assert(sizeof(struct ena_admin_aenq_entry) == 64, "AENQ entry must be 64 bytes");
_Static_assert(ENA_ADMIN_QUEUE_DEPTH * 64 <= DMA_OFF_ACQ - DMA_OFF_AQ, "AQ does not fit");
_Static_assert(ENA_ADMIN_QUEUE_DEPTH * 64 <= DMA_OFF_AENQ - DMA_OFF_ACQ, "ACQ does not fit");
_Static_assert(ENA_ASYNC_QUEUE_DEPTH * 64 <= DMA_OFF_MMIO_RESP - DMA_OFF_AENQ, "AENQ does not fit");
_Static_assert(sizeof(struct ena_admin_host_info) <= DMA_OFF_TX_SQ - DMA_OFF_HOST_INFO, "host info does not fit");
_Static_assert(sizeof(struct ena_eth_io_tx_desc) == 16, "TX descriptor size");
_Static_assert(sizeof(struct ena_eth_io_tx_cdesc) == 8, "TX completion size");
_Static_assert(sizeof(struct ena_eth_io_rx_desc) == 16, "RX descriptor size");
_Static_assert(sizeof(struct ena_eth_io_rx_cdesc_base) == 16, "RX completion size");
_Static_assert(IO_QUEUE_DEPTH * 16 <= DMA_OFF_TX_CQ - DMA_OFF_TX_SQ, "TX SQ does not fit");
_Static_assert(IO_QUEUE_DEPTH * 8 <= DMA_OFF_RX_SQ - DMA_OFF_TX_CQ, "TX CQ does not fit");
_Static_assert(IO_QUEUE_DEPTH * 16 <= DMA_OFF_RX_CQ - DMA_OFF_RX_SQ, "RX SQ does not fit");
_Static_assert(DMA_OFF_RX_CQ + IO_QUEUE_DEPTH * 16 <= ENA_DMA_SIZE, "RX CQ does not fit");
_Static_assert((IO_QUEUE_DEPTH & (IO_QUEUE_DEPTH - 1)) == 0, "queue depth must be a power of two");

static volatile uint8_t *const bar0 = (volatile uint8_t *)ENA_BAR0_VADDR;

static struct {
    bool readless;
    uint16_t mmio_seq;
    volatile struct ena_admin_ena_mmio_req_read_less_resp *mmio_resp;

    volatile struct ena_admin_aq_entry *aq;
    volatile struct ena_admin_acq_entry *acq;
    uint16_t aq_tail;
    uint8_t aq_phase;
    uint16_t acq_head;
    uint8_t acq_phase;
    uint16_t cmd_id;
    uint64_t admin_timeout_ns;

    uint32_t supported_features;
    uint8_t mac[6];
    bool ready;

    uint16_t aenq_head;
    uint8_t aenq_phase;
} ena;

/* One I/O queue pair (SQ + CQ). req_id identifies the sDDF buffer of a descriptor; free req_ids are
 * kept on a stack because completions need not come back in order. */
typedef struct io_queue {
    volatile void *sq;
    volatile void *cq;
    volatile uint32_t *db;
    volatile uint32_t *unmask;
    uint16_t sq_idx;
    uint16_t cq_idx;
    uint16_t sq_tail;
    uint8_t sq_phase;
    uint16_t cq_head;
    uint8_t cq_phase;
    uint16_t inflight;
    net_buff_desc_t buf[IO_QUEUE_DEPTH];
    uint16_t free_ids[IO_QUEUE_DEPTH];
    uint16_t num_free_ids;
} io_queue_t;

static io_queue_t txq;
static io_queue_t rxq;
net_queue_handle_t rx_queue;
net_queue_handle_t tx_queue;

static struct {
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errs;
    uint64_t aenq_events;
    uint64_t irqs;
    uint64_t fallback_hits; /* completions found by the fallback poll, i.e. without an interrupt */
    uint64_t next_print_ns;
} stats;

static inline uintptr_t dma_paddr(uintptr_t off)
{
    return ENA_DMA_PADDR + off;
}

static inline void *dma_vaddr(uintptr_t off)
{
    return (void *)(ENA_DMA_VADDR + off);
}

static inline uint64_t now_ns(void)
{
    return sddf_timer_time_now(timer_config.driver_id);
}

/* ---- PCI configuration space (mechanism #1) ---- */

static uint32_t pci_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off)
{
    uint32_t addr = 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)func << 8) | (off & 0xfc);
    microkit_x86_ioport_write_32(PCI_IOPORT_ADDR_ID, PCI_IOPORT_ADDR, addr);
    return microkit_x86_ioport_read_32(PCI_IOPORT_DATA_ID, PCI_IOPORT_DATA);
}

static void pci_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off, uint32_t val)
{
    uint32_t addr = 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) | ((uint32_t)func << 8) | (off & 0xfc);
    microkit_x86_ioport_write_32(PCI_IOPORT_ADDR_ID, PCI_IOPORT_ADDR, addr);
    microkit_x86_ioport_write_32(PCI_IOPORT_DATA_ID, PCI_IOPORT_DATA, val);
}

/* ---- register access ---- */

static inline void reg_write32(uint16_t off, uint32_t val)
{
    /* make earlier writes to DMA memory visible before the device is told about them */
    THREAD_MEMORY_FENCE();
    *(volatile uint32_t *)(bar0 + off) = val;
}

/* Register read, readless (the device writes the value to host memory) or direct, like
 * ena_com_reg_bar_read32() of the reference. Returns REG_READ_FAILED on timeout. */
static uint32_t reg_read32(uint16_t off)
{
    if (!ena.readless) {
        return *(volatile uint32_t *)(bar0 + off);
    }

    ena.mmio_seq++;
    ena.mmio_resp->req_id = ena.mmio_seq + 0xDEAD;
    uint32_t req = ((uint32_t)off << ENA_REGS_MMIO_REG_READ_REG_OFF_SHIFT) & ENA_REGS_MMIO_REG_READ_REG_OFF_MASK;
    req |= ena.mmio_seq & ENA_REGS_MMIO_REG_READ_REQ_ID_MASK;
    reg_write32(ENA_REGS_MMIO_REG_READ_OFF, req);

    uint64_t deadline = now_ns() + MMIO_READ_TIMEOUT_NS;
    while (ena.mmio_resp->req_id != ena.mmio_seq) {
        if (now_ns() > deadline) {
            LOG_ENA_ERR("register read timed out (offset 0x%x)\n", off);
            return REG_READ_FAILED;
        }
    }
    THREAD_MEMORY_ACQUIRE();
    if (ena.mmio_resp->reg_off != off) {
        LOG_ENA_ERR("register read returned offset 0x%x, expected 0x%x\n", ena.mmio_resp->reg_off, off);
        return REG_READ_FAILED;
    }
    return ena.mmio_resp->reg_val;
}

static void write_mmio_resp_addr(void)
{
    reg_write32(ENA_REGS_MMIO_RESP_LO_OFF, (uint32_t)dma_paddr(DMA_OFF_MMIO_RESP));
    reg_write32(ENA_REGS_MMIO_RESP_HI_OFF, (uint32_t)((uint64_t)dma_paddr(DMA_OFF_MMIO_RESP) >> 32));
}

/* ---- device bring-up ---- */

static bool pci_probe(void)
{
    uint32_t id = pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, 0x00);
    uint16_t vendor = id & 0xffff;
    uint16_t device = id >> 16;
    if (vendor != AMAZON_VENDOR_ID || (device != ENA_DEVICE_ID_PF && device != ENA_DEVICE_ID_PF_RSERV0)) {
        LOG_ENA_ERR("no ENA at PCI %02x:%02x.%x (id %04x:%04x)\n", ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, vendor,
                    device);
        return false;
    }
    uint8_t revision = pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, 0x08) & 0xff;
    uint32_t bar0_cfg = pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, 0x10);
    uint32_t cmd_sts = pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, 0x04);
    LOG_ENA("PCI %02x:%02x.%x %04x:%04x rev 0x%x, BAR0 0x%x, command 0x%x\n", ENA_PCI_BUS, ENA_PCI_DEV,
            ENA_PCI_FUNC, vendor, device, revision, bar0_cfg, cmd_sts & 0xffff);

    if ((bar0_cfg & ~0xfu) != ENA_BAR0_PADDR) {
        LOG_ENA_ERR("BAR0 is 0x%x, the system description maps 0x%lx (update the ec2-t3 profile)\n",
                    bar0_cfg & ~0xfu, ENA_BAR0_PADDR);
        return false;
    }

    /* memory space + bus master; keep INTx disabled (bit 10) */
    uint16_t cmd = (cmd_sts & 0xffff) | (1u << 1) | (1u << 2) | (1u << 10);
    if (cmd != (cmd_sts & 0xffff)) {
        pci_write32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, 0x04, cmd);
    }

    ena.readless = !(revision & ENA_MMIO_DISABLE_REG_READ);
    return true;
}

static bool wait_dev_sts(uint32_t mask, uint32_t expect, uint64_t timeout_ns, const char *what)
{
    uint64_t deadline = now_ns() + timeout_ns;
    for (;;) {
        uint32_t sts = reg_read32(ENA_REGS_DEV_STS_OFF);
        if (sts == REG_READ_FAILED) {
            return false;
        }
        if ((sts & mask) == expect) {
            return true;
        }
        if (now_ns() > deadline) {
            LOG_ENA_ERR("timeout waiting for %s (dev_sts 0x%x)\n", what, sts);
            return false;
        }
    }
}

static bool dev_reset(void)
{
    uint32_t sts = reg_read32(ENA_REGS_DEV_STS_OFF);
    uint32_t caps = reg_read32(ENA_REGS_CAPS_OFF);
    if (sts == REG_READ_FAILED || caps == REG_READ_FAILED) {
        return false;
    }
    LOG_ENA("dev_sts 0x%x, caps 0x%x (DMA width %u, reset timeout %u x 100 ms, admin timeout %u x 100 ms)\n", sts,
            caps, (caps & ENA_REGS_CAPS_DMA_ADDR_WIDTH_MASK) >> ENA_REGS_CAPS_DMA_ADDR_WIDTH_SHIFT,
            (caps & ENA_REGS_CAPS_RESET_TIMEOUT_MASK) >> ENA_REGS_CAPS_RESET_TIMEOUT_SHIFT,
            (caps & ENA_REGS_CAPS_ADMIN_CMD_TO_MASK) >> ENA_REGS_CAPS_ADMIN_CMD_TO_SHIFT);
    if (!(sts & ENA_REGS_DEV_STS_READY_MASK)) {
        LOG_ENA_ERR("device is not ready\n");
        return false;
    }
    uint32_t timeout = (caps & ENA_REGS_CAPS_RESET_TIMEOUT_MASK) >> ENA_REGS_CAPS_RESET_TIMEOUT_SHIFT;
    if (timeout == 0) {
        LOG_ENA_ERR("invalid reset timeout\n");
        return false;
    }
    uint64_t timeout_ns = (uint64_t)timeout * 100 * NS_IN_MS;

    /* reset reason ENA_REGS_RESET_NORMAL (0) */
    reg_write32(ENA_REGS_DEV_CTL_OFF, ENA_REGS_DEV_CTL_DEV_RESET_MASK);
    write_mmio_resp_addr();
    if (!wait_dev_sts(ENA_REGS_DEV_STS_RESET_IN_PROGRESS_MASK, ENA_REGS_DEV_STS_RESET_IN_PROGRESS_MASK, timeout_ns,
                      "reset to start")) {
        return false;
    }
    reg_write32(ENA_REGS_DEV_CTL_OFF, 0);
    if (!wait_dev_sts(ENA_REGS_DEV_STS_RESET_IN_PROGRESS_MASK, 0, timeout_ns, "reset to finish")) {
        return false;
    }

    uint32_t admin_to = (caps & ENA_REGS_CAPS_ADMIN_CMD_TO_MASK) >> ENA_REGS_CAPS_ADMIN_CMD_TO_SHIFT;
    ena.admin_timeout_ns = admin_to ? (uint64_t)admin_to * 100 * NS_IN_MS : DEFAULT_ADMIN_TIMEOUT_NS;
    return true;
}

static bool validate_version(void)
{
    uint32_t ver = reg_read32(ENA_REGS_VERSION_OFF);
    uint32_t ctrl = reg_read32(ENA_REGS_CONTROLLER_VERSION_OFF);
    if (ver == REG_READ_FAILED || ctrl == REG_READ_FAILED) {
        return false;
    }
    LOG_ENA("device version %u.%u, controller version %u.%u.%u (implementation %u)\n",
            (ver & ENA_REGS_VERSION_MAJOR_VERSION_MASK) >> ENA_REGS_VERSION_MAJOR_VERSION_SHIFT,
            ver & ENA_REGS_VERSION_MINOR_VERSION_MASK,
            (ctrl & ENA_REGS_CONTROLLER_VERSION_MAJOR_VERSION_MASK) >> ENA_REGS_CONTROLLER_VERSION_MAJOR_VERSION_SHIFT,
            (ctrl & ENA_REGS_CONTROLLER_VERSION_MINOR_VERSION_MASK) >> ENA_REGS_CONTROLLER_VERSION_MINOR_VERSION_SHIFT,
            ctrl & ENA_REGS_CONTROLLER_VERSION_SUBMINOR_VERSION_MASK,
            (ctrl & ENA_REGS_CONTROLLER_VERSION_IMPL_ID_MASK) >> ENA_REGS_CONTROLLER_VERSION_IMPL_ID_SHIFT);
    uint32_t masked = ctrl & (ENA_REGS_CONTROLLER_VERSION_MAJOR_VERSION_MASK | ENA_REGS_CONTROLLER_VERSION_MINOR_VERSION_MASK
                              | ENA_REGS_CONTROLLER_VERSION_SUBMINOR_VERSION_MASK);
    if (masked < MIN_ENA_CTRL_VER) {
        LOG_ENA_ERR("controller version is too old\n");
        return false;
    }
    return true;
}

static bool admin_init(void)
{
    uint32_t sts = reg_read32(ENA_REGS_DEV_STS_OFF);
    if (sts == REG_READ_FAILED || !(sts & ENA_REGS_DEV_STS_READY_MASK)) {
        LOG_ENA_ERR("device is not ready for admin init (dev_sts 0x%x)\n", sts);
        return false;
    }

    ena.aq = dma_vaddr(DMA_OFF_AQ);
    ena.acq = dma_vaddr(DMA_OFF_ACQ);
    memset(dma_vaddr(DMA_OFF_AQ), 0, ENA_ADMIN_QUEUE_DEPTH * sizeof(struct ena_admin_aq_entry));
    memset(dma_vaddr(DMA_OFF_ACQ), 0, ENA_ADMIN_QUEUE_DEPTH * sizeof(struct ena_admin_acq_entry));
    memset(dma_vaddr(DMA_OFF_AENQ), 0, ENA_ASYNC_QUEUE_DEPTH * sizeof(struct ena_admin_aenq_entry));
    ena.aq_tail = 0;
    ena.aq_phase = 1;
    ena.acq_head = 0;
    ena.acq_phase = 1;
    ena.cmd_id = 0;

    reg_write32(ENA_REGS_AQ_BASE_LO_OFF, (uint32_t)dma_paddr(DMA_OFF_AQ));
    reg_write32(ENA_REGS_AQ_BASE_HI_OFF, (uint32_t)((uint64_t)dma_paddr(DMA_OFF_AQ) >> 32));
    reg_write32(ENA_REGS_ACQ_BASE_LO_OFF, (uint32_t)dma_paddr(DMA_OFF_ACQ));
    reg_write32(ENA_REGS_ACQ_BASE_HI_OFF, (uint32_t)((uint64_t)dma_paddr(DMA_OFF_ACQ) >> 32));

    uint32_t aq_caps = (ENA_ADMIN_QUEUE_DEPTH & ENA_REGS_AQ_CAPS_AQ_DEPTH_MASK)
                     | ((sizeof(struct ena_admin_aq_entry) << ENA_REGS_AQ_CAPS_AQ_ENTRY_SIZE_SHIFT)
                        & ENA_REGS_AQ_CAPS_AQ_ENTRY_SIZE_MASK);
    uint32_t acq_caps = (ENA_ADMIN_QUEUE_DEPTH & ENA_REGS_ACQ_CAPS_ACQ_DEPTH_MASK)
                      | ((sizeof(struct ena_admin_acq_entry) << ENA_REGS_ACQ_CAPS_ACQ_ENTRY_SIZE_SHIFT)
                         & ENA_REGS_ACQ_CAPS_ACQ_ENTRY_SIZE_MASK);
    reg_write32(ENA_REGS_AQ_CAPS_OFF, aq_caps);
    reg_write32(ENA_REGS_ACQ_CAPS_OFF, acq_caps);

    /* asynchronous event notification queue */
    reg_write32(ENA_REGS_AENQ_BASE_LO_OFF, (uint32_t)dma_paddr(DMA_OFF_AENQ));
    reg_write32(ENA_REGS_AENQ_BASE_HI_OFF, (uint32_t)((uint64_t)dma_paddr(DMA_OFF_AENQ) >> 32));
    uint32_t aenq_caps = (ENA_ASYNC_QUEUE_DEPTH & ENA_REGS_AENQ_CAPS_AENQ_DEPTH_MASK)
                       | ((sizeof(struct ena_admin_aenq_entry) << ENA_REGS_AENQ_CAPS_AENQ_ENTRY_SIZE_SHIFT)
                          & ENA_REGS_AENQ_CAPS_AENQ_ENTRY_SIZE_MASK);
    reg_write32(ENA_REGS_AENQ_CAPS_OFF, aenq_caps);
    /* all AENQ entries are available to the device (ena_com_admin_aenq_enable) */
    reg_write32(ENA_REGS_AENQ_HEAD_DB_OFF, ENA_ASYNC_QUEUE_DEPTH);
    return true;
}

/* Submit one admin command and poll for its completion (admin queue polling mode). */
static int admin_exec(struct ena_admin_aq_entry *cmd, struct ena_admin_acq_entry *comp)
{
    uint16_t mask = ENA_ADMIN_QUEUE_DEPTH - 1;
    uint16_t cmd_id = ena.cmd_id;

    cmd->aq_common_descriptor.flags |= ena.aq_phase & ENA_ADMIN_AQ_COMMON_DESC_PHASE_MASK;
    cmd->aq_common_descriptor.command_id |= cmd_id & ENA_ADMIN_AQ_COMMON_DESC_COMMAND_ID_MASK;
    memcpy((void *)&ena.aq[ena.aq_tail & mask], cmd, sizeof(*cmd));
    ena.cmd_id = (ena.cmd_id + 1) & mask;
    ena.aq_tail++;
    if ((ena.aq_tail & mask) == 0) {
        ena.aq_phase = !ena.aq_phase;
    }
    reg_write32(ENA_REGS_AQ_DB_OFF, ena.aq_tail);

    volatile struct ena_admin_acq_entry *cqe = &ena.acq[ena.acq_head & mask];
    uint64_t deadline = now_ns() + ena.admin_timeout_ns;
    while ((cqe->acq_common_descriptor.flags & ENA_ADMIN_ACQ_COMMON_DESC_PHASE_MASK) != ena.acq_phase) {
        if (now_ns() > deadline) {
            LOG_ENA_ERR("admin command (opcode %u) timed out\n", cmd->aq_common_descriptor.opcode);
            return -1;
        }
    }
    THREAD_MEMORY_ACQUIRE();
    memcpy(comp, (const void *)cqe, sizeof(*comp));
    ena.acq_head++;
    if ((ena.acq_head & mask) == 0) {
        ena.acq_phase = !ena.acq_phase;
    }

    uint16_t done_id = comp->acq_common_descriptor.command & ENA_ADMIN_ACQ_COMMON_DESC_COMMAND_ID_MASK;
    if (done_id != cmd_id) {
        LOG_ENA_ERR("admin completion for command %u, expected %u\n", done_id, cmd_id);
        return -1;
    }
    if (comp->acq_common_descriptor.status != ENA_ADMIN_SUCCESS) {
        LOG_ENA_ERR("admin command (opcode %u) failed, status %u\n", cmd->aq_common_descriptor.opcode,
                    comp->acq_common_descriptor.status);
        return -1;
    }
    return 0;
}

static int get_feature(enum ena_admin_aq_feature_id id, uint8_t version, struct ena_admin_get_feat_resp *resp)
{
    struct ena_admin_get_feat_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    memset(resp, 0, sizeof(*resp));
    cmd.aq_common_descriptor.opcode = ENA_ADMIN_GET_FEATURE;
    cmd.feat_common.feature_id = id;
    cmd.feat_common.feature_version = version;
    _Static_assert(sizeof(cmd) == sizeof(struct ena_admin_aq_entry), "get feature command size");
    _Static_assert(sizeof(*resp) == sizeof(struct ena_admin_acq_entry), "get feature response size");
    return admin_exec((struct ena_admin_aq_entry *)&cmd, (struct ena_admin_acq_entry *)resp);
}

static bool read_device_info(void)
{
    struct ena_admin_get_feat_resp resp;
    if (get_feature(ENA_ADMIN_DEVICE_ATTRIBUTES, 0, &resp)) {
        return false;
    }
    struct ena_admin_device_attr_feature_desc *attr = &resp.u.dev_attr;
    memcpy(ena.mac, attr->mac_addr, 6);
    ena.supported_features = attr->supported_features;
    LOG_ENA("MAC %02x:%02x:%02x:%02x:%02x:%02x, max MTU %u\n", attr->mac_addr[0], attr->mac_addr[1],
            attr->mac_addr[2], attr->mac_addr[3], attr->mac_addr[4], attr->mac_addr[5], attr->max_mtu);
    LOG_ENA("impl_id %u, device_version 0x%x, supported_features 0x%x, capabilities 0x%x, phys/virt addr width %u/%u\n",
            attr->impl_id, attr->device_version, attr->supported_features, attr->capabilities,
            attr->phys_addr_width, attr->virt_addr_width);

    if (ena.supported_features & BIT(ENA_ADMIN_MAX_QUEUES_EXT)) {
        if (get_feature(ENA_ADMIN_MAX_QUEUES_EXT, 1 /* ENA_FEATURE_MAX_QUEUE_EXT_VER */, &resp)) {
            return false;
        }
        struct ena_admin_queue_ext_feature_fields *q = &resp.u.max_queue_ext.max_queue_ext;
        LOG_ENA("queues (ext v%u): tx sq/cq %u/%u depth %u/%u, rx sq/cq %u/%u depth %u/%u, max tx header %u, "
                "descs per packet tx/rx %u/%u\n", resp.u.max_queue_ext.version, q->max_tx_sq_num, q->max_tx_cq_num,
                q->max_tx_sq_depth, q->max_tx_cq_depth, q->max_rx_sq_num, q->max_rx_cq_num, q->max_rx_sq_depth,
                q->max_rx_cq_depth, q->max_tx_header_size, q->max_per_packet_tx_descs, q->max_per_packet_rx_descs);
    } else {
        if (get_feature(ENA_ADMIN_MAX_QUEUES_NUM, 0, &resp)) {
            return false;
        }
        struct ena_admin_queue_feature_desc *q = &resp.u.max_queue;
        LOG_ENA("queues: sq %u depth %u, cq %u depth %u, max header %u\n", q->max_sq_num, q->max_sq_depth,
                q->max_cq_num, q->max_cq_depth, q->max_header_size);
    }
    return true;
}

/* ---- M5-2: host info, MTU, I/O queues and the polled data path ---- */

static uint8_t pci_read8(uint8_t off)
{
    return (pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, off) >> ((off & 3) * 8)) & 0xff;
}

static uint16_t pci_read16(uint8_t off)
{
    return (pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, off) >> ((off & 2) * 8)) & 0xffff;
}

/* Find the MSI-X capability, point entries 0..MSIX_ENTRIES_USED-1 at our vector and enable MSI-X. */
static bool msix_setup(void)
{
    uint8_t cap = 0;
    uint16_t status = pci_read16(0x06);
    if (status & (1u << 4)) {
        uint8_t ptr = pci_read8(0x34) & 0xfc;
        for (int guard = 0; ptr && guard < 48; guard++) {
            if (pci_read8(ptr) == PCI_CAP_ID_MSIX) {
                cap = ptr;
                break;
            }
            ptr = pci_read8(ptr + 1) & 0xfc;
        }
    }
    if (!cap) {
        LOG_ENA_ERR("no MSI-X capability\n");
        return false;
    }
    uint32_t dw0 = pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, cap);
    uint16_t msg_ctrl = dw0 >> 16;
    uint32_t table = pci_read32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, cap + 4);
    uint16_t table_size = (msg_ctrl & 0x7ff) + 1;
    uint32_t table_off = table & ~7u;
    LOG_ENA("MSI-X capability at 0x%x: %u entries, table BAR%u+0x%x, control 0x%x\n", cap, table_size, table & 7,
            table_off, msg_ctrl);
    if ((table & 7) != 0 || table_off + table_size * 16 > 0x4000 || table_size < MSIX_ENTRIES_USED) {
        LOG_ENA_ERR("unexpected MSI-X table location or size\n");
        return false;
    }

    /* function mask while the table is written */
    pci_write32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, cap, (dw0 & 0xffff) | ((uint32_t)(msg_ctrl | (1u << 14)) << 16));
    uint32_t data = SEL4_X86_MSI_CPU_VECTOR(ENA_MSI_VECTOR); /* fixed delivery, edge */
    for (int i = 0; i < MSIX_ENTRIES_USED; i++) {
        volatile uint32_t *e = (volatile uint32_t *)(bar0 + table_off + i * 16);
        e[0] = MSI_ADDR_APIC0;
        e[1] = 0;
        e[2] = data;
        e[3] = 0; /* vector control: unmasked */
    }
    /* enable MSI-X, clear the function mask */
    msg_ctrl = (msg_ctrl | (1u << 15)) & ~(1u << 14);
    pci_write32(ENA_PCI_BUS, ENA_PCI_DEV, ENA_PCI_FUNC, cap, (dw0 & 0xffff) | ((uint32_t)msg_ctrl << 16));
    LOG_ENA("MSI-X entries 0..%u -> address 0x%x data 0x%x (seL4 vector %u), control 0x%x\n", MSIX_ENTRIES_USED - 1,
            MSI_ADDR_APIC0, data, ENA_MSI_VECTOR, pci_read16(cap + 2));
    return true;
}

static void set_mem_addr(struct ena_common_mem_addr *a, uint64_t paddr)
{
    a->mem_addr_low = (uint32_t)paddr;
    a->mem_addr_high = (uint16_t)(paddr >> 32);
}

static int set_feature(enum ena_admin_aq_feature_id id, struct ena_admin_set_feat_cmd *cmd)
{
    struct ena_admin_set_feat_resp resp;
    if (!(ena.supported_features & BIT(id))) {
        LOG_ENA_ERR("feature %u is not supported by the device\n", id);
        return -1;
    }
    cmd->aq_common_descriptor.opcode = ENA_ADMIN_SET_FEATURE;
    cmd->feat_common.feature_id = id;
    _Static_assert(sizeof(*cmd) == sizeof(struct ena_admin_aq_entry), "set feature command size");
    _Static_assert(sizeof(resp) == sizeof(struct ena_admin_acq_entry), "set feature response size");
    return admin_exec((struct ena_admin_aq_entry *)cmd, (struct ena_admin_acq_entry *)&resp);
}

static void copy_str(volatile uint8_t *dst, const char *src, size_t size)
{
    size_t i = 0;
    for (; i + 1 < size && src[i]; i++) {
        dst[i] = src[i];
    }
    dst[i] = 0;
}

static bool set_host_info(void)
{
    volatile struct ena_admin_host_info *hi = dma_vaddr(DMA_OFF_HOST_INFO);
    memset((void *)hi, 0, sizeof(*hi));
    hi->os_type = QEDOS_ENA_OS_TYPE;
    copy_str(hi->os_dist_str, "QEDOS (seL4 Microkit 2.3.1)", sizeof(hi->os_dist_str));
    copy_str(hi->kernel_ver_str, "seL4", sizeof(hi->kernel_ver_str));
    hi->driver_version = QEDOS_ENA_DRIVER_VERSION;
    hi->ena_spec_version = (ENA_COMMON_SPEC_VERSION_MAJOR << 8) | ENA_COMMON_SPEC_VERSION_MINOR;
    hi->bdf = (ENA_PCI_BUS << 8) | (ENA_PCI_DEV << 3) | ENA_PCI_FUNC;
    hi->num_cpus = 1;
    /* no rx_offset: received data always starts at the beginning of the buffer */
    hi->driver_supported_features = 0;

    struct ena_admin_set_feat_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    set_mem_addr(&cmd.u.host_attr.os_info_ba, dma_paddr(DMA_OFF_HOST_INFO));
    return set_feature(ENA_ADMIN_HOST_ATTR_CONFIG, &cmd) == 0;
}

static bool set_mtu(uint32_t mtu)
{
    struct ena_admin_set_feat_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.u.mtu.mtu = mtu;
    return set_feature(ENA_ADMIN_MTU, &cmd) == 0;
}

static bool create_queue(io_queue_t *q, bool tx, uintptr_t sq_off, uintptr_t cq_off, uint16_t msix_entry)
{
    uint16_t cdesc_size = tx ? sizeof(struct ena_eth_io_tx_cdesc) : sizeof(struct ena_eth_io_rx_cdesc_base);
    q->sq = dma_vaddr(sq_off);
    q->cq = dma_vaddr(cq_off);
    memset(dma_vaddr(sq_off), 0, IO_QUEUE_DEPTH * 16);
    memset(dma_vaddr(cq_off), 0, IO_QUEUE_DEPTH * cdesc_size);
    q->sq_tail = 0;
    q->sq_phase = 1;
    q->cq_head = 0;
    q->cq_phase = 1;
    q->inflight = 0;
    q->num_free_ids = IO_QUEUE_DEPTH;
    for (uint16_t i = 0; i < IO_QUEUE_DEPTH; i++) {
        q->free_ids[i] = IO_QUEUE_DEPTH - 1 - i;
    }

    /* completion queue first, interrupting on MSI-X entry msix_entry */
    struct ena_admin_aq_create_cq_cmd ccmd;
    struct ena_admin_acq_create_cq_resp_desc cresp;
    memset(&ccmd, 0, sizeof(ccmd));
    ccmd.aq_common_descriptor.opcode = ENA_ADMIN_CREATE_CQ;
    ccmd.cq_caps_1 = ENA_ADMIN_AQ_CREATE_CQ_CMD_INTERRUPT_MODE_ENABLED_MASK;
    ccmd.cq_caps_2 = (cdesc_size / 4) & ENA_ADMIN_AQ_CREATE_CQ_CMD_CQ_ENTRY_SIZE_WORDS_MASK;
    ccmd.cq_depth = IO_QUEUE_DEPTH;
    ccmd.msix_vector = msix_entry;
    set_mem_addr(&ccmd.cq_ba, dma_paddr(cq_off));
    _Static_assert(sizeof(ccmd) <= sizeof(struct ena_admin_aq_entry), "create cq command size");
    _Static_assert(sizeof(cresp) <= sizeof(struct ena_admin_acq_entry), "create cq response size");
    struct ena_admin_aq_entry cmd_entry;
    struct ena_admin_acq_entry comp_entry;
    memset(&cmd_entry, 0, sizeof(cmd_entry));
    memcpy(&cmd_entry, &ccmd, sizeof(ccmd));
    if (admin_exec(&cmd_entry, &comp_entry)) {
        return false;
    }
    memcpy(&cresp, &comp_entry, sizeof(cresp));
    q->cq_idx = cresp.cq_idx;
    if (cresp.cq_actual_depth != IO_QUEUE_DEPTH) {
        LOG_ENA_ERR("%s CQ depth %u, requested %u\n", tx ? "TX" : "RX", cresp.cq_actual_depth, IO_QUEUE_DEPTH);
        return false;
    }
    if (cresp.cq_interrupt_unmask_register_offset == 0 || cresp.cq_interrupt_unmask_register_offset + 4 > 0x4000) {
        LOG_ENA_ERR("%s CQ unmask register offset 0x%x is outside BAR0\n", tx ? "TX" : "RX",
                    cresp.cq_interrupt_unmask_register_offset);
        return false;
    }
    q->unmask = (volatile uint32_t *)(bar0 + cresp.cq_interrupt_unmask_register_offset);

    /* submission queue, descriptors in host memory */
    struct ena_admin_aq_create_sq_cmd scmd;
    struct ena_admin_acq_create_sq_resp_desc sresp;
    memset(&scmd, 0, sizeof(scmd));
    scmd.aq_common_descriptor.opcode = ENA_ADMIN_CREATE_SQ;
    scmd.sq_identity = ((tx ? ENA_ADMIN_SQ_DIRECTION_TX : ENA_ADMIN_SQ_DIRECTION_RX)
                        << ENA_ADMIN_AQ_CREATE_SQ_CMD_SQ_DIRECTION_SHIFT)
                     & ENA_ADMIN_AQ_CREATE_SQ_CMD_SQ_DIRECTION_MASK;
    scmd.sq_caps_2 = (ENA_ADMIN_PLACEMENT_POLICY_HOST & ENA_ADMIN_AQ_CREATE_SQ_CMD_PLACEMENT_POLICY_MASK)
                   | ((ENA_ADMIN_COMPLETION_POLICY_DESC << ENA_ADMIN_AQ_CREATE_SQ_CMD_COMPLETION_POLICY_SHIFT)
                      & ENA_ADMIN_AQ_CREATE_SQ_CMD_COMPLETION_POLICY_MASK);
    scmd.sq_caps_3 = ENA_ADMIN_AQ_CREATE_SQ_CMD_IS_PHYSICALLY_CONTIGUOUS_MASK;
    scmd.cq_idx = q->cq_idx;
    scmd.sq_depth = IO_QUEUE_DEPTH;
    set_mem_addr(&scmd.sq_ba, dma_paddr(sq_off));
    _Static_assert(sizeof(scmd) <= sizeof(struct ena_admin_aq_entry), "create sq command size");
    _Static_assert(sizeof(sresp) <= sizeof(struct ena_admin_acq_entry), "create sq response size");
    memset(&cmd_entry, 0, sizeof(cmd_entry));
    memcpy(&cmd_entry, &scmd, sizeof(scmd));
    if (admin_exec(&cmd_entry, &comp_entry)) {
        return false;
    }
    memcpy(&sresp, &comp_entry, sizeof(sresp));
    q->sq_idx = sresp.sq_idx;
    if (sresp.sq_doorbell_offset == 0 || sresp.sq_doorbell_offset + 4 > 0x4000) {
        LOG_ENA_ERR("%s SQ doorbell offset 0x%x is outside BAR0\n", tx ? "TX" : "RX", sresp.sq_doorbell_offset);
        return false;
    }
    q->db = (volatile uint32_t *)(bar0 + sresp.sq_doorbell_offset);
    LOG_ENA("%s queue: sq %u (doorbell 0x%x), cq %u (unmask 0x%x, MSI-X entry %u), depth %u\n", tx ? "TX" : "RX",
            q->sq_idx, sresp.sq_doorbell_offset, q->cq_idx, cresp.cq_interrupt_unmask_register_offset, msix_entry,
            IO_QUEUE_DEPTH);
    return true;
}

/* The device masks a CQ's interrupt after raising it; re-enable it (no moderation delays). */
static inline void cq_unmask(io_queue_t *q)
{
    THREAD_MEMORY_FENCE();
    *q->unmask = ENA_ETH_IO_INTR_REG_INTR_UNMASK_MASK;
}

static inline void sq_doorbell(io_queue_t *q)
{
    THREAD_MEMORY_FENCE();
    *q->db = q->sq_tail;
}

static inline void sq_advance(io_queue_t *q)
{
    q->sq_tail++;
    if ((q->sq_tail & (IO_QUEUE_DEPTH - 1)) == 0) {
        q->sq_phase = !q->sq_phase;
    }
    q->inflight++;
}

static inline void cq_advance(io_queue_t *q)
{
    q->cq_head++;
    if ((q->cq_head & (IO_QUEUE_DEPTH - 1)) == 0) {
        q->cq_phase = !q->cq_phase;
    }
}

static void trace_frame(const char *dir, uint64_t n, uint64_t paddr, uint16_t len)
{
    if (n > TRACE_FRAMES) {
        return;
    }
    /* sDDF data regions are mapped into this PD only by io address; print the length only */
    LOG_ENA("%s frame #%lu: %u bytes at 0x%lx\n", dir, n, len, paddr);
}

static void rx_provide(void)
{
    bool posted = false;
    bool reprocess = true;
    while (reprocess) {
        /* keep one slot empty so a full ring is not confused with an empty one */
        while (rxq.inflight < IO_QUEUE_DEPTH - 1 && !net_queue_empty_free(&rx_queue)) {
            net_buff_desc_t buffer;
            int err = net_dequeue_free(&rx_queue, &buffer);
            assert(!err);
            uint16_t req_id = rxq.free_ids[--rxq.num_free_ids];
            rxq.buf[req_id] = buffer;

            volatile struct ena_eth_io_rx_desc *d =
                &((volatile struct ena_eth_io_rx_desc *)rxq.sq)[rxq.sq_tail & (IO_QUEUE_DEPTH - 1)];
            d->length = NET_BUFFER_SIZE;
            d->reserved2 = 0;
            d->req_id = req_id;
            d->reserved6 = 0;
            d->buff_addr_lo = (uint32_t)buffer.io_or_offset;
            d->buff_addr_hi = (uint16_t)(buffer.io_or_offset >> 32);
            d->reserved16_w3 = 0;
            THREAD_MEMORY_RELEASE();
            /* the phase bit last, so the device never sees a half-written descriptor */
            d->ctrl = ENA_ETH_IO_RX_DESC_FIRST_MASK | ENA_ETH_IO_RX_DESC_LAST_MASK | ENA_ETH_IO_RX_DESC_COMP_REQ_MASK
                    | (rxq.sq_phase & ENA_ETH_IO_RX_DESC_PHASE_MASK);
            sq_advance(&rxq);
            posted = true;
        }
        net_request_signal_free(&rx_queue);
        reprocess = false;
        if (rxq.inflight < IO_QUEUE_DEPTH - 1 && !net_queue_empty_free(&rx_queue)) {
            net_cancel_signal_free(&rx_queue);
            reprocess = true;
        }
    }
    if (posted) {
        sq_doorbell(&rxq);
    }
}

static unsigned rx_return(void)
{
    unsigned completed = 0;
    bool transferred = false;
    for (;;) {
        volatile struct ena_eth_io_rx_cdesc_base *c =
            &((volatile struct ena_eth_io_rx_cdesc_base *)rxq.cq)[rxq.cq_head & (IO_QUEUE_DEPTH - 1)];
        uint32_t status = c->status;
        if (((status & ENA_ETH_IO_RX_CDESC_BASE_PHASE_MASK) >> ENA_ETH_IO_RX_CDESC_BASE_PHASE_SHIFT) != rxq.cq_phase) {
            break;
        }
        THREAD_MEMORY_ACQUIRE();
        uint16_t req_id = c->req_id;
        uint16_t len = c->length;
        cq_advance(&rxq);
        completed++;
        if (req_id >= IO_QUEUE_DEPTH) {
            LOG_ENA_ERR("RX completion with invalid req_id %u\n", req_id);
            stats.rx_errs++;
            continue;
        }
        net_buff_desc_t buffer = rxq.buf[req_id];
        rxq.free_ids[rxq.num_free_ids++] = req_id;
        rxq.inflight--;

        bool single = (status & ENA_ETH_IO_RX_CDESC_BASE_FIRST_MASK) && (status & ENA_ETH_IO_RX_CDESC_BASE_LAST_MASK);
        if (!single || len == 0 || len > NET_BUFFER_SIZE) {
            /* multi-descriptor frame (larger than one buffer) or bad length: drop it */
            stats.rx_errs++;
            buffer.len = 0;
            int err = net_enqueue_free(&rx_queue, buffer);
            assert(!err);
            continue;
        }
        stats.rx_pkts++;
        stats.rx_bytes += len;
        trace_frame("RX", stats.rx_pkts, buffer.io_or_offset, len);
        buffer.len = len;
        int err = net_enqueue_active(&rx_queue, buffer);
        assert(!err);
        transferred = true;
    }
    if (transferred && net_require_signal_active(&rx_queue)) {
        net_cancel_signal_active(&rx_queue);
        sddf_notify(config.virt_rx.id);
    }
    return completed;
}

static void tx_provide(void)
{
    bool posted = false;
    bool reprocess = true;
    while (reprocess) {
        while (txq.inflight < IO_QUEUE_DEPTH - 1 && !net_queue_empty_active(&tx_queue)) {
            net_buff_desc_t buffer;
            int err = net_dequeue_active(&tx_queue, &buffer);
            assert(!err);
            uint16_t req_id = txq.free_ids[--txq.num_free_ids];
            txq.buf[req_id] = buffer;

            volatile struct ena_eth_io_tx_desc *d =
                &((volatile struct ena_eth_io_tx_desc *)txq.sq)[txq.sq_tail & (IO_QUEUE_DEPTH - 1)];
            d->meta_ctrl = ((uint32_t)req_id << ENA_ETH_IO_TX_DESC_REQ_ID_LO_SHIFT) & ENA_ETH_IO_TX_DESC_REQ_ID_LO_MASK;
            d->buff_addr_lo = (uint32_t)buffer.io_or_offset;
            /* header length 0: descriptors are in host memory (the reference driver does the same) */
            d->buff_addr_hi_hdr_sz = (uint32_t)(buffer.io_or_offset >> 32) & ENA_ETH_IO_TX_DESC_ADDR_HI_MASK;
            THREAD_MEMORY_RELEASE();
            /* len_ctrl carries the phase bit, so it is written last */
            d->len_ctrl = (buffer.len & ENA_ETH_IO_TX_DESC_LENGTH_MASK)
                        | ((((uint32_t)req_id >> 10) << ENA_ETH_IO_TX_DESC_REQ_ID_HI_SHIFT) & ENA_ETH_IO_TX_DESC_REQ_ID_HI_MASK)
                        | (((uint32_t)txq.sq_phase << ENA_ETH_IO_TX_DESC_PHASE_SHIFT) & ENA_ETH_IO_TX_DESC_PHASE_MASK)
                        | ENA_ETH_IO_TX_DESC_FIRST_MASK | ENA_ETH_IO_TX_DESC_LAST_MASK | ENA_ETH_IO_TX_DESC_COMP_REQ_MASK;
            sq_advance(&txq);
            stats.tx_pkts++;
            stats.tx_bytes += buffer.len;
            trace_frame("TX", stats.tx_pkts, buffer.io_or_offset, buffer.len);
            posted = true;
        }
        net_request_signal_active(&tx_queue);
        reprocess = false;
        if (txq.inflight < IO_QUEUE_DEPTH - 1 && !net_queue_empty_active(&tx_queue)) {
            net_cancel_signal_active(&tx_queue);
            reprocess = true;
        }
    }
    if (posted) {
        sq_doorbell(&txq);
    }
}

static unsigned tx_return(void)
{
    unsigned completed = 0;
    bool transferred = false;
    for (;;) {
        volatile struct ena_eth_io_tx_cdesc *c =
            &((volatile struct ena_eth_io_tx_cdesc *)txq.cq)[txq.cq_head & (IO_QUEUE_DEPTH - 1)];
        if ((c->flags & ENA_ETH_IO_TX_CDESC_PHASE_MASK) != txq.cq_phase) {
            break;
        }
        THREAD_MEMORY_ACQUIRE();
        uint16_t req_id = c->req_id;
        cq_advance(&txq);
        completed++;
        if (req_id >= IO_QUEUE_DEPTH) {
            LOG_ENA_ERR("TX completion with invalid req_id %u\n", req_id);
            continue;
        }
        net_buff_desc_t buffer = txq.buf[req_id];
        txq.free_ids[txq.num_free_ids++] = req_id;
        txq.inflight--;
        buffer.len = 0;
        int err = net_enqueue_free(&tx_queue, buffer);
        assert(!err);
        transferred = true;
    }
    if (transferred && net_require_signal_free(&tx_queue)) {
        net_cancel_signal_free(&tx_queue);
        sddf_notify(config.virt_tx.id);
    }
    return completed;
}

/* Asynchronous event notifications (keep-alive, link change, ...): consume them so the queue does not
 * fill up, and print the first few. */
static void aenq_poll(void)
{
    volatile struct ena_admin_aenq_entry *q = dma_vaddr(DMA_OFF_AENQ);
    uint16_t processed = 0;
    for (;;) {
        volatile struct ena_admin_aenq_entry *e = &q[ena.aenq_head & (ENA_ASYNC_QUEUE_DEPTH - 1)];
        if ((e->aenq_common_desc.flags & ENA_ADMIN_AENQ_COMMON_DESC_PHASE_MASK) != ena.aenq_phase) {
            break;
        }
        THREAD_MEMORY_ACQUIRE();
        stats.aenq_events++;
        if (stats.aenq_events <= 4) {
            LOG_ENA("AENQ event #%lu: group %u, syndrome %u\n", stats.aenq_events, e->aenq_common_desc.group,
                    e->aenq_common_desc.syndrome);
        }
        ena.aenq_head++;
        processed++;
        if ((ena.aenq_head & (ENA_ASYNC_QUEUE_DEPTH - 1)) == 0) {
            ena.aenq_phase = !ena.aenq_phase;
        }
    }
    if (processed) {
        reg_write32(ENA_REGS_AENQ_HEAD_DB_OFF, ena.aenq_head);
    }
}

/* Process both CQs, refill RX, consume the AENQ. Returns the number of completions handled. */
static unsigned service(void)
{
    unsigned n = tx_return();
    tx_provide();
    n += rx_return();
    rx_provide();
    aenq_poll();
    return n;
}

static void handle_irq(void)
{
    stats.irqs++;
    service();
    cq_unmask(&txq);
    cq_unmask(&rxq);
    /* completions that arrived between the last check and the unmask raise a new interrupt */
}

/* Fallback poll (the interrupt should have handled everything) and statistics */
static void poll(void)
{
    unsigned n = service();
    if (n) {
        stats.fallback_hits += n;
        cq_unmask(&txq);
        cq_unmask(&rxq);
    }

    uint64_t now = now_ns();
    if (now >= stats.next_print_ns) {
        stats.next_print_ns = now + STATS_INTERVAL_NS;
        LOG_ENA("rx %lu pkts / %lu B (errors %lu), tx %lu pkts / %lu B, inflight rx %u tx %u, aenq %lu, irqs %lu, "
                "fallback %lu\n", stats.rx_pkts, stats.rx_bytes, stats.rx_errs, stats.tx_pkts, stats.tx_bytes,
                rxq.inflight, txq.inflight, stats.aenq_events, stats.irqs, stats.fallback_hits);
    }
    sddf_timer_set_timeout(timer_config.driver_id, POLL_INTERVAL_NS);
}

static bool io_init(void)
{
    net_queue_init(&rx_queue, config.virt_rx.free_queue.vaddr, config.virt_rx.active_queue.vaddr,
                   config.virt_rx.num_buffers);
    net_queue_init(&tx_queue, config.virt_tx.free_queue.vaddr, config.virt_tx.active_queue.vaddr,
                   config.virt_tx.num_buffers);
    ena.aenq_head = ENA_ASYNC_QUEUE_DEPTH; /* as ena_com_admin_init_aenq() of the reference */
    ena.aenq_phase = 1;

    if (!set_host_info()) {
        LOG_ENA_ERR("setting the host info failed\n");
        return false;
    }
    if (!set_mtu(ENA_MTU)) {
        LOG_ENA_ERR("setting MTU %u failed\n", ENA_MTU);
        return false;
    }
    LOG_ENA("host info set, MTU %u\n", ENA_MTU);
    if (!msix_setup()) {
        return false;
    }
    if (!create_queue(&txq, true, DMA_OFF_TX_SQ, DMA_OFF_TX_CQ, MSIX_ENTRY_TX)
        || !create_queue(&rxq, false, DMA_OFF_RX_SQ, DMA_OFF_RX_CQ, MSIX_ENTRY_RX)) {
        return false;
    }
    rx_provide();
    cq_unmask(&txq);
    cq_unmask(&rxq);
    LOG_ENA("RX buffers posted: %u (sDDF pool %u)\n", rxq.inflight, config.virt_rx.num_buffers);
    return true;
}

void init(void)
{
    assert(net_config_check_magic(&config));
    LOG_ENA("M5-3 bring-up (admin queue, I/O queues, MSI-X; fallback poll every %lu ms)\n",
            (unsigned long)(POLL_INTERVAL_NS / NS_IN_MS));
    memset(&ena, 0, sizeof(ena));
    ena.mmio_resp = dma_vaddr(DMA_OFF_MMIO_RESP);
    ena.mmio_resp->req_id = 0;

    if (!pci_probe()) {
        return;
    }
    LOG_ENA("register reads: %s\n", ena.readless ? "readless (via DMA)" : "direct");
    write_mmio_resp_addr();

    if (!dev_reset() || !validate_version() || !admin_init() || !read_device_info() || !io_init()) {
        LOG_ENA_ERR("bring-up failed\n");
        return;
    }
    ena.ready = true;
    LOG_ENA("M5-3 ready: I/O queues up, MSI-X enabled\n");
    stats.next_print_ns = now_ns() + STATS_INTERVAL_NS;
    sddf_timer_set_timeout(timer_config.driver_id, POLL_INTERVAL_NS);
    sddf_irq_ack(ENA_IRQ_CH);
}

void notified(sddf_channel ch)
{
    if (!ena.ready) {
        return;
    }
    if (ch == ENA_IRQ_CH) {
        handle_irq();
        sddf_deferred_irq_ack(ch);
    } else if (ch == timer_config.driver_id) {
        poll();
    } else if (ch == config.virt_tx.id) {
        tx_provide();
    } else if (ch == config.virt_rx.id) {
        rx_provide();
    } else {
        LOG_ENA_ERR("notification on unexpected channel %u\n", ch);
    }
}
