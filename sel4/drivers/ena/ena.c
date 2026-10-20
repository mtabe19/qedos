/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * ENA (AWS Elastic Network Adapter) driver for seL4 Microkit / sDDF.
 * mtabe19/qedos fork, Stage E (docs/STAGE_E_EC2.md 5-5).
 *
 * Step M5-1: find the ENA on PCI, reset it, bring up the admin queue in polling mode and print the
 * device attributes (MAC address, MTU, queue limits). No I/O queues and no interrupts yet.
 *
 * Register layout and admin command formats come from ena_defs/ (Amazon, BSD-3-Clause, see
 * ena_defs/README.md). The init sequence follows ena_com.c of the same source: ena_com_dev_reset(),
 * ena_com_validate_version(), ena_com_admin_init() and ena_com_get_feature_ex().
 *
 * Machine profile (sel4/meta_proofgate.py --profile ec2-t3):
 *   - PCI 00:05.0, configuration space through I/O ports 0xCF8 (id 1) / 0xCFC (id 2)
 *   - BAR0 (16 KiB at 0xfebf4000 with legacy BIOS boot) mapped uncached at ENA_BAR0_VADDR
 *   - DMA memory "hw_net_rings" (64 KiB at paddr 0x7A000000) mapped at ENA_DMA_VADDR
 *   - timer client (used for timeouts; the data path will poll on it until MSI-X)
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
/* 0x2000..: I/O queues (M5-2) */

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
} ena;

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

void init(void)
{
    LOG_ENA("M5-1 bring-up (admin queue only, polling)\n");
    memset(&ena, 0, sizeof(ena));
    ena.mmio_resp = dma_vaddr(DMA_OFF_MMIO_RESP);
    ena.mmio_resp->req_id = 0;

    if (!pci_probe()) {
        return;
    }
    LOG_ENA("register reads: %s\n", ena.readless ? "readless (via DMA)" : "direct");
    write_mmio_resp_addr();

    if (!dev_reset() || !validate_version() || !admin_init() || !read_device_info()) {
        LOG_ENA_ERR("bring-up failed\n");
        return;
    }
    ena.ready = true;
    LOG_ENA("M5-1 done: admin queue works (no I/O queues yet)\n");
}

void notified(sddf_channel ch)
{
    /* M5-1: the data path is not implemented; requests from the virtualisers and timer ticks are ignored */
    (void)ch;
}
