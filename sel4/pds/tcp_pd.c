/*
 * qedos — TCP/IP Stack Protection Domain (`tcp_pd.elf`).
 *
 * Isolation & Security Laws:
 *   - Runs sDDF network queues + lwIP TCP/IP stack.
 *   - Listens on TCP port 8443 and bridges raw ciphertext bytes to/from `tls_pd`
 *     via `shm_tcp_tls` (VADDR_SHM_TCP_TLS).
 *   - Opens outbound TCP connections to fixed backend addresses on behalf of
 *     `connector_pd` via `shm_tcp_conn` (VADDR_SHM_TCP_CONN).
 *   - Has ZERO access to the TLS private key (LAW_008), plaintext HTTP rings,
 *     or the route policy table (LAW_012).
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <os/sddf.h>
#include <sddf/util/util.h>
#include <sddf/util/printf.h>
#include <sddf/network/lib_sddf_lwip.h>
#include <sddf/network/queue.h>
#include <sddf/network/config.h>
#include <sddf/serial/queue.h>
#include <sddf/serial/config.h>
#include <sddf/timer/client.h>
#include <sddf/timer/config.h>

#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "pg_shm.h"

#define CH_TCP_TLS      10
#define CH_TCP_CONN     11
#define PROXY_HTTPS_PORT 8443
#define LWIP_TICK_MS    50

__attribute__((__section__(".serial_client_config"))) serial_client_config_t serial_config;
__attribute__((__section__(".timer_client_config")))  timer_client_config_t  timer_config;
__attribute__((__section__(".net_client_config")))    net_client_config_t    net_config;
__attribute__((__section__(".lib_sddf_lwip_config"))) lib_sddf_lwip_config_t lib_sddf_lwip_config;

static serial_queue_handle_t serial_tx_queue_handle;
static net_queue_handle_t    net_rx_handle;
static net_queue_handle_t    net_tx_handle;

static pg_shm_tcp_tls_t  *shm_tcp_tls  = (pg_shm_tcp_tls_t *)VADDR_SHM_TCP_TLS;
static pg_shm_tcp_conn_t *shm_tcp_conn = (pg_shm_tcp_conn_t *)VADDR_SHM_TCP_CONN;

/* =========================================================================
 * 1. Inbound TCP (:8443) <-> shm_tcp_tls bridge
 * ========================================================================= */
typedef struct {
    bool            in_use;
    uint8_t         slot_idx;
    uint32_t        conn_id;
    struct tcp_pcb *pcb;
} tcp_inbound_t;

static tcp_inbound_t g_inbound[PG_MAX_CONNS];
static uint32_t      g_next_conn_id = 1;

static void inbound_drain_tx(uint8_t s)
{
    tcp_inbound_t     *in = &g_inbound[s];
    pg_tcp_tls_slot_t *ts = &shm_tcp_tls->slots[s];
    if (!in->in_use || in->pcb == NULL) {
        return;
    }

    uint32_t head = ts->tx_head;
    uint32_t tail = ts->tx_tail;
    while (tail != head) {
        uint32_t sndbuf = (uint32_t)tcp_sndbuf(in->pcb);
        if (sndbuf == 0) {
            break;
        }
        uint32_t avail = head - tail;
        uint32_t chunk = (avail < sndbuf) ? avail : sndbuf;
        if (chunk > 1460) {
            chunk = 1460;
        }
        uint8_t buf[1460];
        for (uint32_t i = 0; i < chunk; i++) {
            buf[i] = ts->tx_buf[(tail + i) % PG_RING_SIZE];
        }
        err_t err = tcp_write(in->pcb, buf, (u16_t)chunk, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            break;
        }
        tail += chunk;
    }
    PG_FENCE();
    ts->tx_tail = tail;
    (void)tcp_output(in->pcb);

    if (ts->tls_close_req && ts->tx_tail == ts->tx_head) {
        struct tcp_pcb *pcb = in->pcb;
        in->pcb = NULL;
        in->in_use = false;
        ts->tcp_state = PG_TCP_STATE_FREE;
        ts->conn_id = 0;
        ts->tls_close_req = 0;
        PG_FENCE();
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_err(pcb, NULL);
        (void)tcp_close(pcb);
    }
}

static err_t inbound_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)pcb;
    (void)len;
    tcp_inbound_t *in = (tcp_inbound_t *)arg;
    if (in != NULL && in->in_use) {
        inbound_drain_tx(in->slot_idx);
    }
    return ERR_OK;
}

static err_t inbound_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    tcp_inbound_t *in = (tcp_inbound_t *)arg;
    if (in == NULL || !in->in_use) {
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }
    uint8_t s = in->slot_idx;
    pg_tcp_tls_slot_t *ts = &shm_tcp_tls->slots[s];

    if (p == NULL) {
        /* Client sent FIN */
        ts->tcp_state = PG_TCP_STATE_CLIENT_EOF;
        PG_FENCE();
        microkit_notify(CH_TCP_TLS);
        inbound_drain_tx(s);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        return err;
    }

    uint32_t head = ts->rx_head;
    uint32_t tail = ts->rx_tail;
    uint32_t used = head - tail;
    if (used + p->tot_len > PG_RING_SIZE) {
        /* Backpressure: ask lwIP to redeliver later */
        return ERR_MEM;
    }

    struct pbuf *q = p;
    while (q != NULL) {
        const uint8_t *payload = (const uint8_t *)q->payload;
        for (u16_t i = 0; i < q->len; i++) {
            ts->rx_buf[head % PG_RING_SIZE] = payload[i];
            head++;
        }
        q = q->next;
    }
    PG_FENCE();
    ts->rx_head = head;
    PG_FENCE();

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);

    microkit_notify(CH_TCP_TLS);
    return ERR_OK;
}

static void inbound_err_cb(void *arg, err_t err)
{
    (void)err;
    tcp_inbound_t *in = (tcp_inbound_t *)arg;
    if (in == NULL) {
        return;
    }
    uint8_t s = in->slot_idx;
    in->pcb = NULL;
    in->in_use = false;
    shm_tcp_tls->slots[s].tcp_state = PG_TCP_STATE_RESET;
    shm_tcp_tls->slots[s].conn_id = 0;
    PG_FENCE();
    microkit_notify(CH_TCP_TLS);
}

static err_t inbound_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || newpcb == NULL) {
        return ERR_VAL;
    }

    int found = -1;
    for (uint8_t s = 0; s < PG_MAX_CONNS; s++) {
        if (!g_inbound[s].in_use && shm_tcp_tls->slots[s].tcp_state == PG_TCP_STATE_FREE) {
            found = (int)s;
            break;
        }
    }
    if (found < 0) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    uint8_t s = (uint8_t)found;
    tcp_inbound_t *in = &g_inbound[s];
    pg_tcp_tls_slot_t *ts = &shm_tcp_tls->slots[s];

    uint32_t cid = g_next_conn_id++;
    if (cid == 0) {
        cid = g_next_conn_id++;
    }

    in->in_use   = true;
    in->slot_idx = s;
    in->conn_id  = cid;
    in->pcb      = newpcb;

    ts->rx_head       = 0;
    ts->rx_tail       = 0;
    ts->tx_head       = 0;
    ts->tx_tail       = 0;
    ts->tls_close_req = 0;
    ts->tcp_state     = PG_TCP_STATE_OPEN;
    PG_FENCE();
    ts->conn_id       = cid;
    PG_FENCE();

    tcp_nagle_disable(newpcb);
    tcp_arg(newpcb, in);
    tcp_recv(newpcb, inbound_recv_cb);
    tcp_sent(newpcb, inbound_sent_cb);
    tcp_err(newpcb, inbound_err_cb);

    microkit_notify(CH_TCP_TLS);
    return ERR_OK;
}

static void setup_https_listener(void)
{
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL) {
        sddf_printf("TCP_PD: failed to allocate listener PCB\n");
        return;
    }
    err_t err = tcp_bind(pcb, IP_ANY_TYPE, PROXY_HTTPS_PORT);
    if (err != ERR_OK) {
        sddf_printf("TCP_PD: failed to bind :%d\n", PROXY_HTTPS_PORT);
        return;
    }
    pcb = tcp_listen_with_backlog_and_err(pcb, 8, &err);
    if (pcb == NULL || err != ERR_OK) {
        sddf_printf("TCP_PD: failed to listen on :%d\n", PROXY_HTTPS_PORT);
        return;
    }
    tcp_accept(pcb, inbound_accept_cb);
    sddf_printf("TCP_PD: listening on 0.0.0.0:%d\n", PROXY_HTTPS_PORT);
}

/* =========================================================================
 * 2. Outbound Backend TCP Client (shm_tcp_conn <-> backend IP:port)
 * ========================================================================= */
static uint32_t        g_last_conn_req_seq = 0;
static struct tcp_pcb *g_out_pcb           = NULL;
static uint32_t        g_out_tx_sent       = 0;

static void finish_outbound(uint8_t status)
{
    if (g_out_pcb != NULL) {
        struct tcp_pcb *pcb = g_out_pcb;
        g_out_pcb = NULL;
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_err(pcb, NULL);
        (void)tcp_close(pcb);
    }
    shm_tcp_conn->status = status;
    PG_FENCE();
    shm_tcp_conn->resp_seq = g_last_conn_req_seq;
    PG_FENCE();
    microkit_notify(CH_TCP_CONN);
}

static void outbound_pump_tx(struct tcp_pcb *pcb)
{
    uint32_t total = shm_tcp_conn->tx_len;
    while (g_out_tx_sent < total) {
        uint32_t sndbuf = (uint32_t)tcp_sndbuf(pcb);
        if (sndbuf == 0) {
            break;
        }
        uint32_t rem = total - g_out_tx_sent;
        uint32_t chunk = (rem < sndbuf) ? rem : sndbuf;
        if (chunk > 1460) {
            chunk = 1460;
        }
        err_t err = tcp_write(pcb, &shm_tcp_conn->tx_buf[g_out_tx_sent], (u16_t)chunk, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            break;
        }
        g_out_tx_sent += chunk;
    }
    (void)tcp_output(pcb);
}

static err_t outbound_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)arg;
    (void)len;
    outbound_pump_tx(pcb);
    return ERR_OK;
}

static err_t outbound_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;
    if (p == NULL) {
        /* Backend closed connection (Connection: close complete!) */
        finish_outbound(PG_CONN_STATUS_OK);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        finish_outbound(PG_CONN_STATUS_ERR_CONNECT);
        return ERR_OK;
    }

    uint32_t cur_len = shm_tcp_conn->rx_len;
    struct pbuf *q = p;
    while (q != NULL) {
        const uint8_t *src = (const uint8_t *)q->payload;
        for (u16_t i = 0; i < q->len; i++) {
            if (cur_len < PG_MAX_RESP_RAW) {
                shm_tcp_conn->rx_buf[cur_len++] = src[i];
            }
        }
        q = q->next;
    }
    shm_tcp_conn->rx_len = cur_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void outbound_err_cb(void *arg, err_t err)
{
    (void)arg;
    (void)err;
    g_out_pcb = NULL;
    if (shm_tcp_conn->rx_len > 0) {
        finish_outbound(PG_CONN_STATUS_OK);
    } else {
        finish_outbound(PG_CONN_STATUS_ERR_CONNECT);
    }
}

static err_t outbound_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK) {
        finish_outbound(PG_CONN_STATUS_ERR_CONNECT);
        return err;
    }
    tcp_nagle_disable(pcb);
    outbound_pump_tx(pcb);
    return ERR_OK;
}

static void check_outbound_request(void)
{
    uint32_t rseq = shm_tcp_conn->req_seq;
    if (rseq == g_last_conn_req_seq) {
        return;
    }
    g_last_conn_req_seq = rseq;
    g_out_tx_sent = 0;

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL) {
        finish_outbound(PG_CONN_STATUS_ERR_CONNECT);
        return;
    }
    g_out_pcb = pcb;

    ip_addr_t dst_ip;
    IP_ADDR4(
        &dst_ip,
        shm_tcp_conn->dst_ipv4[0],
        shm_tcp_conn->dst_ipv4[1],
        shm_tcp_conn->dst_ipv4[2],
        shm_tcp_conn->dst_ipv4[3]
    );

    tcp_arg(pcb, NULL);
    tcp_recv(pcb, outbound_recv_cb);
    tcp_sent(pcb, outbound_sent_cb);
    tcp_err(pcb, outbound_err_cb);

    err_t err = tcp_connect(pcb, &dst_ip, shm_tcp_conn->dst_port, outbound_connected_cb);
    if (err != ERR_OK) {
        finish_outbound(PG_CONN_STATUS_ERR_CONNECT);
    }
}

/* =========================================================================
 * 3. sDDF + lwIP Initialization & Notification Loop
 * ========================================================================= */
static void netif_status_callback(char *ip_addr)
{
    sddf_printf("TCP_PD: DHCP lease acquired, IP=%s (listening on :%d)\n", ip_addr, PROXY_HTTPS_PORT);
}

static void set_timeout(void)
{
    sddf_timer_set_timeout(timer_config.driver_id, LWIP_TICK_MS * NS_IN_MS);
}

void init(void)
{
    serial_queue_init(
        &serial_tx_queue_handle,
        serial_config.tx.queue.vaddr,
        serial_config.tx.data.size,
        serial_config.tx.data.vaddr
    );
    serial_putchar_init(serial_config.tx.id, &serial_tx_queue_handle);

    net_queue_init(
        &net_rx_handle,
        net_config.rx.free_queue.vaddr,
        net_config.rx.active_queue.vaddr,
        net_config.rx.num_buffers
    );
    net_queue_init(
        &net_tx_handle,
        net_config.tx.free_queue.vaddr,
        net_config.tx.active_queue.vaddr,
        net_config.tx.num_buffers
    );
    net_buffers_init(&net_tx_handle, 0);

    sddf_lwip_init(
        &lib_sddf_lwip_config,
        &net_config,
        &timer_config,
        net_rx_handle,
        net_tx_handle,
        NULL,
        NULL,
        netif_status_callback,
        NULL,
        NULL,
        NULL
    );
    set_timeout();
    setup_https_listener();
    sddf_lwip_maybe_notify();
}

void notified(sddf_channel ch)
{
    if (ch == net_config.rx.id) {
        sddf_lwip_process_rx();
    } else if (ch == timer_config.driver_id) {
        sddf_lwip_process_timeout();
        set_timeout();
        for (uint8_t s = 0; s < PG_MAX_CONNS; s++) {
            inbound_drain_tx(s);
        }
    } else if (ch == CH_TCP_TLS) {
        for (uint8_t s = 0; s < PG_MAX_CONNS; s++) {
            inbound_drain_tx(s);
        }
    } else if (ch == CH_TCP_CONN) {
        check_outbound_request();
    }
    sddf_lwip_maybe_notify();
}
