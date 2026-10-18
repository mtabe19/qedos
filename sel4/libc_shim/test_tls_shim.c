/*
 * Self-test for freestanding OpenSSL 3.6.1 + libc_shim on x86_64 seL4/Microkit.
 *
 * Verifies:
 *  1. OpenSSL initialization without OS/stdio/threads/syscalls.
 *  2. SSL_CTX creation with TLS1_3_VERSION, cipher TLS_AES_256_GCM_SHA384,
 *     and hybrid post-quantum group X25519MLKEM768.
 *  3. Loading X.509 ECDSA P-256 certificate and private key from memory BIOs
 *     via PEM_read_bio_X509 and PEM_read_bio_PrivateKey.
 *  4. In-memory client <-> server TLS 1.3 handshake over BIO_s_mem() and
 *     verification that SSL_get0_group_name(server_ssl) is "X25519MLKEM768"
 *     and SSL_get_cipher_name(server_ssl) is "TLS_AES_256_GCM_SHA384".
 *  5. Bidirectional encrypted record round-trip and heap coalescing check
 *     across repeated connection cycles so SSL objects do not leak memory.
 */
#include "libc_shim.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if defined(SEL4_MICROKIT_PD)
#include <microkit.h>
#define LOG_PUTS(s) microkit_dbg_puts(s)
#else
extern long write(int fd, const void *buf, size_t count);
static void host_puts(const char *s)
{
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    (void)write(1, s, len);
}
#define LOG_PUTS(s) host_puts(s)
#endif

static const char TEST_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBaDCCAQ2gAwIBAgIUQ4cU8aRNZVfFUmnYI+5bP823irYwCgYIKoZIzj0EAwIw\n"
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAxNzAzMzMwNVoXDTI2MTExNjAz\n"
    "MzMwNVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEm2CAhAsNohe9y7dCWWphGvAYkpvabFu9khAHF8CzmHgSn55au16ehv3k\n"
    "2wQUve9BJeu1VXm4gi7RC2fr4LX+3KM9MDswGgYDVR0RBBMwEYIJbG9jYWxob3N0\n"
    "hwR/AAABMB0GA1UdDgQWBBTV8r8xfrnE7xUXHc1Vbirtjc69RzAKBggqhkjOPQQD\n"
    "AgNJADBGAiEAhkgTm+gjAZhHBiJ8OYGCd/oMRfl0VwvUxfzIGoM7JqwCIQC6pMgn\n"
    "8CYfKkzABe+v1YzRqPltqRR7G4AnVXmGvwYZhw==\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0nTrqf1sOhUmD3b3\n"
    "NmE45zt1M7HIt8l9xZL8fkVSDVahRANCAASbYICECw2iF73Lt0JZamEa8BiSm9ps\n"
    "W72SEAcXwLOYeBKfnlq7Xp6G/eTbBBS970El67VVebiCLtELZ+vgtf7c\n"
    "-----END PRIVATE KEY-----\n";

static int pump_bio(BIO *src, BIO *dst)
{
    uint8_t buf[4096];
    int moved = 0;
    for (;;) {
        int n = BIO_read(src, buf, (int)sizeof(buf));
        if (n <= 0) {
            break;
        }
        int w = BIO_write(dst, buf, n);
        if (w != n) {
            return -1;
        }
        moved += n;
    }
    return moved;
}

static int str_eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static int run_single_handshake(SSL_CTX *server_ctx, SSL_CTX *client_ctx)
{
    SSL *server_ssl = SSL_new(server_ctx);
    SSL *client_ssl = SSL_new(client_ctx);
    if (server_ssl == NULL || client_ssl == NULL) {
        return -10;
    }

    BIO *c2s = BIO_new(BIO_s_mem());
    BIO *s2c = BIO_new(BIO_s_mem());
    if (c2s == NULL || s2c == NULL) {
        return -11;
    }

    /* Take ownership of BIOs: client reads s2c, writes c2s; server reads c2s, writes s2c */
    BIO_up_ref(c2s);
    BIO_up_ref(s2c);
    SSL_set0_rbio(client_ssl, s2c);
    SSL_set0_wbio(client_ssl, c2s);
    SSL_set0_rbio(server_ssl, c2s);
    SSL_set0_wbio(server_ssl, s2c);

    SSL_set_connect_state(client_ssl);
    SSL_set_accept_state(server_ssl);

    int client_done = 0;
    int server_done = 0;
    for (int step = 0; step < 32 && (!client_done || !server_done); step++) {
        if (!client_done) {
            int rc = SSL_do_handshake(client_ssl);
            if (rc == 1) {
                client_done = 1;
            } else {
                int err = SSL_get_error(client_ssl, rc);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    return -12;
                }
            }
        }
        /* c2s and s2c are shared directly between client_ssl and server_ssl */

        if (!server_done) {
            int rc = SSL_do_handshake(server_ssl);
            if (rc == 1) {
                server_done = 1;
            } else {
                int err = SSL_get_error(server_ssl, rc);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    return -13;
                }
            }
        }
    }

    if (!client_done || !server_done) {
        return -14;
    }

    const char *group_name = SSL_get0_group_name(server_ssl);
    if (!str_eq(group_name, "X25519MLKEM768")) {
        return -15;
    }

    const char *cipher_name = SSL_get_cipher_name(server_ssl);
    if (!str_eq(cipher_name, "TLS_AES_256_GCM_SHA384")) {
        return -16;
    }

    /* Verify application data exchange over memory BIOs */
    static const char ping_msg[] = "SELECT 1; -- seL4 TLS 1.3 X25519MLKEM768";
    char rx_buf[128];
    if (SSL_write(client_ssl, ping_msg, (int)sizeof(ping_msg)) != (int)sizeof(ping_msg)) {
        return -17;
    }
    int rlen = SSL_read(server_ssl, rx_buf, (int)sizeof(rx_buf));
    if (rlen != (int)sizeof(ping_msg) || !str_eq(rx_buf, ping_msg)) {
        return -18;
    }

    SSL_shutdown(client_ssl);
    SSL_shutdown(server_ssl);
    SSL_free(client_ssl);
    SSL_free(server_ssl);
    return 0;
}

int test_tls_shim_run(void)
{
    LOG_PUTS("[test_tls_shim] initializing OpenSSL 3.6.1...\n");
    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return 1;
    }

    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    if (server_ctx == NULL || client_ctx == NULL) {
        return 2;
    }

    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);

    if (SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(server_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION) != 1) {
        return 3;
    }

    if (SSL_CTX_set_ciphersuites(server_ctx, "TLS_AES_256_GCM_SHA384") != 1 ||
        SSL_CTX_set_ciphersuites(client_ctx, "TLS_AES_256_GCM_SHA384") != 1) {
        return 4;
    }

    if (SSL_CTX_set1_groups_list(server_ctx, "X25519MLKEM768") != 1 ||
        SSL_CTX_set1_groups_list(client_ctx, "X25519MLKEM768") != 1) {
        return 5;
    }

    /* Load certificate from memory BIO using PEM_read_bio_X509 */
    BIO *cert_bio = BIO_new_mem_buf(TEST_CERT_PEM, (int)(sizeof(TEST_CERT_PEM) - 1));
    if (cert_bio == NULL) {
        return 6;
    }
    X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);
    if (cert == NULL) {
        return 7;
    }
    if (SSL_CTX_use_certificate(server_ctx, cert) != 1) {
        X509_free(cert);
        return 8;
    }
    X509_free(cert);

    /* Load private key from memory BIO using PEM_read_bio_PrivateKey */
    BIO *key_bio = BIO_new_mem_buf(TEST_KEY_PEM, (int)(sizeof(TEST_KEY_PEM) - 1));
    if (key_bio == NULL) {
        return 9;
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    if (pkey == NULL) {
        return 10;
    }
    if (SSL_CTX_use_PrivateKey(server_ctx, pkey) != 1) {
        EVP_PKEY_free(pkey);
        return 11;
    }
    EVP_PKEY_free(pkey);

    if (SSL_CTX_check_private_key(server_ctx) != 1) {
        return 12;
    }

    /* Perform first handshake to warm up any one-time provider caches */
    int rc = run_single_handshake(server_ctx, client_ctx);
    if (rc != 0) {
        return 20 - rc;
    }

    /* Record steady-state heap usage and verify zero leak across 5 handshakes */
    size_t baseline_bytes = libc_shim_heap_bytes_in_use();
    for (int i = 0; i < 5; i++) {
        rc = run_single_handshake(server_ctx, client_ctx);
        if (rc != 0) {
            return 50 - rc;
        }
    }
    size_t after_bytes = libc_shim_heap_bytes_in_use();
    if (after_bytes != baseline_bytes) {
        return 99;
    }

    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);

    LOG_PUTS("[test_tls_shim] PASS: TLS 1.3 + X25519MLKEM768 + TLS_AES_256_GCM_SHA384 verified with zero heap leak!\n");
    return 0;
}

#if defined(SEL4_MICROKIT_PD)
void init(void)
{
    int rc = test_tls_shim_run();
    if (rc != 0) {
        microkit_dbg_puts("[test_tls_shim] FAIL\n");
    }
}

void notified(microkit_channel ch)
{
    (void)ch;
}
#else
int main(void)
{
    return test_tls_shim_run();
}
#endif
