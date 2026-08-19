/*
 * ascon_psk_client.c -- TLS 1.3 external-PSK client for experimental suite
 * 0x006E TLS_ASCON_AEAD128_ASCON_HASH256, using the new-style PSK session
 * API (SSL_set_psk_use_session_callback) so the PSK's Hash algorithm is
 * provisioned as ASCON-HASH256 (RFC 8446 4.2.11: "the Hash algorithm MUST
 * be set when the PSK is established"). The old-style -psk callback in
 * s_client cannot express a non-SHA-256 hash and defaults the binder to
 * SHA-256 per RFC 8446.
 *
 * Usage: ascon_psk_client.exe <host> <port> <psk-hex> <identity>
 * Sends "Hello Ascon TLS1.3!\n" and prints the echo.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static const unsigned char ascon_suite_id[2] = { 0x00, 0x6E };
static unsigned char g_psk[64];
static size_t g_psklen = 0;
static const char *g_identity = "Client_identity";

static void keylog_cb(const SSL *ssl, const char *line)
{
    printf("KEYLOG %s\n", line);
}

static void msg_cb(int write_p, int version, int content_type, const void *buf,
    size_t len, SSL *ssl, void *arg)
{
    static int dump_seq = 0;
    const unsigned char *p = buf;
    char fn[64];
    FILE *f;

    if (content_type == SSL3_RT_HANDSHAKE || content_type == SSL3_RT_ALERT) {
        snprintf(fn, sizeof(fn), "%s%02d.bin",
            write_p ? "sent_" : "recv_", dump_seq++);
        f = fopen(fn, "wb");
        if (f != NULL) {
            fwrite(p, 1, len, f);
            fclose(f);
        }
        printf(">>> %s %s len=%d\n", write_p ? "SENT" : "RECV",
            content_type == SSL3_RT_ALERT ? "ALERT" : "HANDSHAKE", (int)len);
    }
}

static int psk_use_session_cb(SSL *ssl, const EVP_MD *md,
    const unsigned char **id, size_t *idlen, SSL_SESSION **sess)
{
    SSL_SESSION *ss = SSL_SESSION_new();
    const SSL_CIPHER *cipher;

    if (ss == NULL)
        return 0;

    /* Provision the external PSK with Hash = ASCON-HASH256 (suite 0x006E) */
    cipher = SSL_CIPHER_find(ssl, ascon_suite_id);
    if (cipher == NULL
        || !SSL_SESSION_set1_master_key(ss, g_psk, g_psklen)
        || !SSL_SESSION_set_cipher(ss, cipher)
        || !SSL_SESSION_set_protocol_version(ss, TLS1_3_VERSION)
        || !SSL_SESSION_set_time(ss, time(NULL))) {
        SSL_SESSION_free(ss);
        return 0;
    }

    *id = (const unsigned char *)g_identity;
    *idlen = strlen(g_identity);
    *sess = ss;
    return 1; /* one identity offered */
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    char buf[256];
    int ret, n;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <host> <port> <psk-hex> <identity>\n", argv[0]);
        return 2;
    }
    g_psklen = strlen(argv[3]) / 2;
    for (size_t i = 0; i < g_psklen; i++)
        sscanf(argv[3] + 2 * i, "%2hhx", &g_psk[i]);
    g_identity = argv[4];

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto err;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_ASCON_AEAD128_ASCON_HASH256") != 1)
        goto err;
    SSL_CTX_set_psk_use_session_callback(ctx, psk_use_session_cb);
    SSL_CTX_set_msg_callback(ctx, msg_cb);
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto err;
    bio = BIO_new_connect(argv[1]);
    BIO_set_conn_port(bio, argv[2]);
    SSL_set_bio(ssl, bio, bio);

    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("connected: %s / %s\n",
        SSL_get_version(ssl), SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));

    const char *msg = "Hello Ascon TLS1.3!\n";
    if (SSL_write(ssl, msg, (int)strlen(msg)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("sent: %s", msg);

    n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    buf[n] = 0;
    printf("echo (%d bytes): %s", n, buf);

    ret = 0;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return ret;

err:
    ERR_print_errors_fp(stderr);
    return 1;
}
