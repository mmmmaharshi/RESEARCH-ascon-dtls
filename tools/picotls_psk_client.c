/* picotls_psk_client.c — minimal TLS 1.3 PSK client for suite 0x006E
 * (picotls minicrypto build, Ascon-AEAD128 + Ascon-Hash256).
 * Interops with tls13_psk_server.c (wolfSSL) over the wire. */
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include "picotls.h"
#include "picotls/minicrypto.h"

int main(int argc, char** argv)
{
    const char* host = "127.0.0.1";
    int port = 11111;
    WSADATA wsa;
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    setvbuf(stdout, NULL, _IONBF, 0);
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* PSK key: 32 bytes {0x01,0x23,0x45,...} (matches wolfSSL server). */
    unsigned char key[32];
    unsigned char b = 0x01;
    for (int i = 0; i < 32; i++, b += 0x22) {
        if (b >= 0x100) b = 0x01;
        key[i] = b;
    }

    ptls_context_t ctx = {0};
    ctx.random_bytes = ptls_minicrypto_random_bytes;
    ctx.cipher_suites = ptls_minicrypto_cipher_suites;
    ctx.key_exchanges = NULL; /* PSK-only (psk_ke): wolfSSL build has no ECC/FFDHE common ground */
    ctx.pre_shared_key.identity = ptls_iovec_init("Client_identity", 15);
    ctx.pre_shared_key.secret = ptls_iovec_init(key, sizeof(key));
    ctx.pre_shared_key.hash = &ptls_ascon_hash256;
    ctx.get_time = &ptls_get_time;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = inet_addr(host);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("connect fail\n");
        return 1;
    }

    ptls_t* tls = ptls_new(&ctx, 0 /* client */);
    ptls_handshake_properties_t hs = {0};
    ptls_buffer_t wbuf;
    ptls_buffer_init(&wbuf, "", 0);
    int ret;

    /* generate ClientHello */
    ret = ptls_handshake(tls, &wbuf, NULL, NULL, &hs);
    if (wbuf.off > 0) { send(sock, wbuf.base, (int)wbuf.off, 0); wbuf.off = 0; }
    if (ret != 0 && ret != PTLS_ERROR_IN_PROGRESS) {
        printf("clienthello fail %d\n", ret);
        return 1;
    }

    uint8_t rbuf[65536];
    size_t rlen = 0;
    while (ret == PTLS_ERROR_IN_PROGRESS) {
        int n = recv(sock, (char*)rbuf + rlen,
                     (int)(sizeof(rbuf) - rlen), 0);
        if (n <= 0) { printf("recv fail during handshake\n"); return 1; }
        rlen += (size_t)n;
        size_t c = rlen;
        int iter_ret = ptls_handshake(tls, &wbuf, rbuf, &c, &hs);
        printf("[iter] consumed=%u new_total=%u ret=%d first_type=0x%02x\n",
               (unsigned)c, (unsigned)rlen, iter_ret,
               rlen > 0 ? rbuf[0] : 0);
        ret = iter_ret;
        memmove(rbuf, rbuf + c, rlen - c);
        rlen -= c;
if (wbuf.off > 0) { printf("[DBG send-flight] off=%d: ", (int)wbuf.off); for (int i = 0; i < (int)wbuf.off; ++i) printf("%02x", wbuf.base[i]); printf("\n"); send(sock, wbuf.base, (int)wbuf.off, 0); wbuf.off = 0; }
        if (ret == 0) break;
        if (ret != PTLS_ERROR_IN_PROGRESS) {
            printf("handshake err %d\n", ret);
            return 1;
        }
    }

    ptls_cipher_suite_t* cs = ptls_get_cipher(tls);
    printf("HANDSHAKE OK. cipher id=0x%04x name=%s\n", cs->id, cs->name);

    /* send a test message */
    const char* msg = "ping";
    ptls_buffer_t s;
    ptls_buffer_init(&s, "", 0);
    if (ptls_send(tls, &s, msg, strlen(msg)) != 0) {
        printf("send fail\n");
        return 1;
    }
    send(sock, s.base, (int)s.off, 0);
    printf("[DBG send] app record off=%d\n", (int)s.off);
    for (int i = 0; i < (int)s.off; ++i) printf("%02x", s.base[i]);
    printf("\n");
    ptls_buffer_dispose(&s);

    /* receive echo */
    {
        ptls_buffer_t dec;
        ptls_buffer_init(&dec, "", 0);
        int got = 0;
        while (!got) {
            if (rlen == 0) {
                int n = recv(sock, (char*)rbuf, (int)sizeof(rbuf), 0);
                if (n <= 0) { printf("recv echo fail\n"); break; }
                rlen = (size_t)n;
            }
            size_t off = 0;
            while (off < rlen) {
                size_t len = rlen - off;
                int r = ptls_receive(tls, &dec, rbuf + off, &len);
                off += len;
                if (r == 0) {
                    if (dec.off > 0) {
                        printf("ECHO: %.*s\n", (int)dec.off, dec.base);
                        got = 1;
                        break;
                    }
                } else if (r != PTLS_ERROR_IN_PROGRESS) {
                    printf("receive err %d\n", r);
                    break;
                }
            }
            memmove(rbuf, rbuf + off, rlen - off);
            rlen -= off;
            if (got) break;
        }
        ptls_buffer_dispose(&dec);
    }

    ptls_free(tls);
    closesocket(sock);
    WSACleanup();
    return 0;
}
