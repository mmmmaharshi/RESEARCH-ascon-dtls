/* dtls13_psk_server.c — minimal DTLS 1.3 PSK server for suite 0x006E.
 * Mirrors the wolfSSL examples PSK identity/key protocol:
 * identity "Client_identity", key = 32 bytes {0x01,0x23,0x45,...}.
 */
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

static unsigned int psk_server_cb(WOLFSSL* ssl, const char* identity,
    unsigned char* key, unsigned int key_max_len, const char** ciphersuite)
{
    unsigned int i;
    unsigned char b = 0x01;
    const char* userCipher =
        (const char*)wolfSSL_get_psk_callback_ctx(ssl);
    (void)key_max_len;
    if (strcmp(identity, "Client_identity") != 0)
        return 0;
    for (i = 0; i < 32; i++, b += 0x22) {
        if (b >= 0x100) b = 0x01;
        key[i] = b;
    }
    *ciphersuite = userCipher ? userCipher : "TLS13-ASCONAEAD128-ASCONHASH256";
    return 32;
}

int main(int argc, char** argv)
{
    int port = 11111;
    SOCKET sock;
    WSADATA wsa;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    int shortTimeout = argc > 2 && strcmp(argv[2], "--short-timeout") == 0;

    if (argc > 1) port = atoi(argv[1]);
    setvbuf(stdout, NULL, _IONBF, 0);
    WSAStartup(MAKEWORD(2,2), &wsa);
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (ctx == NULL) { printf("ctx fail\n"); return 1; }
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, psk_server_cb);
    wolfSSL_CTX_set_psk_callback_ctx(ctx,
        "TLS13-ASCONAEAD128-ASCONHASH256");
    if (wolfSSL_CTX_set_cipher_list(ctx,
            "TLS13-ASCONAEAD128-ASCONHASH256") != WOLFSSL_SUCCESS) {
        printf("cipher list fail\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (shortTimeout) {
        DWORD timeoutMs = 100;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs,
            sizeof(timeoutMs));
    }
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("bind fail\n"); return 1;
        }
    }

    ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, (int)sock);
    /* Test-only guardrail: tell wolfSSL to treat would-block reads as
     * WANT_READ so the retry loops can bound the wait. */
    if (shortTimeout) {
        wolfSSL_dtls_set_using_nonblock(ssl, 1);
    }
    printf("listening on port %d sock=%llu\n", port,
        (unsigned long long)sock);

    /* Test-only guardrail: the socket stays blocking during accept; the
     * accept loop itself is bounded by the retry count. After the handshake
     * the socket is made nonblocking so read cannot wait forever. */
    {
        int tries = 0;
        do {
            ret = wolfSSL_accept(ssl);
            if (ret == WOLFSSL_SUCCESS) break;
            {
                int err = wolfSSL_get_error(ssl, ret);
                if ((err == WOLFSSL_ERROR_WANT_READ ||
                     err == WOLFSSL_ERROR_WANT_WRITE) &&
                    tries++ < (shortTimeout ? 20 : 200)) {
                    Sleep(50);
                    continue;
                }
            }
            printf("accept fail, err %d (%s)\n",
                wolfSSL_get_error(ssl, ret),
                wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)));
            return 1;
        } while (1);
    }
    printf("HANDSHAKE OK. cipher: %s\n", wolfSSL_get_cipher(ssl));

    /* echo up to msgLoop messages; on a failed read keep looping so that
     * repeated authentication failures (e.g. a flood of corrupted records)
     * accumulate and trip the forced-KeyUpdate path. */
    {
        char buf[64];
        int msgLoop = 20;
        int i;
        if (argc > 3) msgLoop = atoi(argv[3]);
        for (i = 0; i < msgLoop; i++) {
            int tries = 0;
            do {
                ret = wolfSSL_read(ssl, buf, sizeof(buf));
                if (ret <= 0) {
                    int err = wolfSSL_get_error(ssl, ret);
                    if ((err == WOLFSSL_ERROR_WANT_READ ||
                          err == WOLFSSL_ERROR_WANT_WRITE) &&
                         tries++ < (shortTimeout ? 20 : 100)) {
                        Sleep(50);
                        continue;
                    }
                }
                break;
            } while (1);
            if (ret > 0) {
                printf("got: %s\n", buf);
                wolfSSL_write(ssl, buf, ret);
            }
            else {
                int err = wolfSSL_get_error(ssl, ret);
                printf("read fail [%d], err %d\n", i, err);
            }
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    closesocket(sock);
    WSACleanup();
    return 0;
}
