/* tls13_psk_server.c — minimal TLS 1.3 PSK server for suite 0x006E.
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
    const char* userCipher = (const char*)wolfSSL_get_psk_callback_ctx(ssl);
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
    SOCKET listen_sock, sock;
    WSADATA wsa;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    if (argc > 1) port = atoi(argv[1]);
    setvbuf(stdout, NULL, _IONBF, 0);
    WSAStartup(MAKEWORD(2, 2), &wsa);
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) { printf("ctx fail\n"); return 1; }
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, psk_server_cb);
    wolfSSL_CTX_set_psk_callback_ctx(ctx,
        "TLS13-ASCONAEAD128-ASCONHASH256");
    if (wolfSSL_CTX_set_cipher_list(ctx,
            "TLS13-ASCONAEAD128-ASCONHASH256") != WOLFSSL_SUCCESS) {
        printf("cipher list fail\n");
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("bind fail\n"); return 1;
        }
        if (listen(listen_sock, 1) < 0) { printf("listen fail\n"); return 1; }
    }
    printf("listening on port %d\n", port);
    sock = accept(listen_sock, NULL, NULL);
    if (sock == INVALID_SOCKET) { printf("accept fail\n"); return 1; }
    closesocket(listen_sock);

    ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, (int)sock);
    {
        int tries = 0;
        do {
            ret = wolfSSL_accept(ssl);
            if (ret == WOLFSSL_SUCCESS) break;
            {
                int err = wolfSSL_get_error(ssl, ret);
                if ((err == WOLFSSL_ERROR_WANT_READ ||
                     err == WOLFSSL_ERROR_WANT_WRITE) && tries++ < 200) {
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

    {
        char buf[64];
        int msgLoop = 20;
        int i;
        if (argc > 2) msgLoop = atoi(argv[2]);
        for (i = 0; i < msgLoop; i++) {
            int tries = 0;
            do {
                ret = wolfSSL_read(ssl, buf, sizeof(buf));
                if (ret <= 0) {
                    int err = wolfSSL_get_error(ssl, ret);
                    if ((err == WOLFSSL_ERROR_WANT_READ ||
                          err == WOLFSSL_ERROR_WANT_WRITE) &&
                         tries++ < 100) {
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
