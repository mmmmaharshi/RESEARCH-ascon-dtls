/* dtls13_psk_client.c — minimal DTLS 1.3 PSK client for suite 0x006E.
 * Mirrors the wolfSSL examples PSK identity/key protocol:
 * identity "Client_identity", key = 32 bytes {0x01,0x23,0x45,...}.
 */
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

static unsigned int psk_cb(WOLFSSL* ssl, const char* hint, char* identity,
    unsigned int id_max_len, unsigned char* key, unsigned int key_max_len)
{
    unsigned int i;
    unsigned char b = 0x01;
    (void)ssl; (void)hint;
    XSTRNCPY(identity, "Client_identity", id_max_len);
    for (i = 0; i < 32 && i < key_max_len; i++, b += 0x22) {
        if (b >= 0x100) b = 0x01;
        key[i] = b;
    }
    return i;
}

int main(int argc, char** argv)
{
    const char* host = "127.0.0.1";
    int port = 11111;
    SOCKET sock;
    WSADATA wsa;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    int shortTimeout = argc > 3 && strcmp(argv[3], "--short-timeout") == 0;
    int msgCount = 1;
    if (argc > 3) {
        if (strcmp(argv[3], "--short-timeout") == 0) {
            shortTimeout = 1;
            if (argc > 4) msgCount = atoi(argv[4]);
        } else {
            msgCount = atoi(argv[3]);
            if (argc > 4 && strcmp(argv[4], "--short-timeout") == 0)
                shortTimeout = 1;
        }
    }
    if (msgCount < 1) msgCount = 1;

    if (argc > 2) { host = argv[1]; port = atoi(argv[2]); }
    setvbuf(stdout, NULL, _IONBF, 0);
    WSAStartup(MAKEWORD(2,2), &wsa);
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL) { printf("ctx fail\n"); return 1; }
    wolfSSL_CTX_set_psk_client_callback(ctx, psk_cb);
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
        addr.sin_addr.s_addr = inet_addr(host);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("connect fail\n"); return 1;
        }
    }

    ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, (int)sock);
    /* Test-only guardrail: tell wolfSSL to treat would-block reads as
     * WANT_READ so the retry loops can bound the wait. */
    if (shortTimeout) {
        wolfSSL_dtls_set_using_nonblock(ssl, 1);
    }
    printf("initial cipher: %s\n", wolfSSL_get_cipher(ssl));
    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        printf("connect fail, err %d (%s)\n", err,
            wolfSSL_ERR_reason_error_string(err));
        return 1;
    }
    printf("HANDSHAKE OK. cipher: %s\n",
        wolfSSL_get_cipher(ssl));

    /* echo N messages (msgCount; default 1) */
    {
        char buf[64];
        const char* msg = "ascon-dtls test message";
        int i;
        for (i = 0; i < msgCount; i++) {
            wolfSSL_write(ssl, msg, (int)strlen(msg) + 1);
            {
                int tries = 0;
                do {
                    ret = wolfSSL_read(ssl, buf, sizeof(buf));
                    if (ret <= 0) {
                        int err = wolfSSL_get_error(ssl, ret);
                        if ((err == WOLFSSL_ERROR_WANT_READ ||
                             err == WOLFSSL_ERROR_WANT_WRITE) &&
                            tries++ < (shortTimeout ? 10 : 100)) {
                            Sleep(50);
                            continue;
                        }
                    }
                    break;
                } while (1);
            }
            if (ret > 0) printf("echo ok [%d]: %s\n", i, buf);
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
