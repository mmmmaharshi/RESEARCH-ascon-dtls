/* tls13_cert_client.c — minimal TLS 1.3 PKI client for suite 0x006E (TCP).
 * Loads RSA client cert/key + CA, verifies server, cipher 0x006E.
 * TCP adaptation of dtls13_cert_client.c. */
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

#define CERT_DIR "wolfssl/certs/"
#define CLIENT_CERT CERT_DIR "client-cert.pem"
#define CLIENT_KEY  CERT_DIR "client-key.pem"
#define CA_CERT     CERT_DIR "ca-cert.pem"

int main(int argc, char** argv)
{
    const char* host = "127.0.0.1";
    int port = 11111;
    SOCKET sock;
    WSADATA wsa;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;

    if (argc > 2) { host = argv[1]; port = atoi(argv[2]); }
    setvbuf(stdout, NULL, _IONBF, 0);
    WSAStartup(MAKEWORD(2,2), &wsa);
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) { printf("ctx fail\n"); return 1; }

    if (wolfSSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT) != WOLFSSL_SUCCESS) {
        printf("cert load fail\n"); return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        printf("key load fail\n"); return 1;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != WOLFSSL_SUCCESS) {
        printf("ca load fail\n"); return 1;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (wolfSSL_CTX_set_cipher_list(ctx,
            "TLS13-ASCONAEAD128-ASCONHASH256") != WOLFSSL_SUCCESS) {
        printf("cipher list fail\n"); return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { printf("socket fail\n"); return 1; }
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
    printf("initial cipher: %s\n", wolfSSL_get_cipher(ssl));
    ret = wolfSSL_connect(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, ret);
        printf("connect fail, err %d (%s)\n", err,
            wolfSSL_ERR_reason_error_string(err));
        return 1;
    }
    printf("HANDSHAKE OK. cipher: %s\n", wolfSSL_get_cipher(ssl));

    {
        char buf[64];
        const char* msg = "ascon-dtls cert message";
        wolfSSL_write(ssl, msg, (int)strlen(msg) + 1);
        {
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
        }
        if (ret > 0) printf("echo ok: %s\n", buf);
        else printf("echo fail, err %d\n", wolfSSL_get_error(ssl, ret));
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    closesocket(sock);
    WSACleanup();
    return 0;
}