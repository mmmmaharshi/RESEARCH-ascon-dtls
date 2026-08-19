/* tls13_cert_server.c — minimal TLS 1.3 PKI server for suite 0x006E (TCP).
 * Loads RSA server cert/key + CA, requires a client cert, cipher 0x006E.
 * TCP adaptation of dtls13_cert_server.c (listen + accept one connection). */
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"

#define CERT_DIR "wolfssl/certs/"
#define SERVER_CERT CERT_DIR "server-cert.pem"
#define SERVER_KEY  CERT_DIR "server-key.pem"
#define CA_CERT     CERT_DIR "ca-cert.pem"
#define CLIENT_CA_CERT CERT_DIR "client-ca-cert.pem"

int main(int argc, char** argv)
{
    int port = 11111;
    SOCKET sock, csock;
    WSADATA wsa;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;

    if (argc > 1) port = atoi(argv[1]);
    setvbuf(stdout, NULL, _IONBF, 0);
    WSAStartup(MAKEWORD(2,2), &wsa);
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) { printf("ctx fail\n"); return 1; }

    if (wolfSSL_CTX_use_certificate_chain_file(ctx, SERVER_CERT) != WOLFSSL_SUCCESS) {
        printf("cert load fail\n"); return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        printf("key load fail\n"); return 1;
    }
    if (wolfSSL_CTX_check_private_key(ctx) != WOLFSSL_SUCCESS) {
        printf("key mismatch\n"); return 1;
    }
    if (wolfSSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != WOLFSSL_SUCCESS) {
        printf("ca load fail\n"); return 1;
    }
    /* Also trust the CA that signed the client cert (wolfSSL_2048, not Sawtooth) */
    if (wolfSSL_CTX_load_verify_locations(ctx, CLIENT_CA_CERT, NULL) != WOLFSSL_SUCCESS) {
        printf("client-ca load fail\n"); return 1;
    }
    wolfSSL_CTX_set_verify(ctx,
        WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
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
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            printf("bind fail\n"); return 1;
        }
    }
    if (listen(sock, 1) < 0) { printf("listen fail\n"); return 1; }
    csock = accept(sock, NULL, NULL);
    if (csock == INVALID_SOCKET) { printf("accept fail\n"); return 1; }
    printf("accepted on port %d sock=%llu\n", port, (unsigned long long)csock);

    ssl = wolfSSL_new(ctx);
    wolfSSL_set_fd(ssl, (int)csock);
    ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        printf("accept fail, err %d (%s)\n",
            wolfSSL_get_error(ssl, ret),
            wolfSSL_ERR_reason_error_string(wolfSSL_get_error(ssl, ret)));
        return 1;
    }
    printf("HANDSHAKE OK. cipher: %s\n", wolfSSL_get_cipher(ssl));

    {
        char buf[64];
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
        else printf("read fail, err %d\n", wolfSSL_get_error(ssl, ret));
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    closesocket(csock);
    closesocket(sock);
    WSACleanup();
    return 0;
}