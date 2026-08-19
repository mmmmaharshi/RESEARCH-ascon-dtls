#include <stdio.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
int main(void)
{
    WOLFSSL_CTX* ctx;
    int ret;
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL) { printf("ctx fail\n"); return 1; }
    ret = wolfSSL_CTX_set_cipher_list(ctx, "TLS13-ASCONAEAD128-ASCONHASH256");
    printf("set_cipher_list ret: %d\n", ret);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}
