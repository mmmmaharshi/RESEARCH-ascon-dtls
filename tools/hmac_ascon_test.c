#include <stdio.h>
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/hmac.h"
int main(void)
{
    Hmac h;
    byte key[32], out[32];
    int ret, i;
    memset(key, 0x11, sizeof(key));
    memset(out, 0, sizeof(out));
    ret = wc_HmacInit(&h, NULL, INVALID_DEVID);
    printf("Init: %d\n", ret);
    ret = wc_HmacSetKey(&h, WC_ASCON_HASH256, key, 32);
    printf("SetKey: %d\n", ret);
    ret = wc_HmacUpdate(&h, (const byte*)"hello", 5);
    printf("Update: %d\n", ret);
    ret = wc_HmacFinal(&h, out);
    printf("Final: %d\n", ret);
    for (i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    wc_HmacFree(&h);
    return 0;
}
