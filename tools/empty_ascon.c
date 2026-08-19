#include <stdio.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ascon.h"
int main(void)
{
    byte out[32];
    int i;
    wc_AsconHash256 h;
    wc_AsconHash256_Init(&h);
    wc_AsconHash256_Final(&h, out);
    for (i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
