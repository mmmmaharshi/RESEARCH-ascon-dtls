#include <stdio.h>
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ascon.h"
int main(void){byte k[16]={1},n[16]={2},ad[5]={3},b[15]={4},tag[16];wc_AsconAEAD128 e,d;int r;wc_AsconAEAD128_Init(&e);wc_AsconAEAD128_SetKey(&e,k);wc_AsconAEAD128_SetNonce(&e,n);wc_AsconAEAD128_SetAD(&e,ad,5);wc_AsconAEAD128_EncryptUpdate(&e,b,b,15);wc_AsconAEAD128_EncryptFinal(&e,tag);wc_AsconAEAD128_Init(&d);wc_AsconAEAD128_SetKey(&d,k);wc_AsconAEAD128_SetNonce(&d,n);wc_AsconAEAD128_SetAD(&d,ad,5);r=wc_AsconAEAD128_DecryptUpdate(&d,b,b,15);r|=wc_AsconAEAD128_DecryptFinal(&d,tag);printf("inplace dec %d\n",r);return 0;}
