#include <stdio.h>
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ascon.h"
int main(void){
  byte key[16]={0x92,0xdb,0x1a,0x56,0xb7,0x58,0xda,0x79,0x3c,0xcd,0x6a,0x51,0x55,0x74,0xb6,0xfb};
  byte nonce[16]={0xe1,0xc6,0x21,0x9f,0x1d,0xd5,0x9e,0x1a,0x98,0x53,0xf4,0xad,0x0e,0xb2,0xa6,0xc1};
  byte ad[5]={0x2e,0,0,0,0x1f}, pt[15]={8,0,0,2,0,2,0,0,0,0,0,2,0,0,0x16};
  byte ct[15], tag[16], out[15]; wc_AsconAEAD128 e,d; int r;
  wc_AsconAEAD128_Init(&e); wc_AsconAEAD128_SetKey(&e,key); wc_AsconAEAD128_SetNonce(&e,nonce); wc_AsconAEAD128_SetAD(&e,ad,5); r=wc_AsconAEAD128_EncryptUpdate(&e,ct,pt,15); r|=wc_AsconAEAD128_EncryptFinal(&e,tag); printf("enc %d\n",r);
  wc_AsconAEAD128_Init(&d); wc_AsconAEAD128_SetKey(&d,key); wc_AsconAEAD128_SetNonce(&d,nonce); wc_AsconAEAD128_SetAD(&d,ad,5); r=wc_AsconAEAD128_DecryptUpdate(&d,out,ct,15); r|=wc_AsconAEAD128_DecryptFinal(&d,tag); printf("dec %d equal %d\n",r,memcmp(pt,out,15)==0); return 0;
}
