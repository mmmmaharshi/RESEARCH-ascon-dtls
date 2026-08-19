#include <stdio.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/hmac.h"
int main(void) {
    int r = wc_HmacSizeByType(WC_ASCON_HASH256);
    printf("wc_HmacSizeByType(21): %d\n", r);
    return 0;
}
