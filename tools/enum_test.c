#include <stdio.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/hmac.h"
int main(void) {
    printf("WC_ASCON_HASH256=%d\n", (int)WC_ASCON_HASH256);
    printf("WC_HASH_TYPE_ASCON_HASH256=%d\n", (int)WC_HASH_TYPE_ASCON_HASH256);
    return 0;
}
