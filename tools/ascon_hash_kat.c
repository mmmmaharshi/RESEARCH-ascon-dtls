#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "picotls.h"
#include "picotls/minicrypto.h"

static const char *EXP[5] = {
    "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2",
    "0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80",
    "6115E7C9C4081C2797FC8FE1BC57A836AFA1C5381E556DD583860CA2DFB48DD2",
    "265AB89A609F5A05DCA57E83FBBA700F9A2D2C4211BA4CC9F0A1A369E17B915C",
    "D7E4C7ED9B8A325CD08B9EF259F8877054ECD8304FE1B2D7FD847137DF6727EE",
};

static void hex(const uint8_t *b, size_t n, char *o)
{
    static const char *h = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = h[b[i] >> 4];
        o[2 * i + 1] = h[b[i] & 0xf];
    }
    o[2 * n] = '\0';
}

int main(void)
{
    int fail = 0;
    for (int i = 0; i < 5; i++) {
        uint8_t msg[8];
        for (int k = 0; k < i; k++)
            msg[k] = (uint8_t)k;
        ptls_hash_context_t *h = ptls_ascon_hash256.create();
        h->update(h, msg, (size_t)i);
        uint8_t out[32];
        h->final(h, out, PTLS_HASH_FINAL_MODE_FREE);
        char got[65];
        hex(out, 32, got);
        int ok = strcmp(got, EXP[i]) == 0;
        if (!ok)
            fail++;
        printf("i=%d %s %s\n", i, got, ok ? "PASS" : "FAIL");
    }
    printf(fail ? "HASH KAT FAIL\n" : "HASH KAT ALL PASS\n");
    return fail ? 1 : 0;
}
