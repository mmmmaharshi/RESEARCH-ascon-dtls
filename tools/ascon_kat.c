/* picotls Ascon-AEAD128 KAT check vs ascon-c reference vectors (wolfSSL test_ascon_kats.h).
 * key = 000102030405060708090A0B0C0D0E0F, nonce = same, PT = "". */
#include <stdint.h>
#include <picotls/minicrypto.h>
#include <stdio.h>
#include <string.h>

static int hex2bin(const char *h, uint8_t *b, size_t max)
{
    size_t n = strlen(h) / 2;
    if (n > max) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        b[i] = (uint8_t)v;
    }
    return (int)n;
}

static int run(const char *ad_hex, const char *exp_hex)
{
    const uint8_t key[16]  = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    const uint8_t nonce[16]= {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t ad[16], exp[16], tag[16], out[16];
    int adlen = hex2bin(ad_hex, ad, sizeof(ad));
    int explen = hex2bin(exp_hex, exp, sizeof(exp));
    if (adlen < 0 || explen < 0) { printf("bad hex\n"); return 1; }

    fprintf(stderr, "AD=%-8s: new... ", ad_hex); fflush(stderr);
    ptls_aead_context_t *ctx = ptls_aead_new_direct(&ptls_minicrypto_asconaead128, 1, key, nonce);
    if (!ctx) { fprintf(stderr, "NEW FAILED\n"); return 1; }
    fprintf(stderr, "init... "); fflush(stderr);
    ptls_aead_encrypt_init(ctx, 0, ad, (size_t)adlen);
    fprintf(stderr, "update... "); fflush(stderr);
    ptls_aead_encrypt_update(ctx, out, (const void *)"", 0);
    fprintf(stderr, "final... "); fflush(stderr);
    size_t tlen = ptls_aead_encrypt_final(ctx, tag);
    fprintf(stderr, "done\n"); fflush(stderr);
    ptls_aead_free(ctx);

    printf("AD=%-8s tag=", ad_hex);
    for (size_t i = 0; i < tlen; i++) printf("%02X", tag[i]);
    int ok = (tlen == 16 && memcmp(tag, exp, 16) == 0);
    printf("   expected="); for (size_t i = 0; i < 16; i++) printf("%02X", exp[i]);
    printf("   %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main(void)
{
    int fails = 0;
    fails += run("",      "4427D64B8E1E1451FC445960F0839BB0");
    fails += run("00",    "103AB79D913A0321287715A979BB8585");
    fails += run("0001",  "A50E88E30F923B90A9C810181230DF10");
    fails += run("000102","AE214C9F66630658ED8DC7D31131174C");
    fails += run("00010203","C6FF3CF70575B144B955820D9BC7685E");
    printf("\n%s\n", fails ? "SOME KAT FAILED" : "ALL KAT PASS");
    return fails ? 1 : 0;
}
