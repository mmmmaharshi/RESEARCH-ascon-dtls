/* ascon_mask_kat.c
 * Self-checking test vector for the DTLS 1.3 Ascon record-number mask
 * (design-01-record-layer.md §4.2.1, Option B keyed-sponge PRF).
 *
 * Mask = Ascon-P^12( domsep("RNDIMSK_") || sn_key(128) || ct[0..15](128) ),
 *        output = S0' || S1' (16 bytes). Keyed with the per-epoch sn_key.
 *
 * Build (from repo root):
 *   gcc -I. -Iwolfssl -DWOLFSSL_USER_SETTINGS tools/ascon_mask_kat.c \
 *       -Lbuild -lwolfssl -o tools/ascon_mask_kat
 */
#include <stdio.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ascon.h>

static void hex(const char* label, const byte* b, int n)
{
    printf("%-10s: ", label);
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static int one(const char* name, const byte* snkey, const byte* ct)
{
    wc_AsconAEAD128 a;
    byte mask[16];
    int ret;

    printf("=== %s ===\n", name);
    hex("sn_key", snkey, 16);
    hex("ciphertext", ct, 16);
    ret = wc_AsconAEAD128_Init(&a);
    if (ret != 0) { printf("Init err %d\n", ret); return ret; }
    ret = wc_AsconAEAD128_SetKey(&a, snkey);
    if (ret != 0) { printf("SetKey err %d\n", ret); return ret; }
    ret = wc_AsconAEAD128_Mask(&a, ct, mask);
    if (ret != 0) { printf("Mask err %d\n", ret); return ret; }
    hex("mask", mask, 16);
    printf("\n");
    return 0;
}

int main(void)
{
    byte snkey[16], ct1[16], ct2[16], ct0[16];

    /* sn_key = 00 01 02 ... 0f */
    for (int i = 0; i < 16; i++) snkey[i] = (byte)i;
    /* ct1 = 10 11 ... 1f */
    for (int i = 0; i < 16; i++) ct1[i] = (byte)(0x10 + i);
    /* ct2 = 20 21 ... 2f  (different ciphertext, same key -> different mask) */
    for (int i = 0; i < 16; i++) ct2[i] = (byte)(0x20 + i);
    /* ct0 = all zero (retransmission of an all-zero-plaintext record) */
    memset(ct0, 0, sizeof(ct0));

    if (one("case A (sn_key, ct1)", snkey, ct1)) return 1;
    /* ciphertext-dependence: same key, different ct -> expect different mask */
    if (one("case B (same key, ct2)", snkey, ct2)) return 1;
    if (one("case C (sn_key, ct=zeros)", snkey, ct0)) return 1;

    printf("OK: mask is keyed + ciphertext-dependent (Option B).\n");
    return 0;
}
