#include <stdint.h>
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ascon.h"
#include "wolfssl/wolfcrypt/types.h"

#define REC_PT_SZ 32
#define REC_ITERS 3000
#define REC_MASK_ITERS 3000
#define ASCON_AD_SZ 13

static const byte trafficKey[ASCON_AEAD128_KEY_SZ] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10
};
static const byte snKey[ASCON_AEAD128_KEY_SZ] = {
    0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
    0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0
};
static const byte aad[ASCON_AD_SZ] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c };

static byte g_nonce[ASCON_AEAD128_NONCE_SZ];
static byte g_seq[8] = { 0 };

/* mimic the DTLS 1.3 16-byte nonce: 8 fixed bytes + 8-byte LE record number */
static void build_nonce(word32 seq)
{
    int i;
    for (i = 0; i < 8; i++) g_nonce[i] = (byte)(i);
    for (i = 0; i < 8; i++) g_seq[i] = (byte)(seq >> (8 * i));
    memcpy(g_nonce + 8, g_seq, 8);
}

void record_bench(void)
{
    word32 i;
    byte pt[REC_PT_SZ], ct[REC_PT_SZ], tag[ASCON_AEAD128_TAG_SZ], mask[16];
    double t0, t1, cyc, cycPer;
    int dropCount = 0;
    int ret;

    bench_xprintf("\n=== REC START ===\n");

    /* ---- per-record encrypt ---- */
    for (i = 0; i < REC_PT_SZ; i++) pt[i] = (byte)(i & 0xff);
    bench_xprintf("REC_ENC_START\n");
    t0 = bench_current_time(1);
    for (i = 0; i < REC_ITERS; i++) {
        wc_AsconAEAD128 a;
        build_nonce(i);
        wc_AsconAEAD128_Init(&a);
        wc_AsconAEAD128_SetKey(&a, trafficKey);
        wc_AsconAEAD128_SetNonce(&a, g_nonce);
        wc_AsconAEAD128_SetAD(&a, aad, sizeof(aad));
        wc_AsconAEAD128_EncryptUpdate(&a, ct, pt, REC_PT_SZ);
        wc_AsconAEAD128_EncryptFinal(&a, tag);
    }
    t1 = bench_current_time(0);
    cyc = (t1 - t0) * 32000000.0 / (double)REC_ITERS;
    cycPer = cyc / (double)REC_PT_SZ;
    bench_xprintf("ascon-record-encrypt: %.3f cyc/rec (%.3f cyc/byte)\n", cyc, cycPer);
    bench_xprintf("REC_ENC_DONE\n");

    /* ---- per-record decrypt + failed-auth -> KeyUpdate decision ---- */
    bench_xprintf("REC_DEC_START\n");
    t0 = bench_current_time(1);
    for (i = 0; i < REC_ITERS; i++) {
        wc_AsconAEAD128 a;
        build_nonce(i);
        wc_AsconAEAD128_Init(&a);
        wc_AsconAEAD128_SetKey(&a, trafficKey);
        wc_AsconAEAD128_SetNonce(&a, g_nonce);
        wc_AsconAEAD128_SetAD(&a, aad, sizeof(aad));
        wc_AsconAEAD128_DecryptUpdate(&a, pt, ct, REC_PT_SZ);
        ret = wc_AsconAEAD128_DecryptFinal(&a, tag);
        if (ret != 0) {
            dropCount++;
            if (dropCount > 1000) dropCount = 0; /* models forced-KeyUpdate */
        }
    }
    t1 = bench_current_time(0);
    cyc = (t1 - t0) * 32000000.0 / (double)REC_ITERS;
    cycPer = cyc / (double)REC_PT_SZ;
    bench_xprintf("ascon-record-decrypt: %.3f cyc/rec (%.3f cyc/byte)\n", cyc, cycPer);
    bench_xprintf("REC_DEC_DONE\n");

    /* ---- per-record number mask (keyed-sponge, Option B) ---- */
    bench_xprintf("REC_MASK_START\n");
    t0 = bench_current_time(1);
    for (i = 0; i < REC_MASK_ITERS; i++) {
        wc_AsconAEAD128 a;
        memset(ct, (byte)(i & 0xff), sizeof(ct));
        wc_AsconAEAD128_Init(&a);
        wc_AsconAEAD128_SetKey(&a, snKey);
        wc_AsconAEAD128_Mask(&a, ct, mask);
    }
    t1 = bench_current_time(0);
    cyc = (t1 - t0) * 32000000.0 / (double)REC_MASK_ITERS;
    bench_xprintf("ascon-record-mask: %.3f cyc/rec\n", cyc);
    bench_xprintf("REC_MASK_DONE\n");

    bench_xprintf("=== REC END ===\n");
}
