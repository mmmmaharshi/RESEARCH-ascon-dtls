/* ascon.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_ASCON

#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/mask_prf.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/*
 * Implementation of the ASCON AEAD and HASH algorithms. Based on the NIST
 * Initial Public Draft "NIST SP 800-232 ipd" and reference implementation found
 * at https://github.com/ascon/ascon-c.
 */

/*
 * TODO
 * - Add support for big-endian systems
 * - Add support for 32-bit and smaller systems (WOLFSSL_ASCON_32BIT path below) */

#ifndef WORD64_AVAILABLE
    #error "Ascon implementation requires a 64-bit word"
#endif
#ifdef BIG_ENDIAN_ORDER
    #error "Ascon not yet supported on big-endian systems"
#endif

/* Data block size in bytes */
#define ASCON_HASH256_RATE                              8
#define ASCON_HASH256_ROUNDS                           12
#define ASCON_HASH256_IV            0x0000080100CC0002ULL

#define ASCON_AEAD128_ROUNDS_PA                        12
#define ASCON_AEAD128_ROUNDS_PB                         8
#define ASCON_AEAD128_IV            0x00001000808C0001ULL
#define ASCON_AEAD128_RATE                             16

#define MAX_ROUNDS 12

/* Canonical Ascon-p round constants — NIST SP 800-232 Table 5.
 * Unified spec for both 32- and 64-bit paths. Both decompose the same
 * 320-bit state and are verified bit-identical via KATs
 * (tools/ascon_kat.c, tools/verify_ascon_32bit.c, wolfCrypt test vectors).
 * 32-bit path expands each rotr64 into two rotr32; 64-bit path uses rotrFixed64. */
const byte ascon_round_constants[MAX_ROUNDS] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

#ifdef WOLFSSL_ASCON_32BIT

/*
 * 32-bit optimized Ascon permutation.
 *
 * On 32-bit-only cores (Cortex-M0+/M3, RV32) the 64-bit word operations in
 * the reference permutation expand to multi-instruction library sequences
 * (each rotrFixed64 costs ~6-8 native instructions).  This path decomposes
 * the 320-bit state into ten word32 lanes and computes the substitution and
 * linear-diffusion layers directly in 32-bit arithmetic.
 *
 * 64-bit rotation decomposition  (x = xh:xl, two word32 halves):
 *   r <  32:  lo' = (xl>>r) ^ (xh<<(32-r))
 *             hi' = (xh>>r) ^ (xl<<(32-r))
 *   r >= 32:  r' = r-32
 *             lo' = (xh>>r') ^ (xl<<(32-r'))
 *             hi' = (xl>>r') ^ (xh<<(32-r'))
 *
 * XOR replaces OR inside each rotation because the two shifted halves are
 * disjoint; the outer combination with the lane value is genuine XOR per
 * the Ascon linear-layer definition  out = x ^ rotr(x,a) ^ rotr(x,b).
 *
 * Produces bit-identical output to the 64-bit path -- verified against the
 * NIST SP 800-232 Ascon-Hash256 and Ascon-AEAD128 KATs.
 *
 * Round constants (Table 5 of the Ascon specification):
 *   p12: f0 e1 d2 c3 | b4 a5 96 87 78 69 5a 4b
 *   p8 :             b4 a5 96 87 78 69 5a 4b
 */

#define P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, c) do { \
    word32 t0l, t0h, t1l, t1h, t2l, t2h, t3l, t3h, t4l, t4h;           \
    /* Constant-addition layer */                                        \
    x2l ^= (word32)(c);                                                  \
    /* Substitution layer (5-input S-box, decomposed to 32-bit) */      \
    x0l ^= x4l;  x0h ^= x4h;                                            \
    x4l ^= x3l;  x4h ^= x3h;                                            \
    x2l ^= x1l;  x2h ^= x1h;                                            \
    t0l = x0l ^ (~x1l & x2l);  t0h = x0h ^ (~x1h & x2h);               \
    t2l = x2l ^ (~x3l & x4l);  t2h = x2h ^ (~x3h & x4h);               \
    t4l = x4l ^ (~x0l & x1l);  t4h = x4h ^ (~x0h & x1h);               \
    t1l = x1l ^ (~x2l & x3l);  t1h = x1h ^ (~x2h & x3h);               \
    t3l = x3l ^ (~x4l & x0l);  t3h = x3h ^ (~x4h & x0h);               \
    t1l ^= t0l;  t1h ^= t0h;                                            \
    t3l ^= t2l;  t3h ^= t2h;                                            \
    t0l ^= t4l;  t0h ^= t4h;                                            \
    t2l = ~t2l;  t2h = ~t2h;                                            \
    /* Linear diffusion layer (32-bit decomposition of rotr64) */        \
    /* x4: r=7 (<32), r=41 (r'=9) */                                     \
    x4l = t4l ^ (t4l >> 7) ^ (t4h << 25) ^ (t4h >> 9) ^ (t4l << 23);   \
    x4h = t4h ^ (t4h >> 7) ^ (t4l << 25) ^ (t4l >> 9) ^ (t4h << 23);   \
    /* x1: r=61 (r'=29), r=39 (r'=7) */                                  \
    x1l = t1l ^ (t1h >> 29) ^ (t1l << 3) ^ (t1h >> 7) ^ (t1l << 25);   \
    x1h = t1h ^ (t1l >> 29) ^ (t1h << 3) ^ (t1l >> 7) ^ (t1h << 25);   \
    /* x3: r=10, r=17 (both <32) */                                      \
    x3l = t3l ^ (t3l >> 10) ^ (t3l >> 17) ^ (t3h << 22) ^ (t3h << 15);  \
    x3h = t3h ^ (t3h >> 10) ^ (t3h >> 17) ^ (t3l << 22) ^ (t3l << 15);  \
    /* x0: r=19, r=28 (both <32) */                                      \
    x0l = t0l ^ (t0l >> 19) ^ (t0l >> 28) ^ (t0h << 13) ^ (t0h << 4);  \
    x0h = t0h ^ (t0h >> 19) ^ (t0h >> 28) ^ (t0l << 13) ^ (t0l << 4);  \
    /* x2: r=1, r=6 (both <32) */                                       \
    x2l = t2l ^ (t2l >> 1) ^ (t2l >> 6) ^ (t2h << 31) ^ (t2h << 26);   \
    x2h = t2h ^ (t2h >> 1) ^ (t2h >> 6) ^ (t2l << 31) ^ (t2l << 26);   \
} while (0)

#define P32_8(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h) do { \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[4]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[5]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[6]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[7]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[8]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[9]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[10]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[11]); \
} while (0)

#define P32_12(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h) do { \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[0]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[1]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[2]); \
    P32_ROUND(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h, ascon_round_constants[3]); \
    P32_8  (x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h);           \
} while (0)

/*
 * State is loaded into ten word32 locals, all rounds execute on registers
 * (spilling to stack as needed), and the result is stored back once.
 * The branch on `rounds` is resolved at compile time because every call
 * site passes a constant (ASCON_HASH256_ROUNDS=12 or ASCON_AEAD128_ROUNDS_PB=8).
 */
static void permutation(AsconState* a, byte rounds)
{
    word32 x0l = a->s32[0], x0h = a->s32[1];
    word32 x1l = a->s32[2], x1h = a->s32[3];
    word32 x2l = a->s32[4], x2h = a->s32[5];
    word32 x3l = a->s32[6], x3h = a->s32[7];
    word32 x4l = a->s32[8], x4h = a->s32[9];

    if (rounds == 12)
        P32_12(x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h);
    else
        P32_8 (x0l,x0h, x1l,x1h, x2l,x2h, x3l,x3h, x4l,x4h);

    a->s32[0] = x0l; a->s32[1] = x0h;
    a->s32[2] = x1l; a->s32[3] = x1h;
    a->s32[4] = x2l; a->s32[5] = x2h;
    a->s32[6] = x3l; a->s32[7] = x3h;
    a->s32[8] = x4l; a->s32[9] = x4h;
}

#else /* !WOLFSSL_ASCON_32BIT -- original 64-bit paths */

#ifndef WOLFSSL_ASCON_UNROLL

static byte start_index(byte rounds)
{
    switch (rounds) {
        case 8:
            return 4;
        case 12:
            return 0;
        default:
            WOLFSSL_MSG("Something went wrong in wolfCrypt logic. Wrong ASCON "
                        "rounds value.");
            return MAX_ROUNDS;
    }
}

static WC_INLINE void ascon_round(AsconState* a, byte round)
{
    word64 tmp0, tmp1, tmp2, tmp3, tmp4;
    /* 3.2 Constant-Addition Layer */
    a->s64[2] ^= ascon_round_constants[round];
    /* 3.3 Substitution Layer */
    a->s64[0] ^= a->s64[4];
    a->s64[4] ^= a->s64[3];
    a->s64[2] ^= a->s64[1];
    tmp0 = a->s64[0] ^ (~a->s64[1] & a->s64[2]);
    tmp2 = a->s64[2] ^ (~a->s64[3] & a->s64[4]);
    tmp4 = a->s64[4] ^ (~a->s64[0] & a->s64[1]);
    tmp1 = a->s64[1] ^ (~a->s64[2] & a->s64[3]);
    tmp3 = a->s64[3] ^ (~a->s64[4] & a->s64[0]);
    tmp1 ^= tmp0;
    tmp3 ^= tmp2;
    tmp0 ^= tmp4;
    tmp2 = ~tmp2;
    /* 3.4 Linear Diffusion Layer */
    a->s64[4] = tmp4 ^ rotrFixed64(tmp4,  7) ^ rotrFixed64(tmp4, 41);
    a->s64[1] = tmp1 ^ rotrFixed64(tmp1, 61) ^ rotrFixed64(tmp1, 39);
    a->s64[3] = tmp3 ^ rotrFixed64(tmp3, 10) ^ rotrFixed64(tmp3, 17);
    a->s64[0] = tmp0 ^ rotrFixed64(tmp0, 19) ^ rotrFixed64(tmp0, 28);
    a->s64[2] = tmp2 ^ rotrFixed64(tmp2,  1) ^ rotrFixed64(tmp2,  6);
}

static void permutation(AsconState* a, byte rounds)
{
    byte i = start_index(rounds);
    for (; i < MAX_ROUNDS; i++) {
        ascon_round(a, i);
    }
}

#else

#define p(a, c) do {                                                           \
    word64 tmp0, tmp1, tmp2, tmp3, tmp4;                                       \
    /* 3.2 Constant-Addition Layer */                                          \
    (a)->s64[2] ^= c;                                                          \
    /* 3.3 Substitution Layer */                                               \
    (a)->s64[0] ^= (a)->s64[4];                                                \
    (a)->s64[4] ^= (a)->s64[3];                                                \
    (a)->s64[2] ^= (a)->s64[1];                                                \
    tmp0 = (a)->s64[0] ^ (~(a)->s64[1] & (a)->s64[2]);                         \
    tmp2 = (a)->s64[2] ^ (~(a)->s64[3] & (a)->s64[4]);                         \
    tmp4 = (a)->s64[4] ^ (~(a)->s64[0] & (a)->s64[1]);                         \
    tmp1 = (a)->s64[1] ^ (~(a)->s64[2] & (a)->s64[3]);                         \
    tmp3 = (a)->s64[3] ^ (~(a)->s64[4] & (a)->s64[0]);                         \
    tmp1 ^= tmp0;                                                              \
    tmp3 ^= tmp2;                                                              \
    tmp0 ^= tmp4;                                                              \
    tmp2 = ~tmp2;                                                              \
    /* 3.4 Linear Diffusion Layer */                                           \
    (a)->s64[4] = tmp4 ^ rotrFixed64(tmp4,  7) ^ rotrFixed64(tmp4, 41);        \
    (a)->s64[1] = tmp1 ^ rotrFixed64(tmp1, 61) ^ rotrFixed64(tmp1, 39);        \
    (a)->s64[3] = tmp3 ^ rotrFixed64(tmp3, 10) ^ rotrFixed64(tmp3, 17);        \
    (a)->s64[0] = tmp0 ^ rotrFixed64(tmp0, 19) ^ rotrFixed64(tmp0, 28);        \
    (a)->s64[2] = tmp2 ^ rotrFixed64(tmp2,  1) ^ rotrFixed64(tmp2,  6);        \
} while (0)

#define p8(a) \
    p(a, ascon_round_constants[4]); \
    p(a, ascon_round_constants[5]); \
    p(a, ascon_round_constants[6]); \
    p(a, ascon_round_constants[7]); \
    p(a, ascon_round_constants[8]); \
    p(a, ascon_round_constants[9]); \
    p(a, ascon_round_constants[10]); \
    p(a, ascon_round_constants[11])

#define p12(a) \
    p(a, ascon_round_constants[0]); \
    p(a, ascon_round_constants[1]); \
    p(a, ascon_round_constants[2]); \
    p(a, ascon_round_constants[3]); \
    p8(a)

/* Needed layer to evaluate the macro values */
#define _permutation(a, rounds) \
    p ## rounds(a)

#define permutation(a, rounds) \
    _permutation(a, rounds)

#endif

#endif /* WOLFSSL_ASCON_32BIT */

/* AsconHash API */

wc_AsconHash256* wc_AsconHash256_New(void)
{
    wc_AsconHash256* ret = (wc_AsconHash256*)XMALLOC(sizeof(wc_AsconHash256),
            NULL, DYNAMIC_TYPE_ASCON);
    if (ret != NULL) {
        if (wc_AsconHash256_Init(ret) != 0) {
            wc_AsconHash256_Free(ret);
            ret = NULL;
        }
    }
    return ret;
}

void wc_AsconHash256_Free(wc_AsconHash256* a)
{
    if (a != NULL) {
        wc_AsconHash256_Clear(a);
        XFREE(a, NULL, DYNAMIC_TYPE_ASCON);
    }
}

int wc_AsconHash256_Init(wc_AsconHash256* a)
{
    if (a == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(a, 0, sizeof(*a));

    a->state.s64[0] = ASCON_HASH256_IV;
    permutation(&a->state, ASCON_HASH256_ROUNDS);

    return 0;
}

void wc_AsconHash256_Clear(wc_AsconHash256* a)
{
    if (a != NULL) {
        ForceZero(a, sizeof(*a));
    }
}

int wc_AsconHash256_Update(wc_AsconHash256* a, const byte* data, word32 dataSz)
{
    if (a == NULL || (data == NULL && dataSz != 0))
        return BAD_FUNC_ARG;

    if (dataSz == 0)
        return 0;

    /* Process leftover block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_HASH256_RATE - a->lastBlkSz, dataSz);
        xorbuf(a->state.s8 + a->lastBlkSz, data, toProcess);
        data += toProcess;
        dataSz -= toProcess;
        a->lastBlkSz += toProcess;

        if (a->lastBlkSz < ASCON_HASH256_RATE)
            return 0;

        permutation(&a->state, ASCON_HASH256_ROUNDS);
        /* Reset the counter */
        a->lastBlkSz = 0;
    }

    while (dataSz >= ASCON_HASH256_RATE) {
        /* Read in input as little endian numbers */
        xorbuf(a->state.s64, data, ASCON_HASH256_RATE);
        permutation(&a->state, ASCON_HASH256_ROUNDS);
        data += ASCON_HASH256_RATE;
        dataSz -= ASCON_HASH256_RATE;
    }

    xorbuf(a->state.s64, data, dataSz);
    a->lastBlkSz = dataSz;

    return 0;
}

int wc_AsconHash256_Final(wc_AsconHash256* a, byte* hash)
{
    byte i;

    if (a == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Process last block */
    a->state.s8[a->lastBlkSz] ^= 1;

    for (i = 0; i < ASCON_HASH256_SZ; i += ASCON_HASH256_RATE) {
        permutation(&a->state, ASCON_HASH256_ROUNDS);
        XMEMCPY(hash, a->state.s64, ASCON_HASH256_RATE);
        hash += ASCON_HASH256_RATE;
    }

    /* Reset state for reuse, matching the wolfSSL hash convention
     * (e.g. wc_Sha256Final -> InitSha256). The HMAC outer pass feeds
     * the opad into the same context after the inner Final; zeroing
     * here made every Ascon-HMAC with keys > 8 bytes compute its
     * inner/outer hashes from an all-zero (IV-less) state. */
    return wc_AsconHash256_Init(a);
}

/* AsconAEAD API */

wc_AsconAEAD128* wc_AsconAEAD128_New(void)
{
    wc_AsconAEAD128 *ret = (wc_AsconAEAD128*) XMALLOC(sizeof(wc_AsconAEAD128),
            NULL, DYNAMIC_TYPE_ASCON);
    if (ret != NULL) {
        if (wc_AsconAEAD128_Init(ret) != 0) {
            wc_AsconAEAD128_Free(ret);
            ret = NULL;
        }
    }
    return ret;
}

void wc_AsconAEAD128_Free(wc_AsconAEAD128 *a)
{
    if (a != NULL) {
        wc_AsconAEAD128_Clear(a);
        XFREE(a, NULL, DYNAMIC_TYPE_ASCON);
    }
}

int wc_AsconAEAD128_Init(wc_AsconAEAD128 *a)
{
    if (a == NULL)
        return BAD_FUNC_ARG;

#ifdef WORD64_AVAILABLE
    /* Preserve the per-epoch IV across the reset: the TLS 1.3 record layer
     * (BuildTls13Nonce) reads a->iv once per record, and this Init runs once
     * per record, so wiping it here zeroes every record's IV after seq 0. */
    word64 iv0 = a->iv[0];
    word64 iv1 = a->iv[1];
#endif
    XMEMSET(a, 0, sizeof(*a));
#ifdef WORD64_AVAILABLE
    a->iv[0] = iv0;
    a->iv[1] = iv1;
#endif
    a->state.s64[0] = ASCON_AEAD128_IV;

    return 0;
}

void wc_AsconAEAD128_Clear(wc_AsconAEAD128 *a)
{
    if (a != NULL) {
        ForceZero(a, sizeof(*a));
    }
}

int wc_AsconAEAD128_SetKey(wc_AsconAEAD128* a, const byte* key)
{
    if (a == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (a->keySet)
        return BAD_STATE_E;

    XMEMCPY(a->key, key, ASCON_AEAD128_KEY_SZ);
    a->state.s64[1] = a->key[0];
    a->state.s64[2] = a->key[1];
    a->keySet = 1;

    return 0;
}

int wc_AsconAEAD128_SetNonce(wc_AsconAEAD128* a, const byte* nonce)
{
    if (a == NULL || nonce == NULL)
        return BAD_FUNC_ARG;
    if (a->nonceSet)
        return BAD_STATE_E;

    XMEMCPY(&a->state.s64[3], nonce, ASCON_AEAD128_NONCE_SZ);
    a->nonceSet = 1;

    return 0;
}

int wc_AsconAEAD128_SetAD(wc_AsconAEAD128* a, const byte* ad,
                                      word32 adSz)
{
    if (a == NULL || (ad == NULL && adSz > 0))
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet) /* key and nonce must be set before */
        return BAD_STATE_E;

    permutation(&a->state, ASCON_AEAD128_ROUNDS_PA);
    a->state.s64[3] ^= a->key[0];
    a->state.s64[4] ^= a->key[1];

    if (adSz > 0) {
        while (adSz >= ASCON_AEAD128_RATE) {
            xorbuf(a->state.s64, ad, ASCON_AEAD128_RATE);
            permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
            ad += ASCON_AEAD128_RATE;
            adSz -= ASCON_AEAD128_RATE;
        }
        xorbuf(a->state.s64, ad, adSz);
        /* Pad the last block */
        a->state.s8[adSz] ^= 1;
        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
    }
    a->state.s64[4] ^= 1ULL << 63;

    a->adSet = 1;
    return 0;
}

int wc_AsconAEAD128_EncryptUpdate(wc_AsconAEAD128* a, byte* out,
                                  const byte* in, word32 inSz)
{
    if (a == NULL || (in == NULL && inSz > 0))
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op == ASCON_AEAD128_NOTSET)
        a->op = ASCON_AEAD128_ENCRYPT;
    else if (a->op != ASCON_AEAD128_ENCRYPT)
        return BAD_STATE_E;

    /* Process leftover from last block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_AEAD128_RATE - a->lastBlkSz, inSz);
        xorbuf(&a->state.s8[a->lastBlkSz], in, toProcess);
        XMEMCPY(out, &a->state.s8[a->lastBlkSz], toProcess);
        a->lastBlkSz += toProcess;
        in += toProcess;
        out += toProcess;
        inSz -= toProcess;

        if (a->lastBlkSz < ASCON_AEAD128_RATE)
            return 0;

        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        a->lastBlkSz = 0;
    }

    while (inSz >= ASCON_AEAD128_RATE) {
        xorbuf(a->state.s64, in, ASCON_AEAD128_RATE);
        XMEMCPY(out, a->state.s64, ASCON_AEAD128_RATE);
        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        inSz -= ASCON_AEAD128_RATE;
    }
    /* Store leftover */
    xorbuf(a->state.s64, in, inSz);
    XMEMCPY(out, a->state.s64, inSz);
    a->lastBlkSz = inSz;

    return 0;
}


int wc_AsconAEAD128_EncryptFinal(wc_AsconAEAD128* a, byte* tag)
{
    if (a == NULL || tag == NULL)
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op != ASCON_AEAD128_ENCRYPT)
        return BAD_STATE_E;

    /* Process leftover from last block */
    a->state.s8[a->lastBlkSz] ^= 1;

    a->state.s64[2] ^= a->key[0];
    a->state.s64[3] ^= a->key[1];
    permutation(&a->state, ASCON_AEAD128_ROUNDS_PA);
    a->state.s64[3] ^= a->key[0];
    a->state.s64[4] ^= a->key[1];

    XMEMCPY(tag, &a->state.s64[3], ASCON_AEAD128_TAG_SZ);

    /* Keep the activated key/iv: the record layer snapshots them from the
     * context for the next record (tls13.c). The sponge state is wiped by
     * the per-record Init. */

    return 0;

}


int wc_AsconAEAD128_DecryptUpdate(wc_AsconAEAD128* a, byte* out,
                                  const byte* in, word32 inSz)
{
    byte ct[ASCON_AEAD128_RATE];

    if (a == NULL || (in == NULL && inSz > 0))
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op == ASCON_AEAD128_NOTSET)
        a->op = ASCON_AEAD128_DECRYPT;
    else if (a->op != ASCON_AEAD128_DECRYPT)
        return BAD_STATE_E;

    /* Process leftover block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_AEAD128_RATE - a->lastBlkSz, inSz);
        /* Preserve ciphertext for in-place record decryption. */
        XMEMCPY(ct, in, toProcess);
        xorbufout(out, a->state.s8 + a->lastBlkSz, ct, toProcess);
        XMEMCPY(a->state.s8 + a->lastBlkSz, ct, toProcess);
        in += toProcess;
        out += toProcess;
        inSz -= toProcess;
        a->lastBlkSz += toProcess;

        if (a->lastBlkSz < ASCON_AEAD128_RATE)
            return 0;

        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        a->lastBlkSz = 0;
    }

    while (inSz >= ASCON_AEAD128_RATE) {
        XMEMCPY(ct, in, ASCON_AEAD128_RATE);
        xorbufout(out, a->state.s64, ct, ASCON_AEAD128_RATE);
        XMEMCPY(a->state.s64, ct, ASCON_AEAD128_RATE);
        permutation(&a->state, ASCON_AEAD128_ROUNDS_PB);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        inSz -= ASCON_AEAD128_RATE;
    }
    /* Store leftover */
    XMEMCPY(ct, in, inSz);
    xorbufout(out, a->state.s64, ct, inSz);
    XMEMCPY(a->state.s64, ct, inSz);
    a->lastBlkSz = inSz;

    return 0;
}

int wc_AsconAEAD128_DecryptFinal(wc_AsconAEAD128* a, const byte* tag)
{
    int ret = 0;

    if (a == NULL || tag == NULL)
        return BAD_FUNC_ARG;
    if (!a->keySet || !a->nonceSet || !a->adSet)
        return BAD_STATE_E;

    if (a->op != ASCON_AEAD128_DECRYPT)
        return BAD_STATE_E;

    /* Pad last block */
    a->state.s8[a->lastBlkSz] ^= 1;

    a->state.s64[2] ^= a->key[0];
    a->state.s64[3] ^= a->key[1];
    permutation(&a->state, ASCON_AEAD128_ROUNDS_PA);
    a->state.s64[3] ^= a->key[0];
    a->state.s64[4] ^= a->key[1];

    if (ConstantCompare(tag, (const byte*)&a->state.s64[3],
                        ASCON_AEAD128_TAG_SZ) != 0) {
        ret = ASCON_AUTH_E;
    }

    /* Keep the activated key/iv: the record layer snapshots them from the
     * context for the next record (tls13.c). The sponge state is wiped by
     * the per-record Init. */

    return ret;
}

/* Keyed-sponge record number mask (DTLS 1.3 record-number encryption).
 *
 * Design (ascon-dtls design-01-record-layer.md section 4.2.1, Option B):
 *   S = sn_key(128) || ct[0..15](128) || domsep(64)
 *   mask = first 16 bytes of Ascon-P^12(S)
 * Domain-separation constant: ASCII "RNDIMSK_" (distinct from all Ascon
 * IVs: AEAD IV = 0x80400c0600000000, Hash IV = 0xee9398aadb67f03d).
 * Security argument (keyed sponge PRF): see design doc section 6 (T2),
 * bounds q^2/2^192 + q/2^128 for q queries.
 */
int wc_AsconAEAD128_Mask(wc_AsconAEAD128* a, const byte* ciphertext, byte* mask)
{
    if (a == NULL || ciphertext == NULL || mask == NULL)
        return BAD_FUNC_ARG;
    if (!a->keySet)
        return BAD_STATE_E;
    /* Thin wrapper — canonical PRF lives in mask_prf.c (colocated). */
    return mask_prf_derive((const uint8_t*)a->key, ciphertext, mask,
                           mask_prf_domsep_table[MASK_PRF_DTLS]);
}
#endif /* HAVE_ASCON */
