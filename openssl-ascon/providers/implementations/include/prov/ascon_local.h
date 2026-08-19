/*
 * Ascon core for the OpenSSL default provider (experimental).
 *
 * Byte-exact port of the wolfSSL reference implementation
 * (wolfcrypt/src/ascon.c, commit 9fd500a) which is itself bit-exact against
 * the ascon-c reference vectors (R8 KAT cross-check). Do NOT "simplify".
 *
 *   - Ascon-Hash256: rate 8, IV 0x0000080100CC0002, 12 rounds
 *   - Ascon-AEAD128: rate 16, IV 0x00001000808C0001, PA=12/PB=8
 *   - Round constants are XORed into the LOW byte of word x2 (wolfSSL quirk,
 *     matches picotls). All words loaded/stored little-endian via memcpy on
 *     the (little-endian) build targets.
 */

#ifndef OSSL_PROV_ASCON_LOCAL_H
# define OSSL_PROV_ASCON_LOCAL_H
# pragma once

# include <stddef.h>
# include <stdint.h>
# include <string.h>

# define ASCON_MAX_ROUNDS 12
# define ASCON_HASH256_RATE 8
# define ASCON_HASH256_ROUNDS 12
# define ASCON_AEAD128_RATE 16
# define ASCON_AEAD128_PA 12
# define ASCON_AEAD128_PB 8

static const uint8_t ascon_round_constants[ASCON_MAX_ROUNDS] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b
};

static inline uint64_t ascon_rotr64(uint64_t x, uint8_t n)
{
    return (x >> n) | (x << (64 - n));
}

static inline void ascon_round(uint64_t s[5], uint8_t round)
{
    uint64_t t0, t1, t2, t3, t4;

    s[2] ^= ascon_round_constants[round];
    s[0] ^= s[4];
    s[4] ^= s[3];
    s[2] ^= s[1];
    t0 = s[0] ^ (~s[1] & s[2]);
    t2 = s[2] ^ (~s[3] & s[4]);
    t4 = s[4] ^ (~s[0] & s[1]);
    t1 = s[1] ^ (~s[2] & s[3]);
    t3 = s[3] ^ (~s[4] & s[0]);
    t1 ^= t0;
    t3 ^= t2;
    t0 ^= t4;
    t2 = ~t2;
/* Linear diffusion: wolfSSL/picotls quirk variant - each output word is
     * built from rotations of its OWN S-box temp (t4->s4, t1->s1, t3->s3,
     * t0->s0, t2->s2), NOT the cross-word pattern of the ascon-c reference.
     * Byte-exact with wolfSSL ascon.c (commit 9fd500a). */
    s[4] = t4 ^ ascon_rotr64(t4, 7) ^ ascon_rotr64(t4, 41);
    s[1] = t1 ^ ascon_rotr64(t1, 61) ^ ascon_rotr64(t1, 39);
    s[3] = t3 ^ ascon_rotr64(t3, 10) ^ ascon_rotr64(t3, 17);
    s[0] = t0 ^ ascon_rotr64(t0, 19) ^ ascon_rotr64(t0, 28);
    s[2] = t2 ^ ascon_rotr64(t2, 1) ^ ascon_rotr64(t2, 6);
}

static inline void ascon_permute(uint64_t s[5], uint8_t rounds)
{
    uint8_t i = (rounds == 8) ? 4 : 0;

    for (; i < ASCON_MAX_ROUNDS; i++)
        ascon_round(s, i);
}

/* ==================== Ascon-Hash256 ==================== */

typedef struct {
    uint64_t s[5];
    uint8_t lastBlkSz;
} ASCON_HASH256_CTX;

static inline void ascon_hash256_core_init(ASCON_HASH256_CTX *h)
{
    memset(h, 0, sizeof(*h));
    h->s[0] = UINT64_C(0x0000080100CC0002);
    ascon_permute(h->s, ASCON_HASH256_ROUNDS);
}

static inline void ascon_hash256_core_update(ASCON_HASH256_CTX *h,
                                        const uint8_t *data, size_t dataSz)
{
    size_t n;

    while (dataSz > 0) {
        n = ASCON_HASH256_RATE - h->lastBlkSz;
        if (n > dataSz)
            n = dataSz;
        for (size_t i = 0; i < n; i++)
            ((uint8_t *)h->s)[h->lastBlkSz + i] ^= data[i];
        h->lastBlkSz += (uint8_t)n;
        data += n;
        dataSz -= n;
        if (h->lastBlkSz == ASCON_HASH256_RATE) {
            ascon_permute(h->s, ASCON_HASH256_ROUNDS);
            h->lastBlkSz = 0;
        }
    }
}

static inline void ascon_hash256_core_final(ASCON_HASH256_CTX *h, uint8_t out[32])
{
    ((uint8_t *)h->s)[h->lastBlkSz] ^= 0x01;
    for (size_t i = 0; i < 32; i += ASCON_HASH256_RATE) {
        ascon_permute(h->s, ASCON_HASH256_ROUNDS);
        memcpy(out + i, h->s, ASCON_HASH256_RATE);
    }
}

/* ==================== Ascon-AEAD128 ==================== */

typedef struct {
    uint64_t s[5];
    uint64_t key[2];
    uint8_t adPart[ASCON_AEAD128_RATE];
    uint8_t ct[ASCON_AEAD128_RATE];
    uint8_t tag[16];           /* expected (decrypt) / computed (encrypt) */
    uint8_t lastBlkSz;         /* partial plaintext/ciphertext block size */
    uint8_t adPartSz;
    uint8_t enc;               /* 1 = encrypt, 0 = decrypt */
    uint8_t adStarted;         /* PA + key xors applied */
    uint8_t adDone;            /* AD padded + domain separation applied */
} ASCON_AEAD128_CTX;

static inline void ascon_aead128_reset(ASCON_AEAD128_CTX *a,
                                       const uint8_t *key, const uint8_t *nonce)
{
    memset(&a->s, 0, sizeof(a->s));
    memcpy(a->key, key, 16);
    a->s[0] = UINT64_C(0x00001000808C0001);
    memcpy(&a->s[1], key, 8);
    memcpy(&a->s[2], key + 8, 8);
    memcpy(&a->s[3], nonce, 8);
    memcpy(&a->s[4], nonce + 8, 8);
    a->lastBlkSz = 0;
    a->adPartSz = 0;
    a->adStarted = 0;
    a->adDone = 0;
    /*
     * Must clear the AD/CT scratch buffers: aad_finalize XORs the padding
     * byte (adPart[adPartSz] ^= 0x01), so a stale 0x01 left at the pad
     * position by a previous record would cancel it and corrupt the tag.
     */
    memset(a->adPart, 0, sizeof(a->adPart));
    memset(a->ct, 0, sizeof(a->ct));
}

/* Begin AD (if not already begun): PA + key xors, then absorb. Streaming. */
static inline void ascon_aead128_absorb_aad(ASCON_AEAD128_CTX *a,
                                            const uint8_t *ad, size_t adSz)
{
    size_t n;

    if (!a->adStarted) {
        ascon_permute(a->s, ASCON_AEAD128_PA);
        a->s[3] ^= a->key[0];
        a->s[4] ^= a->key[1];
        a->adStarted = 1;
    }
    /* absorb buffered partial + new input */
    while (a->adPartSz > 0 && adSz > 0) {
        n = ASCON_AEAD128_RATE - a->adPartSz;
        if (n > adSz)
            n = adSz;
        memcpy(a->adPart + a->adPartSz, ad, n);
        a->adPartSz += (uint8_t)n;
        ad += n;
        adSz -= n;
        if (a->adPartSz == ASCON_AEAD128_RATE) {
            for (size_t i = 0; i < 2; i++)
                a->s[i] ^= ((const uint64_t *)a->adPart)[i];
            ascon_permute(a->s, ASCON_AEAD128_PB);
            a->adPartSz = 0;
        }
    }
    while (adSz >= ASCON_AEAD128_RATE) {
        for (size_t i = 0; i < 2; i++)
            a->s[i] ^= ((const uint64_t *)ad)[i];
        ascon_permute(a->s, ASCON_AEAD128_PB);
        ad += ASCON_AEAD128_RATE;
        adSz -= ASCON_AEAD128_RATE;
    }
    if (adSz > 0) {
        memcpy(a->adPart, ad, adSz);
        a->adPartSz = (uint8_t)adSz;
    }
}

/* Close AD: pad (if any) + domain separation. wolfSSL: no PB for empty AD. */
static inline void ascon_aead128_aad_finalize(ASCON_AEAD128_CTX *a)
{
    if (a->adDone)
        return;
    if (!a->adStarted) {
        ascon_permute(a->s, ASCON_AEAD128_PA);
        a->s[3] ^= a->key[0];
        a->s[4] ^= a->key[1];
    }
    if (a->adPartSz > 0) {
        a->adPart[a->adPartSz] ^= 0x01;
        for (size_t i = 0; i < 2; i++)
            a->s[i] ^= ((const uint64_t *)a->adPart)[i];
        ascon_permute(a->s, ASCON_AEAD128_PB);
        a->adPartSz = 0;
    }
    a->s[4] ^= UINT64_C(1) << 63;
    a->adDone = 1;
}

/* Streaming encrypt (mirrors wolfSSL EncryptUpdate). Returns bytes written. */
static inline size_t ascon_aead128_encrypt_update(ASCON_AEAD128_CTX *a,
                                                  uint8_t *out,
                                                  const uint8_t *in,
                                                  size_t inSz)
{
    size_t n, total = 0;

    ascon_aead128_aad_finalize(a);
    if (a->lastBlkSz > 0) {
        n = ASCON_AEAD128_RATE - a->lastBlkSz;
        if (n > inSz)
            n = inSz;
        for (size_t i = 0; i < n; i++) {
            ((uint8_t *)a->s)[a->lastBlkSz + i] ^= in[i];
            out[i] = ((uint8_t *)a->s)[a->lastBlkSz + i];
        }
        a->lastBlkSz += (uint8_t)n;
        in += n;
        out += n;
        inSz -= n;
        total += n;
        if (a->lastBlkSz == ASCON_AEAD128_RATE) {
            ascon_permute(a->s, ASCON_AEAD128_PB);
            a->lastBlkSz = 0;
        }
    }
    while (inSz >= ASCON_AEAD128_RATE) {
        for (size_t i = 0; i < 2; i++) {
            a->s[i] ^= ((const uint64_t *)in)[i];
            ((uint64_t *)out)[i] = a->s[i];
        }
        ascon_permute(a->s, ASCON_AEAD128_PB);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        inSz -= ASCON_AEAD128_RATE;
        total += ASCON_AEAD128_RATE;
    }
    if (inSz > 0) {
        for (size_t i = 0; i < inSz; i++) {
            ((uint8_t *)a->s)[i] ^= in[i];
            out[i] = ((uint8_t *)a->s)[i];
        }
        a->lastBlkSz = (uint8_t)inSz;
        total += inSz;
    }
    return total;
}

/* Streaming decrypt (mirrors wolfSSL DecryptUpdate). Returns bytes written. */
static inline size_t ascon_aead128_decrypt_update(ASCON_AEAD128_CTX *a,
                                                  uint8_t *out,
                                                  const uint8_t *in,
                                                  size_t inSz)
{
    size_t n, total = 0;

    ascon_aead128_aad_finalize(a);
    if (a->lastBlkSz > 0) {
        n = ASCON_AEAD128_RATE - a->lastBlkSz;
        if (n > inSz)
            n = inSz;
        memcpy(a->ct, in, n);
        for (size_t i = 0; i < n; i++) {
            out[i] = ((uint8_t *)a->s)[a->lastBlkSz + i] ^ a->ct[i];
            ((uint8_t *)a->s)[a->lastBlkSz + i] = a->ct[i];
        }
        a->lastBlkSz += (uint8_t)n;
        in += n;
        out += n;
        inSz -= n;
        total += n;
        if (a->lastBlkSz == ASCON_AEAD128_RATE) {
            ascon_permute(a->s, ASCON_AEAD128_PB);
            a->lastBlkSz = 0;
        }
    }
    while (inSz >= ASCON_AEAD128_RATE) {
        memcpy(a->ct, in, ASCON_AEAD128_RATE);
        for (size_t i = 0; i < 2; i++) {
            ((uint64_t *)out)[i] = a->s[i] ^ ((const uint64_t *)a->ct)[i];
            a->s[i] = ((const uint64_t *)a->ct)[i];
        }
        ascon_permute(a->s, ASCON_AEAD128_PB);
        in += ASCON_AEAD128_RATE;
        out += ASCON_AEAD128_RATE;
        inSz -= ASCON_AEAD128_RATE;
        total += ASCON_AEAD128_RATE;
    }
    if (inSz > 0) {
        memcpy(a->ct, in, inSz);
        for (size_t i = 0; i < inSz; i++) {
            out[i] = ((uint8_t *)a->s)[i] ^ a->ct[i];
            ((uint8_t *)a->s)[i] = a->ct[i];
        }
        a->lastBlkSz = (uint8_t)inSz;
        total += inSz;
    }
    return total;
}

/*
 * Finalize. Encrypt: compute tag into a->tag, return 1.
 * Decrypt: constant-time compare vs a->tag, return 1 on match.
 */
static inline int ascon_aead128_final(ASCON_AEAD128_CTX *a)
{
    uint8_t computed[16];
    uint8_t diff = 0;

    ascon_aead128_aad_finalize(a);
    ((uint8_t *)a->s)[a->lastBlkSz] ^= 0x01;
    a->s[2] ^= a->key[0];
    a->s[3] ^= a->key[1];
    ascon_permute(a->s, ASCON_AEAD128_PA);
    a->s[3] ^= a->key[0];
    a->s[4] ^= a->key[1];
    memcpy(computed, &a->s[3], 16);
    if (a->enc) {
        memcpy(a->tag, computed, 16);
        return 1;
    }
    for (size_t i = 0; i < 16; i++)
        diff |= computed[i] ^ a->tag[i];
    return diff == 0;
}

#endif /* OSSL_PROV_ASCON_LOCAL_H */

