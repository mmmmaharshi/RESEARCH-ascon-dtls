/* mask_prf.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 * Canonical Mask-PRF module — colocated with ascon.c, shares AsconState + permutation.
 * Single-call keyed-sponge PRF: Mask_K(X)=trunc_16(P(domsep||K||X)), P=Ascon-P^12
 * See wolfssl/wolfcrypt/mask_prf.h (canonical table) and docs/mask-prf-proof.md Thm 1/1''.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_ASCON

#include <wolfssl/wolfcrypt/mask_prf.h>
#include <wolfssl/wolfcrypt/ascon.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#include <string.h>
#include <math.h>

#ifndef WORD64_AVAILABLE
    #error "Mask-PRF requires 64-bit word"
#endif

/* Local permutation — reuse of ascon.c logic (copied, not extern, to keep module colocated).
 * ponytail: duplicate 12-round constants; upgrade to shared header if permutation is refactored. */
static const byte s_round_constants[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};
static WC_INLINE byte s_start_index(byte rounds) {
    return (rounds == 8) ? 4 : 0;
}
static WC_INLINE void s_ascon_round(AsconState* a, byte round) {
    word64 tmp0, tmp1, tmp2, tmp3, tmp4;
    a->s64[2] ^= s_round_constants[round];
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
    a->s64[4] = tmp4 ^ rotrFixed64(tmp4,  7) ^ rotrFixed64(tmp4, 41);
    a->s64[1] = tmp1 ^ rotrFixed64(tmp1, 61) ^ rotrFixed64(tmp1, 39);
    a->s64[3] = tmp3 ^ rotrFixed64(tmp3, 10) ^ rotrFixed64(tmp3, 17);
    a->s64[0] = tmp0 ^ rotrFixed64(tmp0, 19) ^ rotrFixed64(tmp0, 28);
    a->s64[2] = tmp2 ^ rotrFixed64(tmp2,  1) ^ rotrFixed64(tmp2,  6);
}
static void s_permutation(AsconState* a, byte rounds) {
    byte i = s_start_index(rounds);
    for (; i < 12; i++) s_ascon_round(a, i);
}

int mask_prf_derive(const uint8_t key[16], const uint8_t x[16], uint8_t out[16], word64 domsep)
{
    AsconState s;
    if (key == NULL || x == NULL || out == NULL) return BAD_FUNC_ARG;
    XMEMSET(&s, 0, sizeof(s));
    s.s64[0] = domsep;
    XMEMCPY(&s.s64[1], key, 16);
    XMEMCPY(&s.s64[3], x, 16);
    s_permutation(&s, 12);
    XMEMCPY(out, &s.s64[0], 8);
    XMEMCPY(out+8, &s.s64[1], 8);
    ForceZero(&s, sizeof(s));
    return 0;
}

bool mask_prf_check_bound(uint64_t q, double *adv)
{
    if (adv == NULL) return false;
    double qd = (double)q;
    double b192 = ldexp(1.0, 192);
    double b128 = ldexp(1.0, 128);
    double b1 = (qd * qd) / b192;
    double b2 = qd / b128;
    *adv = b1 + b2;
    return true;
}

#endif /* HAVE_ASCON */
