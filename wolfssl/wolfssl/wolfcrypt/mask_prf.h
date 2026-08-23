/* mask_prf.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 * Canonical Mask-PRF header — single source of domsep table.
 * See docs/mask-prf-proof.md Thm 1/1'' and CONTEXT.md.
 */

#ifndef WOLF_CRYPT_MASK_PRF_H
#define WOLF_CRYPT_MASK_PRF_H

#ifdef HAVE_ASCON

#include <wolfssl/wolfcrypt/types.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generic domsep table — one row per context, distinct from Ascon IVs. */
#define MASK_PRF_DOMSEP_RNDIMSK_ 0x524E44494D534B5FULL /* DTLS  RNDIMSK_ flagship */
#define MASK_PRF_DOMSEP_QUPNMSK_ 0x5155504E4D534B5FULL /* QUIC  QUPNMSK_ */
#define MASK_PRF_DOMSEP_ESPSNW__ 0x455350534E575F5FULL /* ESP   ESPSNW__ */
#define MASK_PRF_DOMSEP_OSCORE__ 0x4F53434F52455F5FULL /* OSCORE OSCORE__ */

/* Canonical table — single source; formal artifacts generated via tools/gen_domsep.py */
static const word64 mask_prf_domsep_table[4] = {
    MASK_PRF_DOMSEP_RNDIMSK_,
    MASK_PRF_DOMSEP_QUPNMSK_,
    MASK_PRF_DOMSEP_ESPSNW__,
    MASK_PRF_DOMSEP_OSCORE__
};

typedef enum {
    MASK_PRF_DTLS   = 0,
    MASK_PRF_QUIC   = 1,
    MASK_PRF_ESP    = 2,
    MASK_PRF_OSCORE = 3
} mask_prf_domsep_idx;

/* Opaque ctx — holds domsep only; key is per-call to keep API trimmed. */
typedef struct {
    word64 domsep;
} mask_prf_ctx;

/* Single-call keyed-sponge PRF: out = trunc_16(P(domsep||K||X)), P=Ascon-P^12 */
WOLFSSL_API int mask_prf_derive(const uint8_t key[16], const uint8_t x[16],
                                uint8_t out[16], word64 domsep);

/* Bound check: *adv = q^2/2^192 + q/2^128 (conservative), tight is q/2^128. */
WOLFSSL_API bool mask_prf_check_bound(uint64_t q, double *adv);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HAVE_ASCON */
#endif /* WOLF_CRYPT_MASK_PRF_H */
