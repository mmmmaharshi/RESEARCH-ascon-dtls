/*
 * Default provider implementation of Ascon-Hash256 (experimental).
 *
 * Block size is 8 bytes (Ascon-Hash256 rate). That is deliberate: with a
 * 32-byte key the stock OpenSSL HMAC implementation (crypto/hmac/hmac.c)
 * hashes the key down to 32 bytes and then feeds only the first
 * EVP_MD_block_size() = 8 bytes into the inner/outer hash states, which is
 * exactly the behaviour of the wolfSSL Ascon HMAC (see the R7 interop notes
 * in dtls13-ascon-validation.md). Both stacks therefore derive identical
 * TLS 1.3 HKDF secrets for suite 0x006E.
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>
#include "prov/digestcommon.h"
#include "prov/ascon_local.h"

static int ascon_hash256_init(void *vctx)
{
    ascon_hash256_core_init((ASCON_HASH256_CTX *)vctx);
    return 1;
}

static int ascon_hash256_update(void *vctx, const unsigned char *in, size_t inl)
{
    ascon_hash256_core_update((ASCON_HASH256_CTX *)vctx, in, inl);
    return 1;
}

static int ascon_hash256_final(unsigned char *out, void *vctx)
{
    ascon_hash256_core_final((ASCON_HASH256_CTX *)vctx, out);
    return 1;
}

IMPLEMENT_digest_functions(ascon_hash256, ASCON_HASH256_CTX,
                           ASCON_HASH256_RATE, 32, 0,
                           ascon_hash256_init, ascon_hash256_update,
                           ascon_hash256_final);
