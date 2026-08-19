/*
 * Default provider implementation of the Ascon-128 AEAD (experimental).
 *
 * Implements the TLS 1.3 AEAD contract used by ssl/record/methods/tls13_meth.c:
 *   - key via EVP_CipherInit_ex(ctx, ciph, NULL, NULL, NULL, enc)
 *   - IV length via EVP_CTRL_AEAD_SET_IVLEN (set_ctx_params KEYLEN/IVLEN)
 *   - key via EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, enc)
 *   - per-record nonce as IV: EVP_CipherInit_ex(ctx, NULL, NULL, NULL, nonce)
 *   - AAD via EVP_CipherUpdate(ctx, NULL, &len, aad, aadlen)
 *   - single data EVP_CipherUpdate + EVP_CipherFinal_ex
 *   - tag via EVP_CTRL_AEAD_SET_TAG (decrypt) / EVP_CTRL_AEAD_GET_TAG (encrypt)
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/ascon_local.h"

#define ASCON128_KEYLEN 16
#define ASCON128_IVLEN  16
#define ASCON128_TAGLEN 16
#define ASCON128_BLOCKSIZE 1

static OSSL_FUNC_cipher_newctx_fn ascon128_newctx;
static OSSL_FUNC_cipher_freectx_fn ascon128_freectx;
static OSSL_FUNC_cipher_dupctx_fn ascon128_dupctx;
static OSSL_FUNC_cipher_get_params_fn ascon128_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn ascon128_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn ascon128_set_ctx_params;
static OSSL_FUNC_cipher_gettable_params_fn ascon128_gettable_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn ascon128_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn ascon128_settable_ctx_params;
static OSSL_FUNC_cipher_encrypt_init_fn ascon128_einit;
static OSSL_FUNC_cipher_decrypt_init_fn ascon128_dinit;
static OSSL_FUNC_cipher_update_fn ascon128_update;
static OSSL_FUNC_cipher_final_fn ascon128_final_fn;

static void *ascon128_newctx(void *provctx)
{
    return OPENSSL_zalloc(sizeof(ASCON_AEAD128_CTX));
}

static void ascon128_freectx(void *vctx)
{
    OPENSSL_clear_free(vctx, sizeof(ASCON_AEAD128_CTX));
}

static void *ascon128_dupctx(void *vctx)
{
    ASCON_AEAD128_CTX *in = vctx;
    ASCON_AEAD128_CTX *ret = OPENSSL_malloc(sizeof(*ret));

    if (ret != NULL)
        *ret = *in;
    return ret;
}

static int ascon128_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 0 /* stream cipher mode */))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ASCON128_BLOCKSIZE))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ASCON128_KEYLEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ASCON128_IVLEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_PARAM ascon128_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ascon128_gettable_params(void *provctx)
{
    return ascon128_known_gettable_params;
}

static int ascon128_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    ASCON_AEAD128_CTX *ctx = vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ASCON128_KEYLEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ASCON128_IVLEN))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (p->data == NULL) {
            p->data_size = ASCON128_TAGLEN;
            return 1;
        }
        if (p->data_size < ASCON128_TAGLEN)
            return 0;
        memcpy(p->data, ctx->tag, ASCON128_TAGLEN);
        p->return_size = ASCON128_TAGLEN;
    }
    return 1;
}

static const OSSL_PARAM ascon128_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ascon128_gettable_ctx_params(void *vctx,
                                                      void *provctx)
{
    return ascon128_known_gettable_ctx_params;
}

static int ascon128_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    ASCON_AEAD128_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        size_t v;

        if (!OSSL_PARAM_get_size_t(p, &v) || v != ASCON128_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        size_t v;

        if (!OSSL_PARAM_get_size_t(p, &v) || v != ASCON128_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING
                || p->data_size != ASCON128_TAGLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        memcpy(ctx->tag, p->data, ASCON128_TAGLEN);
    }
    return 1;
}

static const OSSL_PARAM ascon128_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ascon128_settable_ctx_params(void *vctx,
                                                      void *provctx)
{
    return ascon128_known_settable_ctx_params;
}

static int ascon128_init(void *vctx, const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const OSSL_PARAM params[], int enc)
{
    ASCON_AEAD128_CTX *ctx = vctx;

    if (!ascon128_set_ctx_params(vctx, params))
        return 0;
    ctx->enc = (uint8_t)(enc != 0);
    if (key != NULL) {
        if (keylen != ASCON128_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        memcpy(ctx->key, key, ASCON128_KEYLEN);
    }
    if (iv != NULL) {
        if (ivlen != ASCON128_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ascon_aead128_reset(ctx, (const uint8_t *)ctx->key,
                            (const uint8_t *)iv);
    }
    return 1;
}

static int ascon128_einit(void *vctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[])
{
    return ascon128_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int ascon128_dinit(void *vctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[])
{
    return ascon128_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int ascon128_update(void *vctx, unsigned char *out, size_t *outl,
                           size_t outsize, const unsigned char *in, size_t inl)
{
    ASCON_AEAD128_CTX *ctx = vctx;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }
    if (out == NULL) {
        /* AAD */
        ascon_aead128_absorb_aad(ctx, in, inl);
        *outl = 0;
        return 1;
    }
    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (ctx->enc)
        *outl = ascon_aead128_encrypt_update(ctx, out, in, inl);
    else
        *outl = ascon_aead128_decrypt_update(ctx, out, in, inl);
    return 1;
}

static int ascon128_final_fn(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize)
{
    ASCON_AEAD128_CTX *ctx = vctx;

    if (!ascon_aead128_final(ctx))
        return 0;
    *outl = 0;
    return 1;
}

const OSSL_DISPATCH ossl_ascon128_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))ascon128_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))ascon128_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))ascon128_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ascon128_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ascon128_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))ascon128_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))ascon128_final_fn },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ascon128_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ascon128_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ascon128_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))ascon128_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ascon128_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))ascon128_settable_ctx_params },
    OSSL_DISPATCH_END
};
