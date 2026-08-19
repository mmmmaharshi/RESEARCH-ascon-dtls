/* Deterministic KDF KAT: reproduce wolfSSL's TLS 1.3 binder chain with
 * picotls + Ascon-Hash256, from the PSK alone (no ClientHello randomness).
 *
 * wolfSSL reference values (from its debug output during the interop run):
 *   EarlySecret PRK = 43 e5 44 13 96 37 d5 6f ...
 *   binder_key     = 4e 96 0a 0a a3 f0 25 22 c8 ef 4b bc 7f c7 e5 6f
 *                    6c 7c f1 d7 6b 72 de 88 52 c8 d1 5c e6 4c 61 18
 *   finished_key   = cd 4d 1b 8e c9 73 c4 c5 ...
 *
 * If binder_key matches, HMAC-Ascon(32-byte key) is correct and the interop
 * binder failure must come from the transcript hash instead.
 */
#include <picotls.h>
#include <picotls/minicrypto.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void hex(const char *tag, const uint8_t *b, size_t n)
{
    printf("%s = ", tag);
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static void make_psk(uint8_t psk[32])
{
    /* wolfSSL: unsigned char b, b += 0x22 wraps mod 256 (the >= 0x100 check
     * is dead code for unsigned char). Key = 01 23 45 67 89 AB CD EF 11 33... */
    uint8_t b = 0x01;
    for (int i = 0; i < 32; i++)
        psk[i] = b, b = (uint8_t)(b + 0x22);
}

int main(void)
{
    uint8_t psk[32], prk[32], bk[32], fk[32];
    uint8_t zero32[32] = {0};
    /* H("") for Ascon-Hash256 (wolfSSL/ref verified) */
    const uint8_t empty_digest[32] = {0x0b, 0x3b, 0xe5, 0x85, 0x0f, 0x2f, 0x6b,
                                      0x98, 0xca, 0xf2, 0x9f, 0x8f, 0xde, 0xa8,
                                      0x9b, 0x64, 0xa1, 0xfa, 0x70, 0xaa, 0x24,
                                      0x9b, 0x8f, 0x83, 0x9b, 0xd5, 0x3b, 0xaa,
                                      0x30, 0x4d, 0x92, 0xb2};
    int ret;

    make_psk(psk);
    hex("PSK", psk, 32);
    printf("block_size=%zu digest_size=%zu\n", ptls_ascon_hash256.block_size,
           ptls_ascon_hash256.digest_size);

    /* cross-call hash test: H(ipad8 || PSK32) single call vs two calls */
    {
        uint8_t ipad[8];
        uint8_t d1[32], d2[32];
        memset(ipad, 0x36, 8);
        ptls_hash_context_t *h = ptls_ascon_hash256.create();
        h->update(h, ipad, 8);
        h->update(h, psk, 32);
        h->final(h, d1, PTLS_HASH_FINAL_MODE_FREE);
        h = ptls_ascon_hash256.create();
        h->update(h, ipad, 8);
        h->update(h, psk, 32);
        h->final(h, d2, PTLS_HASH_FINAL_MODE_FREE);
        hex("H2CALL(ipad8|psk32)", d1, 32);
        h = ptls_ascon_hash256.create();
        {
            uint8_t m[40];
            memcpy(m, ipad, 8);
            memcpy(m + 8, psk, 32);
            h->update(h, m, 40);
        }
        h->final(h, d2, PTLS_HASH_FINAL_MODE_FREE);
        hex("H1CALL(ipad8|psk32)", d2, 32);
        printf("cross-call %s\n", memcmp(d1, d2, 32) == 0 ? "MATCH" : "DIFFER");
    }
    printf("block_size=%zu digest_size=%zu\n", ptls_ascon_hash256.block_size,
           ptls_ascon_hash256.digest_size);

    /* Early Secret: HKDF-Extract(salt="", ikm=PSK) */
    ret = ptls_hkdf_extract(&ptls_ascon_hash256, prk, ptls_iovec_init(NULL, 0),
                            ptls_iovec_init(psk, 32));
    if (ret != 0) {
        printf("hkdf_extract failed: %d\n", ret);
        return 1;
    }
    hex("PRK", prk, 32);

    /* binder_key = HKDF-Expand-Label(PRK, "tls13 ext binder", H(""), 32) */
    ret = ptls_hkdf_expand_label(&ptls_ascon_hash256, bk, 32,
                                 ptls_iovec_init(prk, 32), "ext binder",
                                 ptls_iovec_init(empty_digest, 32), "tls13 ");
    if (ret != 0) {
        printf("expand_label(binder) failed: %d\n", ret);
        return 1;
    }
    hex("BK ", bk, 32);

    /* finished_key = HKDF-Expand-Label(binder_key, "tls13 finished", H(""), 32) */
    ret = ptls_hkdf_expand_label(&ptls_ascon_hash256, fk, 32,
                                 ptls_iovec_init(bk, 32), "finished",
                                 ptls_iovec_init(empty_digest, 32), "tls13 ");
    if (ret != 0) {
        printf("expand_label(finished) failed: %d\n", ret);
        return 1;
    }
    hex("FK ", fk, 32);

    /* manual HMAC chain (mirror of wolfSSL hmac.c SetKey/Update/Final) */
    {
        uint8_t hkey[32], ipad[8], opad[8], inner[32], outer[32], buf[64];
        ptls_hash_context_t *hc;
        hc = ptls_ascon_hash256.create();
        hc->update(hc, zero32, 32);
        hc->final(hc, hkey, PTLS_HASH_FINAL_MODE_FREE);
        hex("HKEY", hkey, 32);
        for (int i = 0; i < 8; i++) {
            ipad[i] = hkey[i] ^ 0x36;
            opad[i] = hkey[i] ^ 0x5c;
        }
        hex("IPAD", ipad, 8);
        hex("OPAD", opad, 8);
        memcpy(buf, ipad, 8);
        memcpy(buf + 8, psk, 32);
        hc = ptls_ascon_hash256.create();
        hc->update(hc, buf, 40);
        hc->final(hc, inner, PTLS_HASH_FINAL_MODE_FREE);
        hex("INNER", inner, 32);
        memcpy(buf, opad, 8);
        memcpy(buf + 8, inner, 32);
        hc = ptls_ascon_hash256.create();
        hc->update(hc, buf, 40);
        hc->final(hc, outer, PTLS_HASH_FINAL_MODE_FREE);
        hex("OUTER", outer, 32);
    }

    printf("expect BK = 4e960a0aa3f02522c8ef4bbc7fc7e56f6c7cf1d76b72de8852c8d15ce64c6118\n");
    printf("expect FK = cd4d1b8ec973c4c5...\n");
    return 0;
}
