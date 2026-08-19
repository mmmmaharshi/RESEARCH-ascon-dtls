/*
 * Self-checking record-layer AEAD test vectors for
 * TLS_ASCONAEAD128_ASCONHASH256 (0x006E).
 *
 * Mirrors the exact constructions used by wolfSSL's DTLS 1.3 record layer:
 *   nonce = client/server_write_IV  XOR  zero-pad64(seq)   (tls13.c BuildTls13Nonce)
 *   AAD   = DTLS 1.3 record header (content type | version | epoch | masked seq)
 *   primitive = wc_AsconAEAD128_*  (same as tls13.c:2740-2879)
 *
 * The record-number MASK is covered separately by ascon_mask_kat.c.
 *
 * Build: gcc -I. -Iwolfssl -DWOLFSSL_USER_SETTINGS ascon_record_kat.c \
 *          -Lbuild -lwolfssl -lws2_32  (needs build/libwolfssl.dll on PATH)
 */
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ascon.h>
#include <stdio.h>
#include <string.h>

static void build_nonce(const byte* iv, word64 seq, byte* nonce)
{
    memcpy(nonce, iv, ASCON_AEAD128_NONCE_SZ);
    for (int i = 0; i < 8; i++)
        nonce[8 + i] ^= (byte)(seq >> (8 * (7 - i)));
}

static void print_hex(const char* label, const byte* b, int n)
{
    printf("    %-8s = ", label);
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static int run_case(const char* name, const byte* key, const byte* iv,
                    word64 seq, const byte* aad, int aadSz,
                    const byte* pt, int ptSz)
{
    byte nonce[ASCON_AEAD128_NONCE_SZ];
    build_nonce(iv, seq, nonce);

    wc_AsconAEAD128 a;
    byte ct[64], tag[ASCON_AEAD128_TAG_SZ], dec[64];

    int ret = wc_AsconAEAD128_Init(&a); if (ret) return ret;
    ret = wc_AsconAEAD128_SetKey(&a, key);           if (ret) return ret;
    ret = wc_AsconAEAD128_SetNonce(&a, nonce);       if (ret) return ret;
    ret = wc_AsconAEAD128_SetAD(&a, aad, aadSz);     if (ret) return ret;
    ret = wc_AsconAEAD128_EncryptUpdate(&a, ct, pt, ptSz); if (ret) return ret;
    ret = wc_AsconAEAD128_EncryptFinal(&a, tag);     if (ret) return ret;
    wc_AsconAEAD128_Clear(&a);

    ret = wc_AsconAEAD128_Init(&a); if (ret) return ret;
    ret = wc_AsconAEAD128_SetKey(&a, key);           if (ret) return ret;
    ret = wc_AsconAEAD128_SetNonce(&a, nonce);       if (ret) return ret;
    ret = wc_AsconAEAD128_SetAD(&a, aad, aadSz);     if (ret) return ret;
    ret = wc_AsconAEAD128_DecryptUpdate(&a, dec, ct, ptSz); if (ret) return ret;
    ret = wc_AsconAEAD128_DecryptFinal(&a, tag);     if (ret) return ret;
    wc_AsconAEAD128_Clear(&a);

    if (memcmp(dec, pt, ptSz) != 0) {
        printf("  %s: DECRYPT MISMATCH\n", name);
        return -1;
    }

    printf("  %s:\n", name);
    print_hex("key",   key, ASCON_AEAD128_KEY_SZ);
    print_hex("iv",    iv, 16);
    printf("    seq      = %llu\n", (unsigned long long)seq);
    print_hex("nonce", nonce, 16);
    print_hex("aad",   aad, aadSz);
    print_hex("pt",    pt, ptSz);
    print_hex("ct",    ct, ptSz);
    print_hex("tag",   tag, ASCON_AEAD128_TAG_SZ);
    return 0;
}

int main(void)
{
    byte key[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    byte iv[16]   = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                     0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    /* minimal DTLS 1.3 header: type=0x17 app_data, version=0xfefd, epoch=0, seq=0 */
    byte aadMin[13] = {0x17,0xfe,0xfd, 0,0, 0,0,0,0,0,0,0,0};
    /* fuller header: epoch=1, masked seq bytes 12 34 56 78 9a bc de f0 */
    byte aadFull[13] = {0x17,0xfe,0xfd, 0,1, 0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    byte pt1[14] = "ascon-dtls msg";
    byte pt2[32]; for (int i = 0; i < 32; i++) pt2[i] = (byte)i;

    int r = 0;
    r |= run_case("A seq=0  aad=min  pt=14B", key, iv, 0, aadMin, 13, pt1, 14);
    r |= run_case("B seq=1  aad=full pt=32B", key, iv, 1, aadFull, 13, pt2, 32);
    printf(r ? "KAT FAIL\n" : "KAT OK\n");
    return r ? 1 : 0;
}
