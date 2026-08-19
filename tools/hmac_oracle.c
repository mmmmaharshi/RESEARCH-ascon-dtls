/* wolfSSL HMAC-Ascon oracle: prints each step of HMAC(WC_ASCON_HASH256,
 * key=0^32, msg=PSK) so picotls's chain can be diffed step by step. */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <stdio.h>
#include <string.h>

static void hex(const char *tag, const byte *b, int n)
{
    printf("%s = ", tag);
    for (int i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

static void ascon_hash(const byte *in, int inlen, byte *out)
{
    wc_AsconHash256 h;
    wc_AsconHash256_Init(&h);
    wc_AsconHash256_Update(&h, in, (word32)inlen);
    wc_AsconHash256_Final(&h, out);
}

int main(void)
{
    byte psk[32];
    unsigned char b = 0x01;
    int i;
    byte zero32[32] = {0};
    byte hkey[32], ipad[8], opad[8], inner[32], outer[32], buf[64], mac[32];
    Hmac h;

    for (i = 0; i < 32; i++, b += 0x22)
        psk[i] = b; /* wraps mod 256 */
    hex("PSK", psk, 32);

    ascon_hash(zero32, 32, hkey);
    hex("HKEY", hkey, 32);
    for (i = 0; i < 8; i++) {
        ipad[i] = hkey[i] ^ 0x36;
        opad[i] = hkey[i] ^ 0x5c;
    }
    hex("IPAD", ipad, 8);
    hex("OPAD", opad, 8);

    memcpy(buf, ipad, 8);
    memcpy(buf + 8, psk, 32);
    ascon_hash(buf, 40, inner);
    hex("INNER", inner, 32);

    memcpy(buf, opad, 8);
    memcpy(buf + 8, inner, 32);
    ascon_hash(buf, 40, outer);
    hex("OUTER", outer, 32);

    wc_HmacSetKey(&h, WC_ASCON_HASH256, zero32, 32);
    wc_HmacUpdate(&h, psk, 32);
    wc_HmacFinal(&h, mac);
    hex("HMAC-API", mac, 32);

    /* Hypothesis: outer hash = continuation from ZERO state (post-Clear),
     * absorbing opad8 then inner digest. */
    {
        wc_AsconHash256 h2;
        byte out2[32];
        memset(&h2, 0, sizeof(h2)); /* zero state, like after Final's Clear */
        wc_AsconHash256_Update(&h2, opad, 8);
        wc_AsconHash256_Update(&h2, inner, 32);
        wc_AsconHash256_Final(&h2, out2);
        hex("ZERO-CONT", out2, 32);
    }
    /* Real continuation: same context, no touching between Final and opad. */
    {
        wc_AsconHash256 h3;
        byte inner3[32], out3[32];
        wc_AsconHash256_Init(&h3);
        wc_AsconHash256_Update(&h3, ipad, 8);
        wc_AsconHash256_Update(&h3, psk, 32);
        wc_AsconHash256_Final(&h3, inner3);
        wc_AsconHash256_Update(&h3, opad, 8);
        wc_AsconHash256_Update(&h3, inner3, 32);
        wc_AsconHash256_Final(&h3, out3);
        hex("CONT-REAL", out3, 32);
    }
    /* SetKey replica: context IV-INIT'D first (HmacKeyInitHash at line 270),
     * key hashed from IV state, Final's Clear zeroes state, then ipad/opad
     * chains absorb from the ZERO state. */
    {
        wc_AsconHash256 h5;
        byte hkey5[32], ip5[8], op5[8], inner5[32], out5[32];
        int i;
        wc_AsconHash256_Init(&h5);
        wc_AsconHash256_Update(&h5, zero32, 32);
        wc_AsconHash256_Final(&h5, hkey5);   /* state Cleared -> zero */
        for (i = 0; i < 8; i++) {
            ip5[i] = hkey5[i] ^ IPAD;
            op5[i] = hkey5[i] ^ OPAD;
        }
        wc_AsconHash256_Update(&h5, ip5, 8); /* from ZERO state */
        wc_AsconHash256_Update(&h5, psk, 32);
        wc_AsconHash256_Final(&h5, inner5);  /* Cleared -> zero */
        wc_AsconHash256_Update(&h5, op5, 8); /* from ZERO state */
        wc_AsconHash256_Update(&h5, inner5, 32);
        wc_AsconHash256_Final(&h5, out5);
        hex("MIXED-REPL", out5, 32);
    }
    return 0;
}