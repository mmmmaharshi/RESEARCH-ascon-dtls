#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Ascon-DTLS research harness build (M2.1).
 * Windows x86_64, gcc (MSYS2 ucrt64), Ninja.
 * Deliberately minimal: TLS 1.3 + DTLS 1.3 + PSK + Ascon (SP 800-232). */

#define WOLFSSL_TLS13
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_W64_WRAPPER
#define HAVE_HKDF
#define HAVE_AEAD
#define HAVE_ASCON
#define HAVE_HASHDRBG
#define HAVE_FFDHE_2048
#define WC_RSA_PSS
#define HAVE_SUPPORTED_CURVES
#define HAVE_TLS_EXTENSIONS
#define WOLFSSL_TLSX
#define WOLFSSL_SEND_HRR_COOKIE
#define WOLFSSL_DEBUG_TLS
#define DEBUG_WOLFSSL
#define WOLFSSL_EXPERIMENTAL_SETTINGS

/* Reference AEADs for the software benchmark (M2.3).
 * AES-GCM is table-based software AES: WOLFSSL_AESNI is NOT defined,
 * so no AES-NI acceleration is compiled in. */
#define HAVE_AESGCM
#define HAVE_CHACHA
#define HAVE_POLY1305

/* Defaults retained, explicit for the record:
 *  - PSK enabled (NO_PSK NOT defined)
 *  - SHA-256 enabled (required by TLS 1.3 core; suite-level claim tested later)
 *  - AES enabled (DTLS 1.3 auto-defines WOLFSSL_AES_DIRECT; harmless here) */

#endif /* WOLFSSL_USER_SETTINGS_H */
