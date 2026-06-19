/*
* This file is part of the NoxTLS Library.
*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * certgen - Key and certificate generation utility using NoxTLS
 * Similar to OpenSSL genrsa, req -x509.
 */
/**
 * @file main.c
 * @brief Key and certificate generation (genrsa, req) using NoxTLS.
 * @defgroup noxtls_app_certgen Certgen utility
 * @details
 * Commands: genrsa (generate RSA key), genec (generate EC key), req (certificate request / self-signed cert).
 * genrsa options: -out &lt;name&gt; (writes &lt;name&gt;.key and &lt;name&gt;.pub), -outform DER|PEM, -bits 1024|2048|3072|4096.
 * genec options: -out &lt;name&gt; (writes &lt;name&gt;.key and &lt;name&gt;.pub), -outform DER|PEM,
 *                -curve secp192r1|secp224r1|prime256v1|secp384r1|secp521r1|
 *                       brainpoolP256r1|brainpoolP384r1|brainpoolP512r1|
 *                       secp192k1|secp224k1|secp256k1.
 * req options (for -new -x509): -key &lt;file&gt;, -out &lt;file&gt;, -days &lt;n&gt;, -subj &lt;name&gt;.
 * @example
 * certgen genrsa -out server -bits 2048
 * certgen genec -out client -curve prime256v1
 * certgen req -new -x509 -key client.key -out cert.pem -days 365 -subj /CN=localhost
 */

/* MUST be the FIRST #include: app-local noxtls_config.h (project policy)
 * MSVC searches the directory of the including header first for "..."
 * style includes; if a library header pulls in "noxtls_config.h" before
 * this app does, the top-level config wins. Hoisting our local one
 * here ensures _NOXTLS_CONFIG_H_ is set from THIS file. */
#include "noxtls_config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The application-local noxtls_config.h MUST be included before any NoxTLS
 * library header so that NOXTLS_APP_STATIC_BUFFER_SIZE and feature-flag
 * overrides take effect in this translation unit. The application directory
 * is the first entry in include_directories(), so `noxtls_config.h` resolves
 * to ./noxtls_config.h, not the top-level one. */
#include "noxtls_common.h"
#include "noxtls-lib/certs/noxtls_x509.h"
#include "noxtls-lib/certs/certificates.h"
#include "noxtls-lib/certs/asn1.h"
#include "utility/base64.h"
#include "noxtls-lib/pkc/rsa/noxtls_rsa.h"
#include "noxtls-lib/pkc/ecc/noxtls_ecc.h"
#include "noxtls-lib/pkc/ed25519/noxtls_ed25519.h"
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
#include "noxtls-lib/pkc/ed448/noxtls_ed448.h"
#endif
#if NOXTLS_FEATURE_ML_DSA
#include "noxtls-lib/pkc/mldsa/noxtls_mldsa.h"
#endif
#if NOXTLS_FEATURE_SLH_DSA
#include "noxtls-lib/pkc/slhdsa/noxtls_slhdsa.h"
#endif
#include "noxtls-lib/mdigest/noxtls_hash.h"

/* ============================================================================
 * Application-private static workspace (per project policy)
 * ============================================================================
 *
 * Every application owns a large statically-allocated workspace buffer; all
 * dynamic allocations made by this translation unit are served out of it via
 * a simple bump arena. The buffer's size lives in this app's noxtls_config.h
 * (NOXTLS_APP_STATIC_BUFFER_SIZE) so it can be tuned independently per app.
 *
 * free() is a no-op; the whole arena is released en-masse via
 * app_workspace_reset() (e.g. between commands) which also wipes any
 * transient secret material that may have been allocated.
 */
static uint8_t  g_app_workspace[NOXTLS_APP_STATIC_BUFFER_SIZE];
static size_t   g_app_workspace_off = 0U;
#define APP_WORKSPACE_ALIGN ((size_t)16U)

/**
 * @brief Allocate workspace
 *
 * @param[in] n The size to allocate
 * @return The pointer to the allocated workspace
 */
static void *app_workspace_alloc(size_t n)
{
    size_t off = (g_app_workspace_off + (APP_WORKSPACE_ALIGN - 1U)) &
                 ~(APP_WORKSPACE_ALIGN - 1U);
    if(n == 0U || off > sizeof(g_app_workspace) ||
       n > sizeof(g_app_workspace) - off) {
        return NULL;
    }
    g_app_workspace_off = off + n;
    return &g_app_workspace[off];
}

/**
 * @brief Free the workspace
 *
 * @param[in] p The pointer to the workspace to free
 * @return void
*/  
static void app_workspace_free(void *p) { (void)p; }

/**
 * @brief Reset the workspace
 *
 * @return void
 */
static void app_workspace_reset(void)
{
    if(g_app_workspace_off > 0U) {
        memset(g_app_workspace, 0, g_app_workspace_off);
    }
    g_app_workspace_off = 0U;
}

/* Redirect malloc()/free() in this translation unit to the static workspace.
 * Library and standard headers have already been pulled in above; they
 * declared malloc/free as plain functions and are unaffected. App code below
 * uses these macros transparently. */
#undef malloc
#undef free
#define malloc(n) app_workspace_alloc(n)
#define free(p)   app_workspace_free(p)

#define CERTGEN_VERSION "0.1.0"
#define PKCS1_MAX_BYTES (16384u)  /* enough for 4096-bit key DER */
#define SEC1_ECC_MAX_BYTES (512U)  /* SEC1 ECPrivateKey DER (P-521 + OID + public) */
#define SPKI_MAX_BYTES (16384u)   /* SubjectPublicKeyInfo for RSA/EC */
#define CERTGEN_PATH_MAX (512U)
/* Longest basename (chars) before ".key"/".pub" when key/pub paths use CERTGEN_PATH_MAX buffers. */
#define CERTGEN_KEYPUB_BASE_MAX ((CERTGEN_PATH_MAX) - 5U)

/* rsaEncryption OID (1.2.840.113549.1.1.1) - raw DER bytes */
static const uint8_t oid_rsa_encryption[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
/* sha256WithRSAEncryption (1.2.840.113549.1.1.11) */
static const uint8_t oid_sha256_with_rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
/* id-ecPublicKey OID (1.2.840.10045.2.1) - raw DER bytes */
static const uint8_t oid_id_ec_public_key[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
/* id-Ed25519 (1.3.101.112), id-Ed448 (1.3.101.113) — RFC 8410 */
static const uint8_t oid_ed25519[] = { 0x2B, 0x65, 0x70 };
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
static const uint8_t oid_ed448[] = { 0x2B, 0x65, 0x71 };
#endif
#if NOXTLS_FEATURE_ML_DSA
/* id-ml-dsa-44/65/87 OIDs (NIST CSOR, 2.16.840.1.101.3.4.3.{17,18,19}) */
static const uint8_t oid_ml_dsa_44[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
static const uint8_t oid_ml_dsa_65[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
static const uint8_t oid_ml_dsa_87[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };
#endif
#if NOXTLS_FEATURE_SLH_DSA
/* id-slh-dsa-* OIDs (NIST CSOR, 2.16.840.1.101.3.4.3.{20..31}) */
static const uint8_t oid_slh_dsa_sha2_128s[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14 };
static const uint8_t oid_slh_dsa_sha2_128f[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15 };
static const uint8_t oid_slh_dsa_sha2_192s[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16 };
static const uint8_t oid_slh_dsa_sha2_192f[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17 };
static const uint8_t oid_slh_dsa_sha2_256s[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18 };
static const uint8_t oid_slh_dsa_sha2_256f[]  = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19 };
static const uint8_t oid_slh_dsa_shake_128s[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1A };
static const uint8_t oid_slh_dsa_shake_128f[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1B };
static const uint8_t oid_slh_dsa_shake_192s[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1C };
static const uint8_t oid_slh_dsa_shake_192f[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1D };
static const uint8_t oid_slh_dsa_shake_256s[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1E };
static const uint8_t oid_slh_dsa_shake_256f[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1F };
#endif

/* Curve OIDs (DER) for SEC1 ECPrivateKey parameters - same as noxtls_x509.c */
static const uint8_t oid_secp192r1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01};
static const uint8_t oid_secp224r1[] = {0x2B, 0x81, 0x04, 0x00, 0x21};
static const uint8_t oid_secp256r1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t oid_secp384r1[] = {0x2B, 0x81, 0x04, 0x00, 0x22};
static const uint8_t oid_secp521r1[] = {0x2B, 0x81, 0x04, 0x00, 0x23};
static const uint8_t oid_bp256r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07};
static const uint8_t oid_bp384r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B};
static const uint8_t oid_bp512r1[] = {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D};
static const uint8_t oid_secp192k1[] = {0x2B, 0x81, 0x04, 0x00, 0x1F};
static const uint8_t oid_secp224k1[] = {0x2B, 0x81, 0x04, 0x00, 0x20};
static const uint8_t oid_secp256k1[] = {0x2B, 0x81, 0x04, 0x00, 0x0A};

/**
 * @brief Open a file
 *
 * @param[in] filename The name of the file to open
 * @param[in] mode The mode to open the file in
 * @return The file pointer
 */
static FILE *noxtls_fopen(const char *filename, const char *mode)
{
#ifdef _MSC_VER
    FILE *fp = NULL;
    if(fopen_s(&fp, filename, mode) != 0) {
        return NULL;
    }
    return fp;
#else
    return fopen(filename, mode);
#endif
}

/**
 * @brief Print the usage of the application
 *
 * @param[in] prog The name of the application
 * @return void
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands (OpenSSL-like):\n");
    printf("  genrsa      Generate RSA private key\n");
    printf("  genec       Generate EC private key (NIST, Brainpool, secp-k1)\n");
    printf("  gened25519  Generate Ed25519 key pair (PKCS#8 seed + RFC 8410 SPKI .pub)\n");
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    printf("  gened448    Generate Ed448 key pair (PKCS#8 seed + RFC 8410 SPKI .pub)\n");
#endif
#if NOXTLS_FEATURE_ML_DSA
    printf("  genmldsa    Generate ML-DSA (FIPS 204) post-quantum key pair\n");
#endif
#if NOXTLS_FEATURE_SLH_DSA
    printf("  genslhdsa   Generate SLH-DSA (FIPS 205) post-quantum key pair\n");
#endif
    printf("  req         Certificate request / self-signed certificate\n\n");
    printf("genrsa options:\n");
    printf("  -out <name>      Base name for output files: <name>.key (private), <name>.pub (public). Default: stdout (private only)\n");
    printf("  -outform DER|PEM Output format for .key (default: PEM). .pub is always PEM.\n");
    printf("  -bits <n>        Key size: 1024, 2048, 3072, 4096 (default: 2048)\n\n");
    printf("genec options:\n");
    printf("  -out <name>      Base name for output files: <name>.key (private), <name>.pub (public). Default: stdout (private only)\n");
    printf("  -outform DER|PEM Output format for .key (default: PEM). .pub is always PEM.\n");
    printf("  -curve <name>    secp192r1|secp224r1|prime256v1|secp384r1|secp521r1|\n");
    printf("                    brainpoolP256r1|brainpoolP384r1|brainpoolP512r1|\n");
    printf("                    secp192k1|secp224k1|secp256k1 (default: prime256v1)\n\n");
#if NOXTLS_FEATURE_ML_DSA
    printf("genmldsa options:\n");
    printf("  -out <name>      Base name for <name>.key (PKCS#8) and <name>.pub (SPKI). Default: stdout.\n");
    printf("  -outform DER|PEM Output format for .key (default: PEM).\n");
    printf("  -param <set>     ml-dsa-44 | ml-dsa-65 | ml-dsa-87 (default: ml-dsa-65)\n\n");
#endif
#if NOXTLS_FEATURE_SLH_DSA
    printf("genslhdsa options:\n");
    printf("  -out <name>      Base name for <name>.key (PKCS#8) and <name>.pub (SPKI). Default: stdout.\n");
    printf("  -outform DER|PEM Output format for .key (default: PEM).\n");
    printf("  -param <set>     slh-dsa-sha2-128s|f, slh-dsa-sha2-192s|f, slh-dsa-sha2-256s|f,\n");
    printf("                   slh-dsa-shake-128s|f, slh-dsa-shake-192s|f, slh-dsa-shake-256s|f\n");
    printf("                   (default: slh-dsa-sha2-128s)\n\n");
#endif
    printf("req options (for -new -x509 self-signed cert):\n");
    printf("  -new -x509      Create self-signed certificate\n");
    printf("  -key <file>     Private key file. Accepts RSA PKCS#1/PKCS#8, ECC SEC1/PKCS#8,\n");
    printf("                  Ed25519/Ed448 PKCS#8, ML-DSA PKCS#8, SLH-DSA PKCS#8.\n");
    printf("  -out <file>     Output certificate file (required)\n");
    printf("  -outform DER|PEM Output format (default: PEM)\n");
    printf("  -days <n>       Validity in days (default: 365)\n");
    printf("  -subj <name>    Subject, e.g. /CN=localhost\n\n");
    printf("Examples:\n");
    printf("  %s genrsa -out server -bits 2048     # writes server.key and server.pub\n", prog);
    printf("  %s genec -out client -curve prime256v1   # writes client.key and client.pub\n", prog);
    printf("  %s gened25519 -out ed25519key\n", prog);
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    printf("  %s gened448 -out ed448key\n", prog);
#endif
#if NOXTLS_FEATURE_ML_DSA
    printf("  %s genmldsa -out pq -param ml-dsa-65\n", prog);
#endif
#if NOXTLS_FEATURE_SLH_DSA
    printf("  %s genslhdsa -out pq -param slh-dsa-sha2-128s\n", prog);
#endif
    printf("  %s req -new -x509 -key server.key -out cert.pem -days 365 -subj /CN=localhost\n", prog);
}

/* Encode PKCS#1 RSAPrivateKey (DER) from rsa_key_t. Returns length or 0 on error. */
/**
 * @brief Encode PKCS#1 RSAPrivateKey (DER) from rsa_key_t. Returns length or 0 on error.
 *
 * @param[in] key The RSA key to encode
 * @param[out] out The buffer to encode the RSA key into
 * @param[in] out_max The maximum length of the buffer
 * @return The length of the encoded RSA key
 */
static uint32_t encode_pkcs1_rsa_der(const rsa_key_t *key, uint8_t *out, uint32_t out_max)
{
    if (key == NULL || out == NULL || out_max < 100) {
        return 0;
    }

    uint8_t content_buf[PKCS1_MAX_BYTES];
    uint32_t content_len = 0;
    uint32_t key_bytes = key->key_bytes;
    uint32_t prime_len = key_bytes / 2;

    /* Version 0 */
    {
        const uint8_t ver[] = { 0x00 };
        uint32_t n = noxtls_asn1_put_integer(content_buf + content_len, sizeof(content_buf) - content_len, ver, 1);
        if (n == 0) return 0;
        content_len += n;
    }

    /* n, e, d, p, q, dp, dq, qi */
    const uint8_t *values[] = { key->n, key->e, key->d, key->p, key->q, key->dp, key->dq, key->qi };
    const uint32_t lens[] = { key_bytes, key_bytes, key_bytes, prime_len, prime_len, prime_len, prime_len, prime_len };

    for (int i = 0; i < 8; i++) {
        if (values[i] == NULL) return 0;
        uint32_t n = noxtls_asn1_put_integer(content_buf + content_len, (uint32_t)(sizeof(content_buf) - content_len),
                                       values[i], lens[i]);
        if (n == 0) return 0;
        content_len += n;
    }

    return noxtls_asn1_put_sequence(out, out_max, content_buf, content_len);
}

/* Encode SEC1 ECPrivateKey (DER) from ecc_key_t. Returns length or 0 on error. */
/**
 * @brief Encode SEC1 ECPrivateKey (DER) from ecc_key_t. Returns length or 0 on error.
 *
 * @param[in] key The ECC key to encode
 * @param[in] curve_oid The OID of the curve
 * @param[in] curve_oid_len The length of the OID of the curve
 * @param[out] out The buffer to encode the ECC key into
 * @param[in] out_max The maximum length of the buffer
 * @return The length of the encoded ECC key
 */
static uint32_t encode_sec1_ecc_der(const ecc_key_t *key, const uint8_t *curve_oid, uint32_t curve_oid_len, uint8_t *out, uint32_t out_max)
{
    if (key == NULL || key->curve == NULL || key->d == NULL || curve_oid == NULL || out == NULL || out_max < 64) {
        return 0;
    }
    uint32_t size = key->curve->size;
    uint8_t content_buf[SEC1_ECC_MAX_BYTES];
    uint32_t content_len = 0;

    /* version INTEGER 1 */
    {
        const uint8_t ver[] = {0x01};
        uint32_t n = noxtls_asn1_put_integer(content_buf + content_len, sizeof(content_buf) - content_len, ver, 1);
        if (n == 0) return 0;
        content_len += n;
    }
    /* privateKey OCTET STRING (d, size bytes) */
    {
        uint32_t n = noxtls_asn1_put_octet_string(content_buf + content_len, (uint32_t)(sizeof(content_buf) - content_len), key->d, size);
        if (n == 0) return 0;
        content_len += n;
    }
    /* parameters [0] IMPLICIT ECParameters (namedCurve OID) */
    {
        uint8_t oid_der[48];
        uint32_t oid_der_len = noxtls_asn1_put_oid_raw(oid_der, sizeof(oid_der), curve_oid, curve_oid_len);
        if (oid_der_len == 0) return 0;
        uint8_t expl0[64];
        uint32_t expl0_len = noxtls_asn1_put_explicit(expl0, sizeof(expl0), 0, oid_der, oid_der_len);
        if (expl0_len == 0 || content_len + expl0_len > sizeof(content_buf)) return 0;
        memcpy(content_buf + content_len, expl0, expl0_len);
        content_len += expl0_len;
    }
    /* publicKey [1] IMPLICIT BIT STRING (0x04 || x || y, big-endian) */
    {
        uint32_t pub_len = 1 + size * 2;
        uint8_t pub_buf[256];
        if (pub_len > sizeof(pub_buf)) return 0;
        pub_buf[0] = 0x04;
        memcpy(pub_buf + 1, key->Q.x, size);
        memcpy(pub_buf + 1 + size, key->Q.y, size);
        uint8_t bs_buf[268];
        uint32_t bs_len = noxtls_asn1_put_bit_string(bs_buf, sizeof(bs_buf), pub_buf, pub_len);
        if (bs_len == 0) return 0;
        uint8_t expl1[280];
        uint32_t expl1_len = noxtls_asn1_put_explicit(expl1, sizeof(expl1), 1, bs_buf, bs_len);
        if (expl1_len == 0 || content_len + expl1_len > sizeof(content_buf)) return 0;
        memcpy(content_buf + content_len, expl1, expl1_len);
        content_len += expl1_len;
    }
    return noxtls_asn1_put_sequence(out, out_max, content_buf, content_len);
}

/* Encode SubjectPublicKeyInfo (DER) for RSA: SEQUENCE { AlgorithmIdentifier(rsaEncryption,NULL), BIT STRING(RSAPublicKey) }. */
/**
 * @brief Encode SubjectPublicKeyInfo (DER) for RSA: SEQUENCE { AlgorithmIdentifier(rsaEncryption,NULL), BIT STRING(RSAPublicKey) }.
 *
 * @param[in] key The RSA key to encode
 * @param[out] out The buffer to encode the RSA key into
 * @param[in] out_max The maximum length of the buffer
 * @return The length of the encoded RSA key
 */
static uint32_t encode_rsa_public_spki_der(const rsa_key_t *key, uint8_t *out, uint32_t out_max)
{
    if (key == NULL || out == NULL || out_max < 200) {
        return 0;
    }
    uint32_t key_bytes = key->key_bytes;
    /* PKCS#1 RSAPublicKey: SEQUENCE { n, e } */
    uint8_t rsa_content[PKCS1_MAX_BYTES];
    uint32_t rsa_content_len = 0;
    uint32_t n_len = noxtls_asn1_put_integer(rsa_content + rsa_content_len, sizeof(rsa_content) - rsa_content_len, key->n, key_bytes);
    if (n_len == 0) return 0;
    rsa_content_len += n_len;
    n_len = noxtls_asn1_put_integer(rsa_content + rsa_content_len, sizeof(rsa_content) - rsa_content_len, key->e, key_bytes);
    if (n_len == 0) return 0;
    rsa_content_len += n_len;
    uint8_t rsa_seq_buf[PKCS1_MAX_BYTES + 8];
    uint32_t rsa_seq_len = noxtls_asn1_put_sequence(rsa_seq_buf, sizeof(rsa_seq_buf), rsa_content, rsa_content_len);
    if (rsa_seq_len == 0) return 0;

    /* AlgorithmIdentifier: SEQUENCE { rsaEncryption OID, NULL } */
    uint8_t oid_der[32];
    uint32_t oid_len = noxtls_asn1_put_oid_raw(oid_der, sizeof(oid_der), oid_rsa_encryption, sizeof(oid_rsa_encryption));
    if (oid_len == 0) return 0;
    const uint8_t null_der[] = { 0x05, 0x00 };
    uint8_t alg_content[64];
    uint32_t alg_content_len = 0;
    memcpy(alg_content + alg_content_len, oid_der, oid_len);
    alg_content_len += oid_len;
    memcpy(alg_content + alg_content_len, null_der, sizeof(null_der));
    alg_content_len += sizeof(null_der);
    uint8_t alg_seq[80];
    uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), alg_content, alg_content_len);
    if (alg_seq_len == 0) return 0;

    uint8_t bs_buf[PKCS1_MAX_BYTES + 8];
    uint32_t bs_len = noxtls_asn1_put_bit_string(bs_buf, sizeof(bs_buf), rsa_seq_buf, rsa_seq_len);
    if (bs_len == 0) return 0;

    uint8_t spki_content[SPKI_MAX_BYTES];
    if (alg_seq_len + bs_len > sizeof(spki_content)) return 0;
    memcpy(spki_content, alg_seq, alg_seq_len);
    memcpy(spki_content + alg_seq_len, bs_buf, bs_len);
    return noxtls_asn1_put_sequence(out, out_max, spki_content, alg_seq_len + bs_len);
}

/* Encode SubjectPublicKeyInfo (DER) for EC: SEQUENCE { AlgorithmIdentifier(id-ecPublicKey, curveOID), BIT STRING(0x04||x||y) }. */
/**
 * @brief Encode SubjectPublicKeyInfo (DER) for EC: SEQUENCE { AlgorithmIdentifier(id-ecPublicKey, curveOID), BIT STRING(0x04||x||y) }.
 *
 * @param[in] key The ECC key to encode
 * @param[in] curve_oid The OID of the curve
 * @param[in] curve_oid_len The length of the OID of the curve
 * @param[out] out The buffer to encode the ECC key into
 * @param[in] out_max The maximum length of the buffer
 * @return The length of the encoded ECC key
 */
static uint32_t encode_ec_public_spki_der(const ecc_key_t *key, const uint8_t *curve_oid, uint32_t curve_oid_len, uint8_t *out, uint32_t out_max)
{
    if (key == NULL || key->curve == NULL || curve_oid == NULL || out == NULL || out_max < 256) {
        return 0;
    }
    uint32_t size = key->curve->size;
    uint8_t pub_buf[256];
    if (1 + size * 2 > sizeof(pub_buf)) return 0;
    pub_buf[0] = 0x04;
    memcpy(pub_buf + 1, key->Q.x, size);
    memcpy(pub_buf + 1 + size, key->Q.y, size);
    uint32_t pub_len = 1 + size * 2;

    uint8_t oid_ec_der[32];
    uint32_t oid_ec_len = noxtls_asn1_put_oid_raw(oid_ec_der, sizeof(oid_ec_der), oid_id_ec_public_key, sizeof(oid_id_ec_public_key));
    if (oid_ec_len == 0) return 0;
    uint8_t curve_oid_der[48];
    uint32_t curve_oid_len_der = noxtls_asn1_put_oid_raw(curve_oid_der, sizeof(curve_oid_der), curve_oid, curve_oid_len);
    if (curve_oid_len_der == 0) return 0;
    uint8_t alg_content[96];
    uint32_t alg_content_len = 0;
    memcpy(alg_content + alg_content_len, oid_ec_der, oid_ec_len);
    alg_content_len += oid_ec_len;
    memcpy(alg_content + alg_content_len, curve_oid_der, curve_oid_len_der);
    alg_content_len += curve_oid_len_der;
    uint8_t alg_seq[128];
    uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), alg_content, alg_content_len);
    if (alg_seq_len == 0) return 0;

    uint8_t bs_buf[280];
    uint32_t bs_len = noxtls_asn1_put_bit_string(bs_buf, sizeof(bs_buf), pub_buf, pub_len);
    if (bs_len == 0) return 0;

    uint8_t spki_content[512];
    if (alg_seq_len + bs_len > sizeof(spki_content)) return 0;
    memcpy(spki_content, alg_seq, alg_seq_len);
    memcpy(spki_content + alg_seq_len, bs_buf, bs_len);
    return noxtls_asn1_put_sequence(out, out_max, spki_content, alg_seq_len + bs_len);
}

/* PKCS#8 PrivateKeyInfo for Ed25519 / Ed448 raw seed (RFC 8410). */
/**
 * @brief PKCS#8 PrivateKeyInfo for Ed25519 / Ed448 raw seed (RFC 8410).
 *
 * @param[in] alg_oid The OID of the algorithm
 * @param[in] alg_oid_len The length of the OID of the algorithm
 * @param[in] seed The seed to encode
 * @param[in] seed_len The length of the seed to encode
 * @param[out] out The buffer to encode the seed into
 * @param[in] out_max The maximum length of the buffer
 * @return The length of the encoded seed
 */
static uint32_t encode_pkcs8_eddsa_seed_der(const uint8_t *alg_oid, uint32_t alg_oid_len,
    const uint8_t *seed, uint32_t seed_len, uint8_t *out, uint32_t out_max)
{
    uint8_t ver[] = { 0x02, 0x01, 0x00 };
    uint8_t oid_enc[16];
    uint32_t oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), alg_oid, alg_oid_len);
    if (oid_enc_len == 0) return 0;
    uint8_t alg_seq[32];
    uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), oid_enc, oid_enc_len);
    if (alg_seq_len == 0) return 0;
    uint8_t sk_oct[80];
    uint32_t sk_oct_len = noxtls_asn1_put_octet_string(sk_oct, sizeof(sk_oct), seed, seed_len);
    if (sk_oct_len == 0) return 0;
    uint8_t inner[128];
    uint32_t il = 0;
    if (il + sizeof(ver) > sizeof(inner)) return 0;
    memcpy(inner + il, ver, sizeof(ver));
    il += (uint32_t)sizeof(ver);
    if (il + alg_seq_len > sizeof(inner)) return 0;
    memcpy(inner + il, alg_seq, alg_seq_len);
    il += alg_seq_len;
    if (il + sk_oct_len > sizeof(inner)) return 0;
    memcpy(inner + il, sk_oct, sk_oct_len);
    il += sk_oct_len;
    return noxtls_asn1_put_sequence(out, out_max, inner, il);
}

/* SubjectPublicKeyInfo: AlgorithmIdentifier(OID only) + BIT STRING(raw public key). */
/**
 * @brief SubjectPublicKeyInfo: AlgorithmIdentifier(OID only) + BIT STRING(raw public key).
 *
 * @param[in] alg_oid The OID of the algorithm
 * @param[in] alg_oid_len The length of the OID of the algorithm
 * @param[in] raw_pk The raw public key to encode
 * @param[in] raw_pk_len The length of the raw public key to encode
 * @param[out] out The buffer to encode the raw public key into
 * @param[in] out_max The maximum length of the buffer
 * @return The length of the encoded raw public key
 */
static uint32_t encode_eddsa_spki_der(const uint8_t *alg_oid, uint32_t alg_oid_len,
    const uint8_t *raw_pk, uint32_t raw_pk_len, uint8_t *out, uint32_t out_max)
{
    uint8_t oid_enc[16];
    uint32_t oid_enc_len = noxtls_asn1_put_oid_raw(oid_enc, sizeof(oid_enc), alg_oid, alg_oid_len);
    if (oid_enc_len == 0) return 0;
    uint8_t alg_seq[32];
    uint32_t alg_seq_len = noxtls_asn1_put_sequence(alg_seq, sizeof(alg_seq), oid_enc, oid_enc_len);
    if (alg_seq_len == 0) return 0;
    uint8_t bs_buf[80];
    uint32_t bs_len = noxtls_asn1_put_bit_string(bs_buf, sizeof(bs_buf), raw_pk, raw_pk_len);
    if (bs_len == 0) return 0;
    uint8_t spki_content[128];
    if (alg_seq_len + bs_len > sizeof(spki_content)) return 0;
    memcpy(spki_content, alg_seq, alg_seq_len);
    memcpy(spki_content + alg_seq_len, bs_buf, bs_len);
    return noxtls_asn1_put_sequence(out, out_max, spki_content, alg_seq_len + bs_len);
}

/* Return 1 if s (lowercase) equals "key", "pub", "pem", or "der". */
/**
 * @brief Return 1 if s (lowercase) equals "key", "pub", "pem", or "der".
 *
 * @param[in] s The string to check
 * @return 1 if s (lowercase) equals "key", "pub", "pem", or "der", 0 otherwise
 */
static int is_known_ext(const char *s)
{
    if (s[0] == 'k' && s[1] == 'e' && s[2] == 'y' && s[3] == '\0') return 1;
    if (s[0] == 'p' && s[1] == 'u' && s[2] == 'b' && s[3] == '\0') return 1;
    if (s[0] == 'p' && s[1] == 'e' && s[2] == 'm' && s[3] == '\0') return 1;
    if (s[0] == 'd' && s[1] == 'e' && s[2] == 'r' && s[3] == '\0') return 1;
    return 0;
}

/* Build key_path and pub_path from -out base name. Strips .key, .pub, .pem, .der from end. */
/**
 * @brief Build key_path and pub_path from -out base name. Strips .key, .pub, .pem, .der from end.
 *
 * @param[in] out_file The name of the output file
 * @param[out] key_path The path to the key file
 * @param[out] pub_path The path to the public key file
 * @param[in] path_max The maximum length of the path
 * @return void
 */
static void build_key_pub_paths(const char *out_file, char *key_path, char *pub_path, size_t path_max)
{
    if (out_file == NULL || key_path == NULL || pub_path == NULL || path_max == 0) {
        return;
    }
    /* Leave room for ".key" / ".pub" plus snprintf's terminating nul within path_max. */
    size_t max_base = path_max > 5 ? (size_t)path_max - 5U : 0U;
    if (max_base > CERTGEN_KEYPUB_BASE_MAX) {
        max_base = CERTGEN_KEYPUB_BASE_MAX;
    }
    if (max_base == 0U) {
        key_path[0] = '\0';
        pub_path[0] = '\0';
        return;
    }
    const char *last_slash = strrchr(out_file, '/');
#ifdef _WIN32
    const char *last_back = strrchr(out_file, '\\');
    if (last_back != NULL && (last_slash == NULL || last_back > last_slash)) {
        last_slash = last_back;
    }
#endif
    const char *last_dot = strrchr(out_file, '.');
    char base_buf[CERTGEN_KEYPUB_BASE_MAX + 1U];
    if (last_dot != NULL && last_dot > last_slash && last_dot[1] != '\0') {
        const char *suf = last_dot + 1;
        char suf_lower[8];
        size_t j = 0;
        while (j < sizeof(suf_lower) - 1 && suf[j] != '\0') {
            suf_lower[j] = (char)((suf[j] >= 'A' && suf[j] <= 'Z') ? suf[j] + 32 : suf[j]);
            j++;
        }
        suf_lower[j] = '\0';
        if (is_known_ext(suf_lower)) {
            size_t base_len = (size_t)(last_dot - out_file);
            if (base_len >= sizeof(base_buf)) base_len = sizeof(base_buf) - 1;
            if (base_len > max_base) base_len = max_base;
            memcpy(base_buf, out_file, base_len);
            base_buf[base_len] = '\0';
            snprintf(key_path, path_max, "%s.key", base_buf);
            snprintf(pub_path, path_max, "%s.pub", base_buf);
            return;
        }
    }
    {
        size_t ol = strlen(out_file);
        if (ol > max_base) ol = max_base;
        if (ol >= sizeof(base_buf)) ol = sizeof(base_buf) - 1;
        memcpy(base_buf, out_file, ol);
        base_buf[ol] = '\0';
        snprintf(key_path, path_max, "%s.key", base_buf);
        snprintf(pub_path, path_max, "%s.pub", base_buf);
    }
}

/* Write DER to file as PEM with given begin/end markers. Returns 0 on success. */
/**
 * @brief Write DER to file as PEM with given begin/end markers. Returns 0 on success.
 *
 * @param[in] fp The file pointer to write the DER to
 * @param[in] der_buf The buffer to write the DER to
 * @param[in] der_len The length of the DER to write
 * @param[in] begin The beginning of the PEM markers
 * @param[in] end The end of the PEM markers
 * @return 0 on success, -1 on failure
 */
static int write_der_as_pem(FILE *fp, const uint8_t *der_buf, uint32_t der_len, const char *begin, const char *end)
{
    if (fp == NULL || der_buf == NULL || begin == NULL || end == NULL) {
        return -1;
    }
    fputs(begin, fp);
    size_t b64_size = ((size_t)der_len + 2) / 3 * 4 + 4;
    char *b64 = (char *)malloc(b64_size);
    if (b64 == NULL) return -1;
    int b64_len = noxtls_base64_encode(der_buf, der_len, b64);
    if (b64_len > 0) {
        uint32_t written = 0;
        while (written < (uint32_t)b64_len) {
            uint32_t chunk = (uint32_t)(b64_len - written);
            if (chunk > 64) chunk = 64;
            fwrite(b64 + written, 1, chunk, fp);
            written += chunk;
            if (written < (uint32_t)b64_len) fputc('\n', fp);
        }
    }
    fputc('\n', fp);
    free(b64);
    fputs(end, fp);
    return 0;
}

/**
 * @brief Generate an ECC key
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The name of the program
 * @return 0 on success, -1 on failure
 */
static int cmd_genec(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    ecc_curve_t curve_type = NOXTLS_ECC_SECP256R1;
    const uint8_t *curve_oid = oid_secp256r1;
    uint32_t curve_oid_len = sizeof(oid_secp256r1);
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if (strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        } else if (strcmp(argv[i], "-curve") == 0 && i + 1 < argc) {
            const char *curve = argv[++i];
            if (strcmp(curve, "secp192r1") == 0 || strcmp(curve, "prime192v1") == 0 || strcmp(curve, "P-192") == 0) {
                curve_type = NOXTLS_ECC_SECP192R1;
                curve_oid = oid_secp192r1;
                curve_oid_len = sizeof(oid_secp192r1);
            } else if (strcmp(curve, "secp224r1") == 0 || strcmp(curve, "P-224") == 0) {
                curve_type = NOXTLS_ECC_SECP224R1;
                curve_oid = oid_secp224r1;
                curve_oid_len = sizeof(oid_secp224r1);
            } else if (strcmp(curve, "prime256v1") == 0 || strcmp(curve, "secp256r1") == 0 || strcmp(curve, "P-256") == 0) {
                curve_type = NOXTLS_ECC_SECP256R1;
                curve_oid = oid_secp256r1;
                curve_oid_len = sizeof(oid_secp256r1);
            } else if (strcmp(curve, "secp384r1") == 0 || strcmp(curve, "P-384") == 0) {
                curve_type = NOXTLS_ECC_SECP384R1;
                curve_oid = oid_secp384r1;
                curve_oid_len = sizeof(oid_secp384r1);
            } else if (strcmp(curve, "secp521r1") == 0 || strcmp(curve, "P-521") == 0) {
                curve_type = NOXTLS_ECC_SECP521R1;
                curve_oid = oid_secp521r1;
                curve_oid_len = sizeof(oid_secp521r1);
            } else if (strcmp(curve, "brainpoolP256r1") == 0 || strcmp(curve, "bp256r1") == 0) {
                curve_type = NOXTLS_ECC_BP256R1;
                curve_oid = oid_bp256r1;
                curve_oid_len = sizeof(oid_bp256r1);
            } else if (strcmp(curve, "brainpoolP384r1") == 0 || strcmp(curve, "bp384r1") == 0) {
                curve_type = NOXTLS_ECC_BP384R1;
                curve_oid = oid_bp384r1;
                curve_oid_len = sizeof(oid_bp384r1);
            } else if (strcmp(curve, "brainpoolP512r1") == 0 || strcmp(curve, "bp512r1") == 0) {
                curve_type = NOXTLS_ECC_BP512R1;
                curve_oid = oid_bp512r1;
                curve_oid_len = sizeof(oid_bp512r1);
            } else if (strcmp(curve, "secp192k1") == 0) {
                curve_type = NOXTLS_ECC_SECP192K1;
                curve_oid = oid_secp192k1;
                curve_oid_len = sizeof(oid_secp192k1);
            } else if (strcmp(curve, "secp224k1") == 0) {
                curve_type = NOXTLS_ECC_SECP224K1;
                curve_oid = oid_secp224k1;
                curve_oid_len = sizeof(oid_secp224k1);
            } else if (strcmp(curve, "secp256k1") == 0) {
                curve_type = NOXTLS_ECC_SECP256K1;
                curve_oid = oid_secp256k1;
                curve_oid_len = sizeof(oid_secp256k1);
            } else {
                fprintf(stderr, "Error: unsupported -curve value '%s'\n", curve);
                return 1;
            }
        }
    }

    ecc_key_t key;
    if (noxtls_ecc_key_init(&key, curve_type) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Failed to init ECC key\n");
        return 1;
    }
    {
        const char *curve_name = "prime256v1";
        switch (curve_type) {
            case NOXTLS_ECC_SECP192R1: curve_name = "secp192r1"; break;
            case NOXTLS_ECC_SECP224R1: curve_name = "secp224r1"; break;
            case NOXTLS_ECC_SECP256R1: curve_name = "prime256v1"; break;
            case NOXTLS_ECC_SECP384R1: curve_name = "secp384r1"; break;
            case NOXTLS_ECC_SECP521R1: curve_name = "secp521r1"; break;
            case NOXTLS_ECC_BP256R1: curve_name = "brainpoolP256r1"; break;
            case NOXTLS_ECC_BP384R1: curve_name = "brainpoolP384r1"; break;
            case NOXTLS_ECC_BP512R1: curve_name = "brainpoolP512r1"; break;
            case NOXTLS_ECC_SECP192K1: curve_name = "secp192k1"; break;
            case NOXTLS_ECC_SECP224K1: curve_name = "secp224k1"; break;
            case NOXTLS_ECC_SECP256K1: curve_name = "secp256k1"; break;
            default: break;
        }
        printf("Generating EC private key (%s)\n", curve_name);
    }
    if (noxtls_ecc_key_generate(&key, curve_type) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: EC key generation failed\n");
        noxtls_ecc_key_free(&key);
        return 1;
    }

    uint8_t der_buf[SEC1_ECC_MAX_BYTES];
    uint32_t der_len = encode_sec1_ecc_der(&key, curve_oid, curve_oid_len, der_buf, sizeof(der_buf));
    uint8_t pub_der_buf[512];
    uint32_t pub_der_len = encode_ec_public_spki_der(&key, curve_oid, curve_oid_len, pub_der_buf, sizeof(pub_der_buf));
    noxtls_ecc_key_free(&key);
    if (der_len == 0) {
        fprintf(stderr, "Error: Failed to encode EC key\n");
        return 1;
    }

    if (out_file == NULL) {
        FILE *fp = stdout;
        if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            if (fwrite(der_buf, 1, der_len, fp) != der_len) {
                fprintf(stderr, "Error: Write failed\n");
                return 1;
            }
        } else {
            if (write_der_as_pem(fp, der_buf, der_len, "-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n") != 0) {
                return 1;
            }
        }
        printf("Wrote stdout\n");
        return 0;
    }

    char key_path[CERTGEN_PATH_MAX];
    char pub_path[CERTGEN_PATH_MAX];
    build_key_pub_paths(out_file, key_path, pub_path, sizeof(key_path));

    FILE *fp_key = noxtls_fopen(key_path, "wb");
    if (fp_key == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", key_path);
        return 1;
    }
    if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
        if (fwrite(der_buf, 1, der_len, fp_key) != der_len) {
            fprintf(stderr, "Error: Write failed for %s\n", key_path);
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (%u bytes)\n", key_path, (unsigned)der_len);
    } else {
        if (write_der_as_pem(fp_key, der_buf, der_len, "-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n") != 0) {
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (PEM)\n", key_path);
    }
    fclose(fp_key);

    if (pub_der_len > 0) {
        FILE *fp_pub = noxtls_fopen(pub_path, "wb");
        if (fp_pub == NULL) {
            fprintf(stderr, "Error: Cannot open %s for writing\n", pub_path);
            return 1;
        }
        if (write_der_as_pem(fp_pub, pub_der_buf, pub_der_len, CERT_PUB_KEY_STR "\n", CERT_PUB_KEY_END "\n") != 0) {
            fclose(fp_pub);
            return 1;
        }
        fclose(fp_pub);
        printf("Wrote %s (PEM)\n", pub_path);
    }
    return 0;
}

/**
 * @brief Generate a Ed25519 key pair
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The program name
 * @return 0 on success, -1 on failure
 */
static int cmd_gened25519(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if (strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        }
    }
    uint8_t sk[32];
    uint8_t pk[32];
    if (noxtls_ed25519_generate_key(sk, pk) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Ed25519 key generation failed\n");
        return 1;
    }
    uint8_t pkcs8[128];
    uint32_t pkcs8_len = encode_pkcs8_eddsa_seed_der(oid_ed25519, sizeof(oid_ed25519), sk, 32, pkcs8, sizeof(pkcs8));
    uint8_t spki[128];
    uint32_t spki_len = encode_eddsa_spki_der(oid_ed25519, sizeof(oid_ed25519), pk, 32, spki, sizeof(spki));
    if (pkcs8_len == 0 || spki_len == 0) {
        fprintf(stderr, "Error: DER encode failed\n");
        return 1;
    }
    printf("Generating Ed25519 key pair\n");
    if (out_file == NULL) {
        FILE *fp = stdout;
        if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            fwrite(pkcs8, 1, pkcs8_len, fp);
        } else if (write_der_as_pem(fp, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            return 1;
        }
        printf("Wrote Ed25519 private key to stdout\n");
        return 0;
    }
    char key_path[CERTGEN_PATH_MAX];
    char pub_path[CERTGEN_PATH_MAX];
    build_key_pub_paths(out_file, key_path, pub_path, sizeof(key_path));
    FILE *fp_key = noxtls_fopen(key_path, "wb");
    if (fp_key == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", key_path);
        return 1;
    }
    if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
        if (fwrite(pkcs8, 1, pkcs8_len, fp_key) != pkcs8_len) {
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (%u bytes)\n", key_path, (unsigned)pkcs8_len);
    } else {
        if (write_der_as_pem(fp_key, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (PEM PKCS#8)\n", key_path);
    }
    fclose(fp_key);
    FILE *fp_pub = noxtls_fopen(pub_path, "wb");
    if (fp_pub == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", pub_path);
        return 1;
    }
    if (write_der_as_pem(fp_pub, spki, spki_len, CERT_PUB_KEY_STR "\n", CERT_PUB_KEY_END "\n") != 0) {
        fclose(fp_pub);
        return 1;
    }
    fclose(fp_pub);
    printf("Wrote %s (PEM SPKI)\n", pub_path);
    return 0;
}

#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
/**
 * @brief Generate an Ed448 key pair (PKCS#8 seed + RFC 8410 SPKI .pub).
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The program name
 * @return 0 on success, 1 on failure
 */
static int cmd_gened448(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if (strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        }
    }
    uint8_t sk[57];
    uint8_t pk[57];
    if (noxtls_ed448_generate_key(sk, pk) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Ed448 key generation failed\n");
        return 1;
    }
    uint8_t pkcs8[160];
    uint32_t pkcs8_len = encode_pkcs8_eddsa_seed_der(oid_ed448, sizeof(oid_ed448), sk, 57, pkcs8, sizeof(pkcs8));
    uint8_t spki[200];
    uint32_t spki_len = encode_eddsa_spki_der(oid_ed448, sizeof(oid_ed448), pk, 57, spki, sizeof(spki));
    if (pkcs8_len == 0 || spki_len == 0) {
        fprintf(stderr, "Error: DER encode failed\n");
        return 1;
    }
    printf("Generating Ed448 key pair\n");
    if (out_file == NULL) {
        FILE *fp = stdout;
        if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            fwrite(pkcs8, 1, pkcs8_len, fp);
        } else if (write_der_as_pem(fp, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            return 1;
        }
        printf("Wrote Ed448 private key to stdout\n");
        return 0;
    }
    char key_path[CERTGEN_PATH_MAX];
    char pub_path[CERTGEN_PATH_MAX];
    build_key_pub_paths(out_file, key_path, pub_path, sizeof(key_path));
    FILE *fp_key = noxtls_fopen(key_path, "wb");
    if (fp_key == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", key_path);
        return 1;
    }
    if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
        if (fwrite(pkcs8, 1, pkcs8_len, fp_key) != pkcs8_len) {
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (%u bytes)\n", key_path, (unsigned)pkcs8_len);
    } else {
        if (write_der_as_pem(fp_key, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (PEM PKCS#8)\n", key_path);
    }
    fclose(fp_key);
    FILE *fp_pub = noxtls_fopen(pub_path, "wb");
    if (fp_pub == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", pub_path);
        return 1;
    }
    if (write_der_as_pem(fp_pub, spki, spki_len, CERT_PUB_KEY_STR "\n", CERT_PUB_KEY_END "\n") != 0) {
        fclose(fp_pub);
        return 1;
    }
    fclose(fp_pub);
    printf("Wrote %s (PEM SPKI)\n", pub_path);
    return 0;
}
#endif

#if NOXTLS_FEATURE_ML_DSA
/**
 * @brief Map an ML-DSA parameter name to enum and OID.
 *
 * @param[in] name Parameter set name (e.g. "ml-dsa-65", "mldsa65").
 * @param[out] out_param Resolved ML-DSA parameter enum.
 * @param[out] out_oid Pointer to the DER OID bytes.
 * @param[out] out_oid_len Length of the OID in bytes.
 * @return 0 on success, -1 if @p name is not recognized
 */
static int mldsa_param_from_name(const char *name, noxtls_mldsa_param_t *out_param,
                                 const uint8_t **out_oid, uint32_t *out_oid_len)
{
    if(strcmp(name, "ml-dsa-44") == 0 || strcmp(name, "mldsa44") == 0) {
        *out_param = NOXTLS_MLDSA_44; *out_oid = oid_ml_dsa_44; *out_oid_len = sizeof(oid_ml_dsa_44); return 0;
    }
    if(strcmp(name, "ml-dsa-65") == 0 || strcmp(name, "mldsa65") == 0) {
        *out_param = NOXTLS_MLDSA_65; *out_oid = oid_ml_dsa_65; *out_oid_len = sizeof(oid_ml_dsa_65); return 0;
    }
    if(strcmp(name, "ml-dsa-87") == 0 || strcmp(name, "mldsa87") == 0) {
        *out_param = NOXTLS_MLDSA_87; *out_oid = oid_ml_dsa_87; *out_oid_len = sizeof(oid_ml_dsa_87); return 0;
    }
    return -1;
}

/**
 * @brief Generate an ML-DSA (FIPS 204) post-quantum key pair.
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The program name
 * @return 0 on success, 1 on failure
 */
static int cmd_genmldsa(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    noxtls_mldsa_param_t param = NOXTLS_MLDSA_65;
    const uint8_t *param_oid = oid_ml_dsa_65;
    uint32_t param_oid_len = sizeof(oid_ml_dsa_65);
    uint32_t sk_len;
    uint32_t pk_len;
    uint8_t *sk = NULL;
    uint8_t *pk = NULL;
    uint8_t *pkcs8 = NULL;
    uint32_t pkcs8_len = 0;
    uint32_t pkcs8_max;
    uint8_t *spki = NULL;
    uint32_t spki_len = 0;
    uint32_t spki_max;
    int rc = 1;
    int i;

    for(i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if(strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        } else if(strcmp(argv[i], "-param") == 0 && i + 1 < argc) {
            if(mldsa_param_from_name(argv[++i], &param, &param_oid, &param_oid_len) != 0) {
                fprintf(stderr, "Error: unsupported -param value '%s'\n", argv[i]);
                return 1;
            }
        }
    }

    sk_len = noxtls_mldsa_secret_key_len(param);
    pk_len = noxtls_mldsa_public_key_len(param);
    if(sk_len == 0 || pk_len == 0) {
        fprintf(stderr, "Error: unsupported ML-DSA parameter set\n");
        return 1;
    }
    /* PKCS#8 wrapper + OID overhead is well under 32B */
    pkcs8_max = sk_len + 64;
    /* SPKI wrapper + OID overhead is well under 64B */
    spki_max = pk_len + 80;
    sk = (uint8_t *)malloc(sk_len);
    pk = (uint8_t *)malloc(pk_len);
    pkcs8 = (uint8_t *)malloc(pkcs8_max);
    spki = (uint8_t *)malloc(spki_max);
    if(sk == NULL || pk == NULL || pkcs8 == NULL || spki == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto done;
    }

    printf("Generating ML-DSA key pair (param=%d)\n", (int)param);
    if(noxtls_mldsa_keygen(param, pk, sk) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: ML-DSA key generation failed\n");
        goto done;
    }

    pkcs8_len = encode_pkcs8_eddsa_seed_der(param_oid, param_oid_len, sk, sk_len, pkcs8, pkcs8_max);
    spki_len = encode_eddsa_spki_der(param_oid, param_oid_len, pk, pk_len, spki, spki_max);
    if(pkcs8_len == 0 || spki_len == 0) {
        fprintf(stderr, "Error: DER encode failed\n");
        goto done;
    }

    if(out_file == NULL) {
        FILE *fp = stdout;
        if(strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            fwrite(pkcs8, 1, pkcs8_len, fp);
        } else if(write_der_as_pem(fp, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            goto done;
        }
        printf("Wrote ML-DSA private key to stdout\n");
        rc = 0;
        goto done;
    }

    {
        char key_path[CERTGEN_PATH_MAX];
        char pub_path[CERTGEN_PATH_MAX];
        FILE *fp_key;
        FILE *fp_pub;
        build_key_pub_paths(out_file, key_path, pub_path, sizeof(key_path));
        fp_key = noxtls_fopen(key_path, "wb");
        if(fp_key == NULL) {
            fprintf(stderr, "Error: Cannot open %s for writing\n", key_path);
            goto done;
        }
        if(strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            fwrite(pkcs8, 1, pkcs8_len, fp_key);
            printf("Wrote %s (%u bytes DER PKCS#8)\n", key_path, (unsigned)pkcs8_len);
        } else if(write_der_as_pem(fp_key, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            fclose(fp_key);
            goto done;
        } else {
            printf("Wrote %s (PEM PKCS#8)\n", key_path);
        }
        fclose(fp_key);
        fp_pub = noxtls_fopen(pub_path, "wb");
        if(fp_pub == NULL) {
            fprintf(stderr, "Error: Cannot open %s for writing\n", pub_path);
            goto done;
        }
        if(write_der_as_pem(fp_pub, spki, spki_len, CERT_PUB_KEY_STR "\n", CERT_PUB_KEY_END "\n") != 0) {
            fclose(fp_pub);
            goto done;
        }
        fclose(fp_pub);
        printf("Wrote %s (PEM SPKI)\n", pub_path);
    }
    rc = 0;

done:
    if(sk != NULL) { memset(sk, 0, sk_len); free(sk); }
    if(pk != NULL) free(pk);
    if(pkcs8 != NULL) { memset(pkcs8, 0, pkcs8_max); free(pkcs8); }
    if(spki != NULL) free(spki);
    return rc;
}
#endif /* NOXTLS_FEATURE_ML_DSA */

#if NOXTLS_FEATURE_SLH_DSA
/**
 * @brief Map an SLH-DSA parameter name to enum and OID.
 *
 * @param[in] name Parameter set name (e.g. "slh-dsa-sha2-128s").
 * @param[out] out_param Resolved SLH-DSA parameter enum.
 * @param[out] out_oid Pointer to the DER OID bytes.
 * @param[out] out_oid_len Length of the OID in bytes.
 * @return 0 on success, -1 if @p name is not recognized
 */
static int slhdsa_param_from_name(const char *name, noxtls_slhdsa_param_t *out_param,
                                  const uint8_t **out_oid, uint32_t *out_oid_len)
{
#define MATCH_SLH(n, e, oid_arr) \
    if(strcmp(name, (n)) == 0) { *out_param = (e); *out_oid = (oid_arr); *out_oid_len = sizeof(oid_arr); return 0; }
    MATCH_SLH("slh-dsa-sha2-128s", NOXTLS_SLHDSA_SHA2_128S, oid_slh_dsa_sha2_128s)
    MATCH_SLH("slh-dsa-sha2-128f", NOXTLS_SLHDSA_SHA2_128F, oid_slh_dsa_sha2_128f)
    MATCH_SLH("slh-dsa-sha2-192s", NOXTLS_SLHDSA_SHA2_192S, oid_slh_dsa_sha2_192s)
    MATCH_SLH("slh-dsa-sha2-192f", NOXTLS_SLHDSA_SHA2_192F, oid_slh_dsa_sha2_192f)
    MATCH_SLH("slh-dsa-sha2-256s", NOXTLS_SLHDSA_SHA2_256S, oid_slh_dsa_sha2_256s)
    MATCH_SLH("slh-dsa-sha2-256f", NOXTLS_SLHDSA_SHA2_256F, oid_slh_dsa_sha2_256f)
    MATCH_SLH("slh-dsa-shake-128s", NOXTLS_SLHDSA_SHAKE_128S, oid_slh_dsa_shake_128s)
    MATCH_SLH("slh-dsa-shake-128f", NOXTLS_SLHDSA_SHAKE_128F, oid_slh_dsa_shake_128f)
    MATCH_SLH("slh-dsa-shake-192s", NOXTLS_SLHDSA_SHAKE_192S, oid_slh_dsa_shake_192s)
    MATCH_SLH("slh-dsa-shake-192f", NOXTLS_SLHDSA_SHAKE_192F, oid_slh_dsa_shake_192f)
    MATCH_SLH("slh-dsa-shake-256s", NOXTLS_SLHDSA_SHAKE_256S, oid_slh_dsa_shake_256s)
    MATCH_SLH("slh-dsa-shake-256f", NOXTLS_SLHDSA_SHAKE_256F, oid_slh_dsa_shake_256f)
#undef MATCH_SLH
    return -1;
}

/**
 * @brief Generate an SLH-DSA (FIPS 205) post-quantum key pair.
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The program name
 * @return 0 on success, 1 on failure
 */
static int cmd_genslhdsa(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    noxtls_slhdsa_param_t param = NOXTLS_SLHDSA_SHA2_128S;
    const uint8_t *param_oid = oid_slh_dsa_sha2_128s;
    uint32_t param_oid_len = sizeof(oid_slh_dsa_sha2_128s);
    uint32_t sk_len;
    uint32_t pk_len;
    uint8_t *sk = NULL;
    uint8_t *pk = NULL;
    uint8_t *pkcs8 = NULL;
    uint32_t pkcs8_len = 0;
    uint32_t pkcs8_max;
    uint8_t *spki = NULL;
    uint32_t spki_len = 0;
    uint32_t spki_max;
    int rc = 1;
    int i;

    for(i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if(strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        } else if(strcmp(argv[i], "-param") == 0 && i + 1 < argc) {
            if(slhdsa_param_from_name(argv[++i], &param, &param_oid, &param_oid_len) != 0) {
                fprintf(stderr, "Error: unsupported -param value '%s'\n", argv[i]);
                return 1;
            }
        }
    }

    sk_len = noxtls_slhdsa_secret_key_len(param);
    pk_len = noxtls_slhdsa_public_key_len(param);
    if(sk_len == 0 || pk_len == 0) {
        fprintf(stderr, "Error: unsupported SLH-DSA parameter set\n");
        return 1;
    }
    pkcs8_max = sk_len + 64;
    spki_max = pk_len + 80;
    sk = (uint8_t *)malloc(sk_len);
    pk = (uint8_t *)malloc(pk_len);
    pkcs8 = (uint8_t *)malloc(pkcs8_max);
    spki = (uint8_t *)malloc(spki_max);
    if(sk == NULL || pk == NULL || pkcs8 == NULL || spki == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        goto done;
    }

    printf("Generating SLH-DSA key pair (param=%d)\n", (int)param);
    if(noxtls_slhdsa_keygen(param, pk, sk) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: SLH-DSA key generation failed\n");
        goto done;
    }

    pkcs8_len = encode_pkcs8_eddsa_seed_der(param_oid, param_oid_len, sk, sk_len, pkcs8, pkcs8_max);
    spki_len = encode_eddsa_spki_der(param_oid, param_oid_len, pk, pk_len, spki, spki_max);
    if(pkcs8_len == 0 || spki_len == 0) {
        fprintf(stderr, "Error: DER encode failed\n");
        goto done;
    }

    if(out_file == NULL) {
        FILE *fp = stdout;
        if(strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            fwrite(pkcs8, 1, pkcs8_len, fp);
        } else if(write_der_as_pem(fp, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            goto done;
        }
        printf("Wrote SLH-DSA private key to stdout\n");
        rc = 0;
        goto done;
    }

    {
        char key_path[CERTGEN_PATH_MAX];
        char pub_path[CERTGEN_PATH_MAX];
        FILE *fp_key;
        FILE *fp_pub;
        build_key_pub_paths(out_file, key_path, pub_path, sizeof(key_path));
        fp_key = noxtls_fopen(key_path, "wb");
        if(fp_key == NULL) {
            fprintf(stderr, "Error: Cannot open %s for writing\n", key_path);
            goto done;
        }
        if(strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            fwrite(pkcs8, 1, pkcs8_len, fp_key);
            printf("Wrote %s (%u bytes DER PKCS#8)\n", key_path, (unsigned)pkcs8_len);
        } else if(write_der_as_pem(fp_key, pkcs8, pkcs8_len, "-----BEGIN PRIVATE KEY-----\n", "-----END PRIVATE KEY-----\n") != 0) {
            fclose(fp_key);
            goto done;
        } else {
            printf("Wrote %s (PEM PKCS#8)\n", key_path);
        }
        fclose(fp_key);
        fp_pub = noxtls_fopen(pub_path, "wb");
        if(fp_pub == NULL) {
            fprintf(stderr, "Error: Cannot open %s for writing\n", pub_path);
            goto done;
        }
        if(write_der_as_pem(fp_pub, spki, spki_len, CERT_PUB_KEY_STR "\n", CERT_PUB_KEY_END "\n") != 0) {
            fclose(fp_pub);
            goto done;
        }
        fclose(fp_pub);
        printf("Wrote %s (PEM SPKI)\n", pub_path);
    }
    rc = 0;

done:
    if(sk != NULL) { memset(sk, 0, sk_len); free(sk); }
    if(pk != NULL) free(pk);
    if(pkcs8 != NULL) { memset(pkcs8, 0, pkcs8_max); free(pkcs8); }
    if(spki != NULL) free(spki);
    return rc;
}
#endif /* NOXTLS_FEATURE_SLH_DSA */

/**
 * @brief Generate an RSA private key and optional public key file.
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The program name
 * @return 0 on success, 1 on failure
 */
static int cmd_genrsa(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    rsa_key_size_t bits = RSA_2048_BIT;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if (strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        } else if (strcmp(argv[i], "-bits") == 0 && i + 1 < argc) {
            int b = atoi(argv[++i]);
            if (b == 1024) bits = RSA_1024_BIT;
            else if (b == 2048) bits = RSA_2048_BIT;
            else if (b == 3072) bits = RSA_3072_BIT;
            else if (b == 4096) bits = RSA_4096_BIT;
            else {
                fprintf(stderr, "Error: -bits must be 1024, 2048, 3072, or 4096\n");
                return 1;
            }
        }
    }

    rsa_key_t key;
    if (noxtls_rsa_key_init(&key, bits) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Failed to init RSA key\n");
        return 1;
    }
    printf("Generating RSA private key, %u bit\n", (unsigned)bits);
    if (noxtls_rsa_key_generate(&key, bits) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Key generation failed\n");
        noxtls_rsa_key_free(&key);
        return 1;
    }

    uint8_t der_buf[PKCS1_MAX_BYTES];
    uint32_t der_len = encode_pkcs1_rsa_der(&key, der_buf, sizeof(der_buf));
    uint8_t pub_der_buf[SPKI_MAX_BYTES];
    uint32_t pub_der_len = encode_rsa_public_spki_der(&key, pub_der_buf, sizeof(pub_der_buf));
    noxtls_rsa_key_free(&key);
    if (der_len == 0) {
        fprintf(stderr, "Error: Failed to encode key\n");
        return 1;
    }

    if (out_file == NULL) {
        FILE *fp = stdout;
        if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
            if (fwrite(der_buf, 1, der_len, fp) != der_len) {
                fprintf(stderr, "Error: Write failed\n");
                return 1;
            }
        } else {
            if (write_der_as_pem(fp, der_buf, der_len, "-----BEGIN RSA PRIVATE KEY-----\n", "-----END RSA PRIVATE KEY-----\n") != 0) {
                return 1;
            }
        }
        printf("Wrote stdout\n");
        return 0;
    }

    char key_path[CERTGEN_PATH_MAX];
    char pub_path[CERTGEN_PATH_MAX];
    build_key_pub_paths(out_file, key_path, pub_path, sizeof(key_path));

    FILE *fp_key = noxtls_fopen(key_path, "wb");
    if (fp_key == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", key_path);
        return 1;
    }
    if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
        if (fwrite(der_buf, 1, der_len, fp_key) != der_len) {
            fprintf(stderr, "Error: Write failed for %s\n", key_path);
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (%u bytes)\n", key_path, (unsigned)der_len);
    } else {
        if (write_der_as_pem(fp_key, der_buf, der_len, "-----BEGIN RSA PRIVATE KEY-----\n", "-----END RSA PRIVATE KEY-----\n") != 0) {
            fclose(fp_key);
            return 1;
        }
        printf("Wrote %s (PEM)\n", key_path);
    }
    fclose(fp_key);

    if (pub_der_len > 0) {
        FILE *fp_pub = noxtls_fopen(pub_path, "wb");
        if (fp_pub == NULL) {
            fprintf(stderr, "Error: Cannot open %s for writing\n", pub_path);
            return 1;
        }
        if (write_der_as_pem(fp_pub, pub_der_buf, pub_der_len, CERT_PUB_KEY_STR "\n", CERT_PUB_KEY_END "\n") != 0) {
            fclose(fp_pub);
            return 1;
        }
        fclose(fp_pub);
        printf("Wrote %s (PEM)\n", pub_path);
    }
    return 0;
}

/* OIDs for ECC self-signed cert (id-ecPublicKey, ecdsa-with-SHA256) */
#if NOXTLS_HAVE_CERT_WRITE
/* Extract CN value from OpenSSL-style -subj (e.g. /CN=localhost or CN=localhost). Puts result in cn_out, max cn_size. */
/**
 * @brief Extract the CN value from a subject
 *
 * @param[in] subj The subject
 * @param[out] cn_out The CN value
 * @param[in] cn_size The size of the CN value
 * @return void
 */
static void extract_cn_from_subj(const char *subj, char *cn_out, size_t cn_size)
{
    const char *p = subj;
    if (cn_out == NULL || cn_size == 0) return;
    cn_out[0] = '\0';
    while (*p == '/' || *p == ' ') p++;
    if ((p[0] == 'C' || p[0] == 'c') && (p[1] == 'N' || p[1] == 'n') && p[2] == '=') {
        p += 3;
        size_t i = 0;
        while (i + 1 < cn_size && *p && *p != '/' && *p != ' ') {
            cn_out[i++] = *p++;
        }
        cn_out[i] = '\0';
        return;
    }
    /* Fallback: use whole string (strip leading /) */
    while (*p == '/') p++;
    strncpy(cn_out, p, cn_size - 1);
    cn_out[cn_size - 1] = '\0';
}

/* ecdsa-with-SHA256 OID (1.2.840.10045.4.3.2) for ECC self-signed certificates. */
static const uint8_t oid_ecdsa_sha256[]     = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
/* Largest in-flight cert. Grows automatically when PQC signatures are enabled
 * (SLH-DSA signatures can exceed 49 KB). Heap-allocated below; not on the stack. */
#if NOXTLS_FEATURE_SLH_DSA
#define CERTGEN_CERT_DER_MAX  (64U * 1024U)
#elif NOXTLS_FEATURE_ML_DSA
#define CERTGEN_CERT_DER_MAX  (16U * 1024U)
#else
#define CERTGEN_CERT_DER_MAX  4096u
#endif
#define CERTGEN_PEM_MAX       (CERTGEN_CERT_DER_MAX * 2U)

/**
 * @brief Generate a self-signed X.509 certificate
 *
 * @param[in] cn_buf The common name to use in the certificate
 * @param[in] days The number of days to sign the certificate for
 * @param[in] subject_pk_oid The OID of the subject public key
 * @param[in] subject_pk_oid_len The length of the OID of the subject public key
 * @param[in] subject_pk_params The parameters of the subject public key
 * @param[in] subject_pk_params_len The length of the parameters of the subject public key
 * @param[in] subject_pk The subject public key
 * @param[in] subject_pk_len The length of the subject public key
 * @param[in] sig_oid The OID of the signature algorithm
 * @param[in] sig_oid_len The length of the OID of the signature algorithm
 * @param[in] sign_key_der The DER encoded signature key
 * @param[in] sign_key_der_len The length of the DER encoded signature key
 * @param[in] hash_algo The hash algorithm to use for the signature
 * @param[in] out_file The name of the output file
 * @param[in] outform The format of the output file
 * @return 0 on success, -1 on failure
 */
static int certgen_self_signed_x509_common(
    const char *cn_buf,
    int days,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk_params, uint32_t subject_pk_params_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key_der, uint32_t sign_key_der_len,
    noxtls_hash_algos_t hash_algo,
    const char *out_file,
    const char *outform)
{
    uint8_t issuer_der[256];
    uint8_t subject_der[256];
    uint32_t issuer_len = 0;
    uint32_t subject_len = 0;
    noxtls_return_t rc = noxtls_x509_dn_from_cn(cn_buf, issuer_der, sizeof(issuer_der), &issuer_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Failed to build issuer DN\n");
        return 1;
    }
    rc = noxtls_x509_dn_from_cn(cn_buf, subject_der, sizeof(subject_der), &subject_len);
    if (rc != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Failed to build subject DN\n");
        return 1;
    }

    char not_before[16];
    char not_after[16];
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        fprintf(stderr, "Error: time() failed\n");
        return 1;
    }
#ifdef _MSC_VER
    struct tm tm_before;
    struct tm tm_after;
    if (gmtime_s(&tm_before, &now) != 0) {
        fprintf(stderr, "Error: gmtime failed\n");
        return 1;
    }
    time_t end = now + (time_t)days * 24 * 3600;
    if (gmtime_s(&tm_after, &end) != 0) {
        fprintf(stderr, "Error: gmtime failed\n");
        return 1;
    }
    snprintf(not_before, sizeof(not_before), "%02d%02d%02d%02d%02d%02dZ",
        tm_before.tm_year % 100, tm_before.tm_mon + 1, tm_before.tm_mday,
        tm_before.tm_hour, tm_before.tm_min, tm_before.tm_sec);
    snprintf(not_after, sizeof(not_after), "%02d%02d%02d%02d%02d%02dZ",
        tm_after.tm_year % 100, tm_after.tm_mon + 1, tm_after.tm_mday,
        tm_after.tm_hour, tm_after.tm_min, tm_after.tm_sec);
#else
    struct tm *tm_before = gmtime(&now);
    if (tm_before == NULL) {
        fprintf(stderr, "Error: gmtime failed\n");
        return 1;
    }
    time_t end = now + (time_t)days * 24 * 3600;
    struct tm *tm_after = gmtime(&end);
    if (tm_after == NULL) {
        fprintf(stderr, "Error: gmtime failed\n");
        return 1;
    }
    snprintf(not_before, sizeof(not_before), "%02d%02d%02d%02d%02d%02dZ",
        tm_before->tm_year % 100, tm_before->tm_mon + 1, tm_before->tm_mday,
        tm_before->tm_hour, tm_before->tm_min, tm_before->tm_sec);
    snprintf(not_after, sizeof(not_after), "%02d%02d%02d%02d%02d%02dZ",
        tm_after->tm_year % 100, tm_after->tm_mon + 1, tm_after->tm_mday,
        tm_after->tm_hour, tm_after->tm_min, tm_after->tm_sec);
#endif

    uint8_t serial[20] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    uint8_t *cert_der = NULL;
    uint32_t cert_der_len = 0;
    uint8_t *pem_buf = NULL;
    FILE *fp = NULL;
    int ret = 1;

    cert_der = (uint8_t *)malloc(CERTGEN_CERT_DER_MAX);
    if (cert_der == NULL) {
        fprintf(stderr, "Error: out of memory\n");
        return 1;
    }

    rc = noxtls_x509_certificate_generate_self_signed_ex(
        serial, (uint32_t)sizeof(serial),
        issuer_der, issuer_len, subject_der, subject_len,
        not_before, not_after,
        subject_pk_oid, subject_pk_oid_len,
        subject_pk_params, subject_pk_params_len,
        subject_pk, subject_pk_len,
        sig_oid, sig_oid_len,
        sign_key_der, sign_key_der_len,
        hash_algo,
        cert_der, CERTGEN_CERT_DER_MAX, &cert_der_len);

    if (rc != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Certificate generation failed (%d)\n", (int)rc);
        goto done;
    }

    fp = noxtls_fopen(out_file, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", out_file);
        goto done;
    }
    if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
        if (fwrite(cert_der, 1, cert_der_len, fp) != (size_t)cert_der_len) {
            fprintf(stderr, "Error: Write failed\n");
            goto done;
        }
        printf("Wrote %s (%u bytes DER)\n", out_file, (unsigned)cert_der_len);
    } else {
        uint32_t pem_len = 0;
        pem_buf = (uint8_t *)malloc(CERTGEN_PEM_MAX);
        if (pem_buf == NULL) {
            fprintf(stderr, "Error: out of memory\n");
            goto done;
        }
        rc = noxtls_certificate_der_to_pem(cert_der, cert_der_len, pem_buf, &pem_len);
        if (rc != NOXTLS_RETURN_SUCCESS || pem_len == 0) {
            fprintf(stderr, "Error: DER to PEM failed\n");
            goto done;
        }
        if (fwrite(pem_buf, 1, pem_len, fp) != (size_t)pem_len) {
            fprintf(stderr, "Error: Write failed\n");
            goto done;
        }
        printf("Wrote %s (PEM)\n", out_file);
    }
    ret = 0;

done:
    if (fp != NULL) fclose(fp);
    free(pem_buf);
    free(cert_der);
    return ret;
}
#endif

#if NOXTLS_HAVE_CERT_WRITE
/* Strip a PEM "-----BEGIN ... -----" / "-----END ... -----" envelope and base64-decode
 * the body into @p out_der. Returns 0 on success. Accepts an empty/no envelope (DER input).
 */
/**
 * @brief Load a DER or PEM file
 *
 * @param[in] path The path to the file to load
 * @param[out] out The buffer to load the DER or PEM into
 * @param[out] out_len The length of the DER or PEM
 * @return 0 on success, -1 on failure
 */
static int load_der_or_pem_file(const char *path, uint8_t **out, uint32_t *out_len)
{
    FILE *fp;
    long flen;
    uint8_t *raw = NULL;
    size_t got;
    int rc = -1;

    *out = NULL;
    *out_len = 0;
    fp = noxtls_fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    flen = ftell(fp);
    if (flen <= 0 || flen > (long)(1024U * 1024U)) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return -1; }
    raw = (uint8_t *)malloc((size_t)flen + 1U);
    if (raw == NULL) { fclose(fp); return -1; }
    got = fread(raw, 1, (size_t)flen, fp);
    fclose(fp);
    if (got != (size_t)flen) { free(raw); return -1; }
    raw[flen] = '\0';

    /* Detect PEM by header substring. */
    {
        char *begin = strstr((char *)raw, "-----BEGIN");
        if (begin != NULL) {
            char *body = strchr(begin, '\n');
            char *end = strstr(body != NULL ? body : begin, "-----END");
            if (body == NULL || end == NULL) {
                free(raw);
                return -1;
            }
            body++; /* skip the newline */
            *end = '\0';
            {
                size_t b64_in_len = (size_t)(end - body);
                uint8_t *dec = (uint8_t *)malloc(b64_in_len);
                int dec_len;
                if (dec == NULL) { free(raw); return -1; }
                dec_len = noxtls_base64_decode((const char *)body, (int)b64_in_len, dec);
                if (dec_len <= 0) {
                    free(dec);
                    free(raw);
                    return -1;
                }
                *out = dec;
                *out_len = (uint32_t)dec_len;
                rc = 0;
            }
        } else {
            *out = (uint8_t *)malloc((size_t)flen);
            if (*out == NULL) { free(raw); return -1; }
            memcpy(*out, raw, (size_t)flen);
            *out_len = (uint32_t)flen;
            rc = 0;
        }
    }
    free(raw);
    return rc;
}

/* Read a DER length octet group at *p (advancing *p past the length octets).
 * Returns 0 on success and writes the decoded length to *out_len. */
/**
 * @brief Read a DER length octet group at *p (advancing *p past the length octets).
 * Returns 0 on success and writes the decoded length to *out_len.
 *
 * @param[in] p The pointer to the DER length octet group
 * @param[in] end The end of the DER length octet group
 * @param[out] out_len The length of the DER length octet group
 * @return 0 on success, -1 on failure
 */
static int certgen_asn1_read_len(const uint8_t **p, const uint8_t *end, uint32_t *out_len)
{
    uint32_t v;
    uint8_t first;
    if (*p >= end) {
        return -1;
    }
    first = *(*p)++;
    if ((first & 0x80u) == 0U) {
        *out_len = first;
        return 0;
    }
    {
        uint32_t n = (uint32_t)(first & 0x7Fu);
        uint32_t i;
        if (n == 0U || n > 4U || (uint32_t)(end - *p) < n) {
            return -1;
        }
        v = 0U;
        for (i = 0U; i < n; i++) {
            v = (v << 8) | (uint32_t)(*(*p)++);
        }
        *out_len = v;
        return 0;
    }
}

/* Read a tag-length-value triple and place the value pointer/length in *body_out / *body_len_out.
 * Advances *p past the value. Returns 0 on success. */
/**
 * @brief Read a tag-length-value triple and place the value pointer/length in *body_out / *body_len_out.
 * Advances *p past the value. Returns 0 on success.
 *
 * @param[in] p The pointer to the tag-length-value triple
 * @param[in] end The end of the tag-length-value triple
 * @param[in] expected_tag The expected tag of the tag-length-value triple
 * @param[out] body_out The pointer to the value of the tag-length-value triple
 * @param[out] body_len_out The length of the value of the tag-length-value triple
 * @return 0 on success, -1 on failure
 */
static int certgen_asn1_read_tlv(const uint8_t **p, const uint8_t *end,
                                 uint8_t expected_tag,
                                 const uint8_t **body_out, uint32_t *body_len_out)
{
    uint32_t len;
    if (*p >= end || *(*p)++ != expected_tag) {
        return -1;
    }
    if (certgen_asn1_read_len(p, end, &len) != 0) {
        return -1;
    }
    if ((uint32_t)(end - *p) < len) {
        return -1;
    }
    *body_out = *p;
    *body_len_out = len;
    *p += len;
    return 0;
}

/* Extract the raw subjectPublicKey bytes (BIT STRING content minus the leading
 * "unused bits" octet) from a DER-encoded SubjectPublicKeyInfo. Returns 0 on success. */
/**
 * @brief Extract the raw subjectPublicKey bytes (BIT STRING content minus the leading
 * "unused bits" octet) from a DER-encoded SubjectPublicKeyInfo. Returns 0 on success.
 *
 * @param[in] der The DER encoded SubjectPublicKeyInfo
 * @param[in] der_len The length of the DER encoded SubjectPublicKeyInfo
 * @param[out] pk_out The pointer to the raw subjectPublicKey bytes
 * @param[out] pk_len_out The length of the raw subjectPublicKey bytes
 * @return 0 on success, -1 on failure
 */
static int spki_extract_raw_pubkey(const uint8_t *der, uint32_t der_len,
                                   const uint8_t **pk_out, uint32_t *pk_len_out)
{
    const uint8_t *p = der;
    const uint8_t *end = der + der_len;
    const uint8_t *body;
    uint32_t body_len;
    const uint8_t *bs_body;
    uint32_t bs_len;
    const uint8_t *alg_body;
    uint32_t alg_len;

    /* Outer SEQUENCE: SubjectPublicKeyInfo */
    if (certgen_asn1_read_tlv(&p, end, ASN1_DER_TAG_SEQUENCE, &body, &body_len) != 0) {
        return -1;
    }
    p = body;
    end = body + body_len;
    /* Skip AlgorithmIdentifier (SEQUENCE) */
    if (certgen_asn1_read_tlv(&p, end, ASN1_DER_TAG_SEQUENCE, &alg_body, &alg_len) != 0) {
        return -1;
    }
    (void)alg_body; (void)alg_len;
    /* BIT STRING with subjectPublicKey */
    if (certgen_asn1_read_tlv(&p, end, ASN1_TAG_BITSTRING, &bs_body, &bs_len) != 0) {
        return -1;
    }
    if (bs_len < 1U || bs_body[0] != 0x00u) {
        return -1; /* must be octet-aligned (unused bits == 0) */
    }
    *pk_out = bs_body + 1;
    *pk_len_out = bs_len - 1U;
    return 0;
}

/* Build the companion ".pub" path for a given key path: strips .key/.pem/.der and appends .pub. */
/**
 * @brief Build the companion ".pub" path for a given key path: strips .key/.pem/.der and appends .pub.
 *
 * @param[in] key_path The path to the key file
 * @param[out] out The path to the public key file
 * @param[in] out_max The maximum length of the path
 * @return void
 */
static void derive_pub_path(const char *key_path, char *out, size_t out_max)
{
    const char *dot;
    size_t base_len;
    if (out_max == 0) return;
    out[0] = '\0';
    dot = strrchr(key_path, '.');
    base_len = (dot != NULL) ? (size_t)(dot - key_path) : strlen(key_path);
    if (base_len + 5U >= out_max) {
        base_len = (out_max > 5U) ? out_max - 5U : 0;
    }
    memcpy(out, key_path, base_len);
    out[base_len] = '\0';
    if (out_max - base_len >= 5U) {
        memcpy(out + base_len, ".pub", 5U);
    }
}

/* Load a SPKI ".pub" file (PEM or DER) and return the raw subjectPublicKey bytes. */
/**
 * @brief Load a SPKI ".pub" file (PEM or DER) and return the raw subjectPublicKey bytes.
 *
 * @param[in] path The path to the SPKI ".pub" file
 * @param[out] owned_der The pointer to the DER encoded SubjectPublicKeyInfo
 * @param[out] owned_der_len The length of the DER encoded SubjectPublicKeyInfo
 * @param[out] pk_ptr The pointer to the raw subjectPublicKey bytes
 * @param[out] pk_len The length of the raw subjectPublicKey bytes
 * @return 0 on success, -1 on failure
 */
static int load_raw_pubkey_from_file(const char *path,
                                     uint8_t **owned_der, uint32_t *owned_der_len,
                                     const uint8_t **pk_ptr, uint32_t *pk_len)
{
    uint8_t *der = NULL;
    uint32_t der_len = 0;
    if (load_der_or_pem_file(path, &der, &der_len) != 0) {
        return -1;
    }
    if (spki_extract_raw_pubkey(der, der_len, pk_ptr, pk_len) != 0) {
        free(der);
        return -1;
    }
    *owned_der = der;
    *owned_der_len = der_len;
    return 0;
}
#endif /* NOXTLS_HAVE_CERT_WRITE */

/**
 * @brief Generate a certificate request
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @param[in] prog The name of the program
 * @return 0 on success, -1 on failure
 */
static int cmd_req(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *key_file = NULL;
    const char *out_file = NULL;
#if NOXTLS_HAVE_CERT_WRITE
    const char *pub_file = NULL;
    const char *outform = "PEM";
    int days = 365;
    const char *subj = "/CN=localhost";
#endif
    int new_x509 = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
#if NOXTLS_HAVE_CERT_WRITE
        } else if (strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        } else if (strcmp(argv[i], "-days") == 0 && i + 1 < argc) {
            days = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-subj") == 0 && i + 1 < argc) {
            subj = argv[++i];
        } else if (strcmp(argv[i], "-pub") == 0 && i + 1 < argc) {
            pub_file = argv[++i];
#endif
        } else if (strcmp(argv[i], "-new") == 0) {
            /* next should be -x509 */
        } else if (strcmp(argv[i], "-x509") == 0) {
            new_x509 = 1;
        }
    }

    if (!new_x509) {
        fprintf(stderr, "Only -new -x509 (self-signed certificate) is supported.\n");
        return 1;
    }
    if (key_file == NULL || out_file == NULL) {
        fprintf(stderr, "Error: -key and -out are required for req -new -x509\n");
        return 1;
    }

    x509_private_key_t priv;
    noxtls_x509_private_key_init(&priv);
    if (noxtls_x509_private_key_load_file(&priv, key_file) != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Cannot load private key from %s\n", key_file);
        noxtls_x509_private_key_free(&priv);
        return 1;
    }

#if NOXTLS_HAVE_CERT_WRITE
    {
        char cn_buf[256];
        extract_cn_from_subj(subj, cn_buf, sizeof(cn_buf));
        if (cn_buf[0] == '\0') {
            strncpy(cn_buf, "localhost", sizeof(cn_buf) - 1);
            cn_buf[sizeof(cn_buf) - 1] = '\0';
        }

        uint32_t key_raw_len = priv.raw_data_len;
        const uint8_t *key_raw = priv.raw_data;
        if (key_raw == NULL || key_raw_len == 0) {
            fprintf(stderr, "Error: No raw key data for signing\n");
            noxtls_x509_private_key_free(&priv);
            return 1;
        }

        if (priv.key_type == X509_PRIVATE_KEY_RSA) {
            rsa_key_t rsa_key;
            noxtls_return_t rc = noxtls_x509_private_key_to_rsa_key(&priv, &rsa_key);
            uint8_t *rsa_pub_der = NULL;
            uint32_t rsa_pub_der_len = 0;
            uint8_t *rsa_inner = NULL;
            uint32_t key_bytes;
            uint32_t n_enc_len;
            uint32_t e_enc_len;
            int out;

            if (rc != NOXTLS_RETURN_SUCCESS) {
                fprintf(stderr, "Error: Failed to convert key to RSA\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            key_bytes = rsa_key.key_bytes;
            /* subjectPublicKey BIT STRING content = DER SEQUENCE { n, e } per PKCS#1 (RSAPublicKey). */
            rsa_inner = (uint8_t *)malloc((size_t)key_bytes * 2U + 64U);
            rsa_pub_der = (uint8_t *)malloc((size_t)key_bytes * 2U + 64U);
            if (rsa_inner == NULL || rsa_pub_der == NULL) {
                free(rsa_inner);
                free(rsa_pub_der);
                noxtls_rsa_key_free(&rsa_key);
                noxtls_x509_private_key_free(&priv);
                fprintf(stderr, "Error: out of memory\n");
                return 1;
            }
            n_enc_len = noxtls_asn1_put_integer(rsa_inner, key_bytes * 2U + 64U, rsa_key.n, key_bytes);
            e_enc_len = noxtls_asn1_put_integer(rsa_inner + n_enc_len, key_bytes * 2U + 64U - n_enc_len,
                                                rsa_key.e, key_bytes);
            if (n_enc_len == 0 || e_enc_len == 0) {
                free(rsa_inner);
                free(rsa_pub_der);
                noxtls_rsa_key_free(&rsa_key);
                noxtls_x509_private_key_free(&priv);
                fprintf(stderr, "Error: failed to encode RSAPublicKey\n");
                return 1;
            }
            rsa_pub_der_len = noxtls_asn1_put_sequence(rsa_pub_der, key_bytes * 2U + 64U,
                                                      rsa_inner, n_enc_len + e_enc_len);
            free(rsa_inner);
            noxtls_rsa_key_free(&rsa_key);
            if (rsa_pub_der_len == 0) {
                free(rsa_pub_der);
                noxtls_x509_private_key_free(&priv);
                fprintf(stderr, "Error: failed to wrap RSAPublicKey\n");
                return 1;
            }

            out = certgen_self_signed_x509_common(
                cn_buf, days,
                oid_rsa_encryption, (uint32_t)sizeof(oid_rsa_encryption),
                NULL, 0,
                rsa_pub_der, rsa_pub_der_len,
                oid_sha256_with_rsa, (uint32_t)sizeof(oid_sha256_with_rsa),
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256,
                out_file, outform);
            free(rsa_pub_der);
            noxtls_x509_private_key_free(&priv);
            return out;
        }

        if (priv.key_type == X509_PRIVATE_KEY_ECC) {
            ecc_key_t ecc_key;
            noxtls_return_t rc = noxtls_x509_private_key_to_ecc_key(&priv, &ecc_key);
            uint8_t curve_oid_der[16];
            uint32_t curve_oid_der_len;
            const uint8_t *curve_oid = NULL;
            uint32_t curve_oid_len = 0;
            const uint8_t *sig_oid_ptr = NULL;
            uint32_t sig_oid_len = 0;
            noxtls_hash_algos_t sig_hash = NOXTLS_HASH_SHA_256;
            uint32_t curve_size;
            uint32_t pub_key_len;
            uint8_t pub_key_buf[133]; /* 1 + 2*66 for P-521 */
            int out;

            if (rc != NOXTLS_RETURN_SUCCESS) {
                fprintf(stderr, "Error: Failed to convert key to ECC\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }

            /* Map curve to (namedCurve OID, signature OID, signature hash). */
            if (priv.ecc_curve_oid_len > 0 && priv.ecc_curve_oid_len <= sizeof(curve_oid_der) - 2) {
                curve_oid = priv.ecc_curve_oid;
                curve_oid_len = priv.ecc_curve_oid_len;
            }
            if (curve_oid == NULL) {
                fprintf(stderr, "Error: ECC private key is missing its named-curve OID\n");
                noxtls_ecc_key_free(&ecc_key);
                noxtls_x509_private_key_free(&priv);
                return 1;
            }

            /* DER-encode the namedCurve OID as `06 LL <oid bytes>` to pass as the
             * AlgorithmIdentifier parameters body. */
            curve_oid_der[0] = 0x06; /* OBJECT IDENTIFIER tag */
            curve_oid_der[1] = (uint8_t)curve_oid_len;
            memcpy(curve_oid_der + 2, curve_oid, curve_oid_len);
            curve_oid_der_len = 2U + curve_oid_len;

            curve_size = ecc_key.curve != NULL ? ecc_key.curve->size : 32U;
            if (curve_size > 66u || 1U + 2U * curve_size > sizeof(pub_key_buf)) {
                fprintf(stderr, "Error: Unsupported curve size\n");
                noxtls_ecc_key_free(&ecc_key);
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            pub_key_buf[0] = 0x04;
            memcpy(pub_key_buf + 1, ecc_key.Q.x, curve_size);
            memcpy(pub_key_buf + 1U + curve_size, ecc_key.Q.y, curve_size);
            pub_key_len = 1U + 2U * curve_size;
            noxtls_ecc_key_free(&ecc_key);

            /* Pick a signature OID matched to the curve size. */
            {
                /* ecdsa-with-SHA384 (1.2.840.10045.4.3.3) */
                static const uint8_t oid_ecdsa_sha384[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };
                /* ecdsa-with-SHA512 (1.2.840.10045.4.3.4) */
                static const uint8_t oid_ecdsa_sha512[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04 };
                if (curve_size <= 32U) {
                    sig_oid_ptr = oid_ecdsa_sha256;
                    sig_oid_len = sizeof(oid_ecdsa_sha256);
                    sig_hash = NOXTLS_HASH_SHA_256;
                } else if (curve_size <= 48U) {
                    sig_oid_ptr = oid_ecdsa_sha384;
                    sig_oid_len = sizeof(oid_ecdsa_sha384);
                    sig_hash = NOXTLS_HASH_SHA_384;
                } else {
                    sig_oid_ptr = oid_ecdsa_sha512;
                    sig_oid_len = sizeof(oid_ecdsa_sha512);
                    sig_hash = NOXTLS_HASH_SHA_512;
                }
            }

            out = certgen_self_signed_x509_common(
                cn_buf, days,
                oid_id_ec_public_key, (uint32_t)sizeof(oid_id_ec_public_key),
                curve_oid_der, curve_oid_der_len,
                pub_key_buf, pub_key_len,
                sig_oid_ptr, sig_oid_len,
                key_raw, key_raw_len,
                sig_hash,
                out_file, outform);
            noxtls_x509_private_key_free(&priv);
            return out;
        }
#if NOXTLS_FEATURE_ED25519
        if (priv.key_type == X509_PRIVATE_KEY_ED25519) {
            uint32_t slen = 0;
            const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&priv, &slen);
            if (seed == NULL || slen != 32) {
                fprintf(stderr, "Error: Invalid Ed25519 private key material\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            uint8_t pub_raw[32];
            if (noxtls_ed25519_public_key(seed, pub_raw) != NOXTLS_RETURN_SUCCESS) {
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            int out = certgen_self_signed_x509_common(
                cn_buf, days,
                oid_ed25519, (uint32_t)sizeof(oid_ed25519),
                NULL, 0,
                pub_raw, 32,
                oid_ed25519, (uint32_t)sizeof(oid_ed25519),
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256,
                out_file, outform);
            noxtls_x509_private_key_free(&priv);
            return out;
        }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
        if (priv.key_type == X509_PRIVATE_KEY_ED448) {
            uint32_t slen = 0;
            const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&priv, &slen);
            if (seed == NULL || slen != 57) {
                fprintf(stderr, "Error: Invalid Ed448 private key material\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            uint8_t pub_raw[57];
            if (noxtls_ed448_public_key(seed, pub_raw) != NOXTLS_RETURN_SUCCESS) {
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            int out = certgen_self_signed_x509_common(
                cn_buf, days,
                oid_ed448, (uint32_t)sizeof(oid_ed448),
                NULL, 0,
                pub_raw, 57,
                oid_ed448, (uint32_t)sizeof(oid_ed448),
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256,
                out_file, outform);
            noxtls_x509_private_key_free(&priv);
            return out;
        }
#endif
#if NOXTLS_FEATURE_ML_DSA
        if (priv.key_type == X509_PRIVATE_KEY_ML_DSA) {
            /* ML-DSA needs the public key from the companion .pub file (cannot derive cheaply). */
            char auto_pub[CERTGEN_PATH_MAX];
            const char *pub_path = pub_file;
            uint8_t *pub_der = NULL;
            uint32_t pub_der_len = 0;
            const uint8_t *pk_ptr = NULL;
            uint32_t pk_len = 0;
            const uint8_t *param_oid = NULL;
            uint32_t param_oid_len = 0;
            uint32_t expected_pk_len = 0;
            int out;

            if (pub_path == NULL) {
                derive_pub_path(key_file, auto_pub, sizeof(auto_pub));
                pub_path = auto_pub;
            }
            if (load_raw_pubkey_from_file(pub_path, &pub_der, &pub_der_len, &pk_ptr, &pk_len) != 0) {
                fprintf(stderr, "Error: Cannot load ML-DSA public key from %s\n", pub_path);
                fprintf(stderr, "Hint: pass -pub <file>, or place the SPKI .pub next to the .key file.\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            switch ((noxtls_mldsa_param_t)priv.pqc_param) {
                case NOXTLS_MLDSA_44: param_oid = oid_ml_dsa_44; param_oid_len = sizeof(oid_ml_dsa_44); break;
                case NOXTLS_MLDSA_65: param_oid = oid_ml_dsa_65; param_oid_len = sizeof(oid_ml_dsa_65); break;
                case NOXTLS_MLDSA_87: param_oid = oid_ml_dsa_87; param_oid_len = sizeof(oid_ml_dsa_87); break;
                default: break;
            }
            expected_pk_len = noxtls_mldsa_public_key_len((noxtls_mldsa_param_t)priv.pqc_param);
            if (param_oid == NULL || expected_pk_len == 0 || pk_len != expected_pk_len) {
                fprintf(stderr, "Error: ML-DSA public key length mismatch (got %u, expected %u)\n",
                        (unsigned)pk_len, (unsigned)expected_pk_len);
                free(pub_der);
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            out = certgen_self_signed_x509_common(
                cn_buf, days,
                param_oid, param_oid_len,
                NULL, 0,
                pk_ptr, pk_len,
                param_oid, param_oid_len,
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256, /* unused for ML-DSA */
                out_file, outform);
            free(pub_der);
            noxtls_x509_private_key_free(&priv);
            return out;
        }
#endif
#if NOXTLS_FEATURE_SLH_DSA
        if (priv.key_type == X509_PRIVATE_KEY_SLH_DSA) {
            char auto_pub[CERTGEN_PATH_MAX];
            const char *pub_path = pub_file;
            uint8_t *pub_der = NULL;
            uint32_t pub_der_len = 0;
            const uint8_t *pk_ptr = NULL;
            uint32_t pk_len = 0;
            const uint8_t *param_oid = NULL;
            uint32_t param_oid_len = 0;
            uint32_t expected_pk_len = 0;
            int out;

            if (pub_path == NULL) {
                derive_pub_path(key_file, auto_pub, sizeof(auto_pub));
                pub_path = auto_pub;
            }
            if (load_raw_pubkey_from_file(pub_path, &pub_der, &pub_der_len, &pk_ptr, &pk_len) != 0) {
                fprintf(stderr, "Error: Cannot load SLH-DSA public key from %s\n", pub_path);
                fprintf(stderr, "Hint: pass -pub <file>, or place the SPKI .pub next to the .key file.\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            switch ((noxtls_slhdsa_param_t)priv.pqc_param) {
                case NOXTLS_SLHDSA_SHA2_128S: param_oid = oid_slh_dsa_sha2_128s; param_oid_len = sizeof(oid_slh_dsa_sha2_128s); break;
                case NOXTLS_SLHDSA_SHA2_128F: param_oid = oid_slh_dsa_sha2_128f; param_oid_len = sizeof(oid_slh_dsa_sha2_128f); break;
                case NOXTLS_SLHDSA_SHA2_192S: param_oid = oid_slh_dsa_sha2_192s; param_oid_len = sizeof(oid_slh_dsa_sha2_192s); break;
                case NOXTLS_SLHDSA_SHA2_192F: param_oid = oid_slh_dsa_sha2_192f; param_oid_len = sizeof(oid_slh_dsa_sha2_192f); break;
                case NOXTLS_SLHDSA_SHA2_256S: param_oid = oid_slh_dsa_sha2_256s; param_oid_len = sizeof(oid_slh_dsa_sha2_256s); break;
                case NOXTLS_SLHDSA_SHA2_256F: param_oid = oid_slh_dsa_sha2_256f; param_oid_len = sizeof(oid_slh_dsa_sha2_256f); break;
                case NOXTLS_SLHDSA_SHAKE_128S: param_oid = oid_slh_dsa_shake_128s; param_oid_len = sizeof(oid_slh_dsa_shake_128s); break;
                case NOXTLS_SLHDSA_SHAKE_128F: param_oid = oid_slh_dsa_shake_128f; param_oid_len = sizeof(oid_slh_dsa_shake_128f); break;
                case NOXTLS_SLHDSA_SHAKE_192S: param_oid = oid_slh_dsa_shake_192s; param_oid_len = sizeof(oid_slh_dsa_shake_192s); break;
                case NOXTLS_SLHDSA_SHAKE_192F: param_oid = oid_slh_dsa_shake_192f; param_oid_len = sizeof(oid_slh_dsa_shake_192f); break;
                case NOXTLS_SLHDSA_SHAKE_256S: param_oid = oid_slh_dsa_shake_256s; param_oid_len = sizeof(oid_slh_dsa_shake_256s); break;
                case NOXTLS_SLHDSA_SHAKE_256F: param_oid = oid_slh_dsa_shake_256f; param_oid_len = sizeof(oid_slh_dsa_shake_256f); break;
                default: break;
            }
            expected_pk_len = noxtls_slhdsa_public_key_len((noxtls_slhdsa_param_t)priv.pqc_param);
            if (param_oid == NULL || expected_pk_len == 0 || pk_len != expected_pk_len) {
                fprintf(stderr, "Error: SLH-DSA public key length mismatch (got %u, expected %u)\n",
                        (unsigned)pk_len, (unsigned)expected_pk_len);
                free(pub_der);
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            out = certgen_self_signed_x509_common(
                cn_buf, days,
                param_oid, param_oid_len,
                NULL, 0,
                pk_ptr, pk_len,
                param_oid, param_oid_len,
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256, /* unused for SLH-DSA */
                out_file, outform);
            free(pub_der);
            noxtls_x509_private_key_free(&priv);
            return out;
        }
#endif
        noxtls_x509_private_key_free(&priv);
        fprintf(stderr, "Error: Self-signed certificate generation does not yet support this key type.\n");
        fprintf(stderr, "Supported: RSA, ECC, Ed25519, Ed448 (build-dependent), ML-DSA, SLH-DSA.\n");
        return 1;
    }
#else
    (void)key_file;
    noxtls_x509_private_key_free(&priv);
    fprintf(stderr, "Self-signed certificate generation is not available in this build.\n");
    fprintf(stderr, "Reconfigure with -DNOXTLS_CFG_HAVE_CERT_WRITE=ON to enable it.\n");
    return 1;
#endif
}

/**
 * @brief certgen entry point; dispatches to key and certificate subcommands.
 *
 * @param[in] argc Argument count (including program name)
 * @param[in] argv Command-line arguments; argv[1] is the subcommand
 * @return 0 on success, 1 on error or unknown command
 */
int main(int argc, char **argv)
{
    const char *prog = argv[0];
    if (argc < 2) {
        print_usage(prog);
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(prog);
        return 0;
    }
    if (strcmp(argv[1], "-version") == 0 || strcmp(argv[1], "-v") == 0) {
        printf("certgen %s (NoxTLS)\n", CERTGEN_VERSION);
        return 0;
    }
    if (strcmp(argv[1], "genrsa") == 0) {
        return cmd_genrsa(argc - 1, argv + 1, prog);
    }
    if (strcmp(argv[1], "genec") == 0) {
        return cmd_genec(argc - 1, argv + 1, prog);
    }
    if (strcmp(argv[1], "gened25519") == 0) {
        return cmd_gened25519(argc - 1, argv + 1, prog);
    }
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if (strcmp(argv[1], "gened448") == 0) {
        return cmd_gened448(argc - 1, argv + 1, prog);
    }
#endif
#if NOXTLS_FEATURE_ML_DSA
    if (strcmp(argv[1], "genmldsa") == 0) {
        return cmd_genmldsa(argc - 1, argv + 1, prog);
    }
#endif
#if NOXTLS_FEATURE_SLH_DSA
    if (strcmp(argv[1], "genslhdsa") == 0) {
        return cmd_genslhdsa(argc - 1, argv + 1, prog);
    }
#endif
    if (strcmp(argv[1], "req") == 0) {
        return cmd_req(argc - 1, argv + 1, prog);
    }
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage(prog);
    return 1;
}
