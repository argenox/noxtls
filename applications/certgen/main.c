/*
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
 *
 * certgen - Key and certificate generation utility using NOXTLS
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
#include "noxtls-lib/mdigest/noxtls_hash.h"

#define CERTGEN_VERSION "0.1.0"
#define PKCS1_MAX_BYTES (16384u)  /* enough for 4096-bit key DER */
#define SEC1_ECC_MAX_BYTES (512u)  /* SEC1 ECPrivateKey DER (P-521 + OID + public) */
#define SPKI_MAX_BYTES (16384u)   /* SubjectPublicKeyInfo for RSA/EC */
#define CERTGEN_PATH_MAX (512u)

/* rsaEncryption OID (1.2.840.113549.1.1.1) - raw DER bytes */
static const uint8_t oid_rsa_encryption[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
/* id-ecPublicKey OID (1.2.840.10045.2.1) - raw DER bytes */
static const uint8_t oid_id_ec_public_key[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
/* id-Ed25519 (1.3.101.112), id-Ed448 (1.3.101.113) — RFC 8410 */
static const uint8_t oid_ed25519[] = { 0x2B, 0x65, 0x70 };
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
static const uint8_t oid_ed448[] = { 0x2B, 0x65, 0x71 };
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
    printf("req options (for -new -x509 self-signed cert):\n");
    printf("  -new -x509      Create self-signed certificate\n");
    printf("  -key <file>     Private key file (required; ECC or Ed25519/Ed448 PKCS#8 when cert write enabled)\n");
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
    printf("  %s req -new -x509 -key client.key -out cert.pem -days 365 -subj /CN=localhost\n", prog);
}

/* Encode PKCS#1 RSAPrivateKey (DER) from rsa_key_t. Returns length or 0 on error. */
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
static int is_known_ext(const char *s)
{
    if (s[0] == 'k' && s[1] == 'e' && s[2] == 'y' && s[3] == '\0') return 1;
    if (s[0] == 'p' && s[1] == 'u' && s[2] == 'b' && s[3] == '\0') return 1;
    if (s[0] == 'p' && s[1] == 'e' && s[2] == 'm' && s[3] == '\0') return 1;
    if (s[0] == 'd' && s[1] == 'e' && s[2] == 'r' && s[3] == '\0') return 1;
    return 0;
}

/* Build key_path and pub_path from -out base name. Strips .key, .pub, .pem, .der from end. */
static void build_key_pub_paths(const char *out_file, char *key_path, char *pub_path, size_t path_max)
{
    if (out_file == NULL || key_path == NULL || pub_path == NULL || path_max == 0) {
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
    char base_buf[CERTGEN_PATH_MAX];
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
            memcpy(base_buf, out_file, base_len);
            base_buf[base_len] = '\0';
            snprintf(key_path, path_max, "%s.key", base_buf);
            snprintf(pub_path, path_max, "%s.pub", base_buf);
            return;
        }
    }
    snprintf(key_path, path_max, "%s.key", out_file);
    snprintf(pub_path, path_max, "%s.pub", out_file);
}

/* Write DER to file as PEM with given begin/end markers. Returns 0 on success. */
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

static int cmd_genec(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *out_file = NULL;
    const char *outform = "PEM";
    ecc_curve_t curve_type = ECC_SECP256R1;
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
                curve_type = ECC_SECP192R1;
                curve_oid = oid_secp192r1;
                curve_oid_len = sizeof(oid_secp192r1);
            } else if (strcmp(curve, "secp224r1") == 0 || strcmp(curve, "P-224") == 0) {
                curve_type = ECC_SECP224R1;
                curve_oid = oid_secp224r1;
                curve_oid_len = sizeof(oid_secp224r1);
            } else if (strcmp(curve, "prime256v1") == 0 || strcmp(curve, "secp256r1") == 0 || strcmp(curve, "P-256") == 0) {
                curve_type = ECC_SECP256R1;
                curve_oid = oid_secp256r1;
                curve_oid_len = sizeof(oid_secp256r1);
            } else if (strcmp(curve, "secp384r1") == 0 || strcmp(curve, "P-384") == 0) {
                curve_type = ECC_SECP384R1;
                curve_oid = oid_secp384r1;
                curve_oid_len = sizeof(oid_secp384r1);
            } else if (strcmp(curve, "secp521r1") == 0 || strcmp(curve, "P-521") == 0) {
                curve_type = ECC_SECP521R1;
                curve_oid = oid_secp521r1;
                curve_oid_len = sizeof(oid_secp521r1);
            } else if (strcmp(curve, "brainpoolP256r1") == 0 || strcmp(curve, "bp256r1") == 0) {
                curve_type = ECC_BP256R1;
                curve_oid = oid_bp256r1;
                curve_oid_len = sizeof(oid_bp256r1);
            } else if (strcmp(curve, "brainpoolP384r1") == 0 || strcmp(curve, "bp384r1") == 0) {
                curve_type = ECC_BP384R1;
                curve_oid = oid_bp384r1;
                curve_oid_len = sizeof(oid_bp384r1);
            } else if (strcmp(curve, "brainpoolP512r1") == 0 || strcmp(curve, "bp512r1") == 0) {
                curve_type = ECC_BP512R1;
                curve_oid = oid_bp512r1;
                curve_oid_len = sizeof(oid_bp512r1);
            } else if (strcmp(curve, "secp192k1") == 0) {
                curve_type = ECC_SECP192K1;
                curve_oid = oid_secp192k1;
                curve_oid_len = sizeof(oid_secp192k1);
            } else if (strcmp(curve, "secp224k1") == 0) {
                curve_type = ECC_SECP224K1;
                curve_oid = oid_secp224k1;
                curve_oid_len = sizeof(oid_secp224k1);
            } else if (strcmp(curve, "secp256k1") == 0) {
                curve_type = ECC_SECP256K1;
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
            case ECC_SECP192R1: curve_name = "secp192r1"; break;
            case ECC_SECP224R1: curve_name = "secp224r1"; break;
            case ECC_SECP256R1: curve_name = "prime256v1"; break;
            case ECC_SECP384R1: curve_name = "secp384r1"; break;
            case ECC_SECP521R1: curve_name = "secp521r1"; break;
            case ECC_BP256R1: curve_name = "brainpoolP256r1"; break;
            case ECC_BP384R1: curve_name = "brainpoolP384r1"; break;
            case ECC_BP512R1: curve_name = "brainpoolP512r1"; break;
            case ECC_SECP192K1: curve_name = "secp192k1"; break;
            case ECC_SECP224K1: curve_name = "secp224k1"; break;
            case ECC_SECP256K1: curve_name = "secp256k1"; break;
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

    char key_path[CERTGEN_PATH_MAX], pub_path[CERTGEN_PATH_MAX];
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
    uint8_t sk[32], pk[32];
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
    char key_path[CERTGEN_PATH_MAX], pub_path[CERTGEN_PATH_MAX];
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
    uint8_t sk[57], pk[57];
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
    char key_path[CERTGEN_PATH_MAX], pub_path[CERTGEN_PATH_MAX];
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

    char key_path[CERTGEN_PATH_MAX], pub_path[CERTGEN_PATH_MAX];
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

/* Extract CN value from OpenSSL-style -subj (e.g. /CN=localhost or CN=localhost). Puts result in cn_out, max cn_size. */
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

/* OIDs for ECC self-signed cert (id-ecPublicKey, ecdsa-with-SHA256) */
#if NOXTLS_HAVE_CERT_WRITE
static const uint8_t oid_ecdsa_sha256[]     = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
#define CERTGEN_CERT_DER_MAX 4096
#define CERTGEN_PEM_MAX      8192

static int certgen_self_signed_x509_common(
    const char *cn_buf,
    int days,
    const uint8_t *subject_pk_oid, uint32_t subject_pk_oid_len,
    const uint8_t *subject_pk, uint32_t subject_pk_len,
    const uint8_t *sig_oid, uint32_t sig_oid_len,
    const uint8_t *sign_key_der, uint32_t sign_key_der_len,
    noxtls_hash_algos_t hash_algo,
    const char *out_file,
    const char *outform)
{
    uint8_t issuer_der[256], subject_der[256];
    uint32_t issuer_len = 0, subject_len = 0;
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

    char not_before[16], not_after[16];
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        fprintf(stderr, "Error: time() failed\n");
        return 1;
    }
#ifdef _MSC_VER
    struct tm tm_before, tm_after;
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
    uint8_t cert_der[CERTGEN_CERT_DER_MAX];
    uint32_t cert_der_len = 0;

    rc = noxtls_x509_certificate_generate_self_signed(
        serial, (uint32_t)sizeof(serial),
        issuer_der, issuer_len, subject_der, subject_len,
        not_before, not_after,
        subject_pk_oid, subject_pk_oid_len,
        subject_pk, subject_pk_len,
        sig_oid, sig_oid_len,
        sign_key_der, sign_key_der_len,
        hash_algo,
        cert_der, sizeof(cert_der), &cert_der_len);

    if (rc != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "Error: Certificate generation failed (%d)\n", (int)rc);
        return 1;
    }

    FILE *fp = noxtls_fopen(out_file, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Error: Cannot open %s for writing\n", out_file);
        return 1;
    }
    if (strcmp(outform, "DER") == 0 || strcmp(outform, "der") == 0) {
        if (fwrite(cert_der, 1, cert_der_len, fp) != (size_t)cert_der_len) {
            fprintf(stderr, "Error: Write failed\n");
            fclose(fp);
            return 1;
        }
        printf("Wrote %s (%u bytes DER)\n", out_file, (unsigned)cert_der_len);
    } else {
        uint8_t pem_buf[CERTGEN_PEM_MAX];
        uint32_t pem_len = 0;
        rc = noxtls_certificate_der_to_pem(cert_der, cert_der_len, pem_buf, &pem_len);
        if (rc != NOXTLS_RETURN_SUCCESS || pem_len == 0) {
            fprintf(stderr, "Error: DER to PEM failed\n");
            fclose(fp);
            return 1;
        }
        if (fwrite(pem_buf, 1, pem_len, fp) != (size_t)pem_len) {
            fprintf(stderr, "Error: Write failed\n");
            fclose(fp);
            return 1;
        }
        printf("Wrote %s (PEM)\n", out_file);
    }
    fclose(fp);
    return 0;
}
#endif

static int cmd_req(int argc, char **argv, const char *prog)
{
    (void)prog;
    const char *key_file = NULL;
    const char *out_file = NULL;
    const char *outform = "PEM";
    int days = 365;
    const char *subj = "/CN=localhost";
    int new_x509 = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_file = argv[++i];
        } else if (strcmp(argv[i], "-outform") == 0 && i + 1 < argc) {
            outform = argv[++i];
        } else if (strcmp(argv[i], "-days") == 0 && i + 1 < argc) {
            days = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-subj") == 0 && i + 1 < argc) {
            subj = argv[++i];
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

        if (priv.key_type == X509_PRIVATE_KEY_ECC) {
            ecc_key_t ecc_key;
            noxtls_return_t rc = noxtls_x509_private_key_to_ecc_key(&priv, &ecc_key);
            if (rc != NOXTLS_RETURN_SUCCESS) {
                fprintf(stderr, "Error: Failed to convert key to ECC\n");
                noxtls_x509_private_key_free(&priv);
                return 1;
            }

            uint32_t curve_size = ecc_key.curve != NULL ? ecc_key.curve->size : 32;
            uint8_t pub_key_buf[133]; /* 1 + 2*66 for P-521 */
            if (curve_size > 66 || 1 + 2 * curve_size > sizeof(pub_key_buf)) {
                fprintf(stderr, "Error: Unsupported curve size\n");
                noxtls_ecc_key_free(&ecc_key);
                noxtls_x509_private_key_free(&priv);
                return 1;
            }
            pub_key_buf[0] = 0x04;
            memcpy(pub_key_buf + 1, ecc_key.Q.x, curve_size);
            memcpy(pub_key_buf + 1 + curve_size, ecc_key.Q.y, curve_size);
            uint32_t pub_key_len = 1 + 2 * curve_size;
            noxtls_ecc_key_free(&ecc_key);

            int out = certgen_self_signed_x509_common(
                cn_buf, days,
                oid_id_ec_public_key, (uint32_t)sizeof(oid_id_ec_public_key),
                pub_key_buf, pub_key_len,
                oid_ecdsa_sha256, (uint32_t)sizeof(oid_ecdsa_sha256),
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256,
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
                pub_raw, 57,
                oid_ed448, (uint32_t)sizeof(oid_ed448),
                key_raw, key_raw_len,
                NOXTLS_HASH_SHA_256,
                out_file, outform);
            noxtls_x509_private_key_free(&priv);
            return out;
        }
#endif
        noxtls_x509_private_key_free(&priv);
        fprintf(stderr, "Error: Self-signed certificate generation supports ECC, Ed25519, and Ed448 keys.\n");
        fprintf(stderr, "Use %s genec / gened25519 / gened448, then req -new -x509 -key ...\n", prog);
        return 1;
    }
#else
    if (priv.key_type != X509_PRIVATE_KEY_RSA) {
        fprintf(stderr, "Error: This build supports only RSA for certificate generation (not implemented).\n");
        noxtls_x509_private_key_free(&priv);
        return 1;
    }
    noxtls_x509_private_key_free(&priv);
    fprintf(stderr, "Self-signed certificate generation is not available in this build.\n");
    fprintf(stderr, "Build with -DNOXTLS_HAVE_CERT_WRITE=ON to enable ECC self-signed cert generation.\n");
    fprintf(stderr, "Example with OpenSSL: openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj /CN=localhost\n");
    return 1;
#endif
}

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
        printf("certgen %s (NOXTLS)\n", CERTGEN_VERSION);
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
    if (strcmp(argv[1], "req") == 0) {
        return cmd_req(argc - 1, argv + 1, prog);
    }
    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage(prog);
    return 1;
}
