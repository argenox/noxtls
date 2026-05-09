/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of a
* commercial license from Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
* 
*
* File:    main.c
* Summary: Public Key Cryptography Utility Application
*
*/

/**
 * @file main.c
 * @brief Public key cryptography CLI (RSA encrypt/decrypt, sign/verify).
 * @defgroup noxtls_app_pkc PKC utility
 * @details
 * Operations: encrypt, decrypt, sign, verify, genkey. Algorithm: rsa.
 * Parameters: operation, algorithm, then key/data as needed.
 * Options: -k &lt;bits&gt; key size (1024,2048,3072,4096), -h &lt;algo&gt; hash (md5,sha1,sha256),
 * -d debug, -x input as hex, -v version.
 * @example
 * pkc encrypt rsa "Hello World"
 * pkc decrypt rsa &lt;hex_ciphertext&gt;
 * pkc sign rsa "Message to sign"
 * pkc verify rsa "Message" &lt;hex_signature&gt;
 * pkc genkey rsa -k 2048
 * pkc -h
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls_common.h"
#include "string_common.h"
#include "noxtls-lib/pkc/rsa/noxtls_rsa.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#if NOXTLS_FEATURE_ED25519
#include "noxtls-lib/pkc/ed25519/noxtls_ed25519.h"
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
#include "noxtls-lib/pkc/ed448/noxtls_ed448.h"
#endif
#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
#include "noxtls-lib/certs/noxtls_x509.h"
#endif

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 0

typedef enum {
    PKC_OP_ENCRYPT,
    PKC_OP_DECRYPT,
    PKC_OP_SIGN,
    PKC_OP_VERIFY,
    PKC_OP_GENKEY,
} pkc_operation_t;

typedef enum {
    INPUT_DATA_TYPE_STRING,
    INPUT_DATA_TYPE_HEX,
} input_data_type_t;

typedef enum {
    PKC_ALG_RSA = 0,
    PKC_ALG_ED25519,
    PKC_ALG_ED25519CTX,
    PKC_ALG_ED25519PH,
    PKC_ALG_ED448,
    PKC_ALG_ED448CTX,
    PKC_ALG_ED448PH,
} pkc_alg_t;

uint8_t debug_lvl = 0;

void print_usage(const char *name)
{
    printf("usage: %s [operation] [algorithm] <parameters>\n", name);
    printf("\nSupported Operations:\n\n");
    printf("  encrypt    - Encrypt data using public key (RSA only)\n");
    printf("  decrypt    - Decrypt data using private key (RSA only)\n");
    printf("  sign       - Sign data using private key\n");
    printf("  verify     - Verify signature using public key\n");
    printf("  genkey     - Generate key pair\n");

    printf("\nSupported Algorithms:\n\n");
    printf("  rsa        - RSA\n");
#if NOXTLS_FEATURE_ED25519
    printf("  ed25519    - Ed25519 (PureEdDSA)\n");
    printf("  ed25519ctx - Ed25519ctx (requires -C <hex> context, 1..255 bytes)\n");
    printf("  ed25519ph  - Ed25519ph (pre-hash)\n");
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    printf("  ed448      - Ed448 (PureEdDSA)\n");
    printf("  ed448ctx   - Ed448ctx (requires -C <hex> context)\n");
    printf("  ed448ph    - Ed448ph (pre-hash)\n");
#endif

    printf("\nCommandline Switches:\n\n");
    printf("  -k <size>      RSA key size (1024, 2048, 3072, 4096) - default: 2048\n");
    printf("  -K <file>      Private key PEM/DER (PKCS#8) for EdDSA sign\n");
    printf("  -P <hex>       Raw public key hex (32 bytes Ed25519, 57 bytes Ed448) for EdDSA verify\n");
    printf("  -C <hex>       Context hex for *ctx algorithms (sign and verify)\n");
    printf("  -h <algo>      Hash for RSA signatures (md5, sha1, sha256) - default: sha256\n");
    printf("  -d             Enable debug mode\n");
    printf("  -x             Interpret message input as hexadecimal\n");
    printf("  -v             Version information\n");

    printf("\nExamples:\n\n");
    printf("  %s encrypt rsa \"Hello World\"\n", name);
    printf("  %s sign rsa \"Message to sign\"\n", name);
#if NOXTLS_FEATURE_ED25519
    printf("  %s genkey ed25519\n", name);
    printf("  %s sign ed25519 -K key.pem \"message\"\n", name);
    printf("  %s verify ed25519 -P <64-char hex> \"message\" <128-char hex sig>\n", name);
#endif
    printf("\n");
}

void print_version(void)
{
    printf("PKC Utility v%d.%d.%d\n", APP_VERSION_MAJOR, APP_VERSION_MINOR, APP_VERSION_BUILD);
}

void print_hex(const uint8_t *data, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int pkc_alg_is_eddsa(pkc_alg_t a)
{
#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
    return (int)a >= (int)PKC_ALG_ED25519 && (int)a <= (int)PKC_ALG_ED448PH;
#else
    (void)a;
    return 0;
#endif
}

#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
static int pkc_read_file_alloc(const char *path, uint8_t **out, uint32_t *out_len)
{
    FILE *fp;
#ifdef _MSC_VER
    if(fopen_s(&fp, path, "rb") != 0 || fp == NULL) {
        return -1;
    }
#else
    fp = fopen(path, "rb");
    if(fp == NULL) {
        return -1;
    }
#endif
    if(fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if(sz <= 0 || sz > (1 << 20)) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1u);
    if(buf == NULL) {
        fclose(fp);
        return -1;
    }
    if(fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    buf[(size_t)sz] = '\0';
    *out = buf;
    *out_len = (uint32_t)sz;
    return 0;
}

static int pkc_load_x509_private_key_file(const char *path, x509_private_key_t *key)
{
    uint8_t *buf = NULL;
    uint32_t blen = 0;
    if(pkc_read_file_alloc(path, &buf, &blen) != 0) {
        return -1;
    }
    noxtls_x509_private_key_init(key);
    noxtls_return_t rc = noxtls_x509_private_key_parse_pem(key, buf, blen);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_x509_private_key_parse_der(key, buf, blen);
    }
    free(buf);
    return rc == NOXTLS_RETURN_SUCCESS ? 0 : -1;
}

static int pkc_hex_to_bytes(const char *hex, uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
    size_t hl = strlen(hex);
    int parsed_len;
    if(hl % 2u != 0 || hl / 2u > (size_t)out_max) {
        return -1;
    }
    parsed_len = noxtls_hex_string_to_bytes(hex, out, hl / 2u);
    if(parsed_len < 0) {
        return -1;
    }
    *out_len = (uint32_t)parsed_len;
    if(*out_len != hl / 2u) {
        return -1;
    }
    return 0;
}

static int pkc_eddsa_sign(pkc_alg_t alg, const char *key_path, const char *ctx_hex,
    const uint8_t *msg, uint32_t msg_len)
{
    x509_private_key_t pk;
    if(pkc_load_x509_private_key_file(key_path, &pk) != 0) {
        printf("Error: Cannot load private key from %s\n", key_path);
        return -1;
    }

    uint8_t ctx_buf[255];
    uint32_t ctx_len = 0;
    if(ctx_hex != NULL && ctx_hex[0] != '\0') {
        if(pkc_hex_to_bytes(ctx_hex, ctx_buf, (uint32_t)sizeof(ctx_buf), &ctx_len) != 0) {
            printf("Error: Bad context hex\n");
            noxtls_x509_private_key_free(&pk);
            return -1;
        }
    }

    uint32_t sl;
    const uint8_t *seed = noxtls_x509_private_key_get_eddsa_seed(&pk, &sl);
    int ret = -1;

#if NOXTLS_FEATURE_ED25519
    if(alg >= PKC_ALG_ED25519 && alg <= PKC_ALG_ED25519PH) {
        if(seed == NULL || sl != 32) {
            printf("Error: Key is not Ed25519 PKCS#8\n");
            noxtls_x509_private_key_free(&pk);
            return -1;
        }
        uint8_t sig[64];
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        if(alg == PKC_ALG_ED25519) {
            rc = noxtls_ed25519_sign(seed, msg, msg_len, sig);
        } else if(alg == PKC_ALG_ED25519CTX) {
            if(ctx_len < 1 || ctx_len > NOXTLS_ED25519_CONTEXT_MAX) {
                printf("Error: ed25519ctx requires -C with 1..255 byte context\n");
                noxtls_x509_private_key_free(&pk);
                return -1;
            }
            rc = noxtls_ed25519ctx_sign(seed, ctx_buf, ctx_len, msg, msg_len, sig);
        } else if(alg == PKC_ALG_ED25519PH) {
            rc = noxtls_ed25519ph_sign(seed, msg, msg_len, sig);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            printf("Signature: ");
            print_hex(sig, 64);
            ret = 0;
        } else {
            printf("Error: Ed25519 sign failed\n");
        }
        noxtls_x509_private_key_free(&pk);
        return ret;
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(alg >= PKC_ALG_ED448 && alg <= PKC_ALG_ED448PH) {
        if(seed == NULL || sl != 57) {
            printf("Error: Key is not Ed448 PKCS#8\n");
            noxtls_x509_private_key_free(&pk);
            return -1;
        }
        uint8_t sig[114];
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        if(alg == PKC_ALG_ED448) {
            rc = noxtls_ed448_sign(seed, msg, msg_len, sig);
        } else if(alg == PKC_ALG_ED448CTX) {
            if(ctx_len < 1 || ctx_len > NOXTLS_ED448_CONTEXT_MAX) {
                printf("Error: ed448ctx requires -C with 1..255 byte context\n");
                noxtls_x509_private_key_free(&pk);
                return -1;
            }
            rc = noxtls_ed448ctx_sign(seed, ctx_buf, ctx_len, msg, msg_len, sig);
        } else if(alg == PKC_ALG_ED448PH) {
            rc = noxtls_ed448ph_sign(seed, msg, msg_len, sig);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            printf("Signature: ");
            print_hex(sig, 114);
            ret = 0;
        } else {
            printf("Error: Ed448 sign failed\n");
        }
        noxtls_x509_private_key_free(&pk);
        return ret;
    }
#endif
    (void)msg;
    (void)msg_len;
    printf("Error: Unsupported EdDSA algorithm for sign\n");
    noxtls_x509_private_key_free(&pk);
    return -1;
}

static int pkc_eddsa_verify(pkc_alg_t alg, const char *pub_hex, const char *ctx_hex,
    const uint8_t *msg, uint32_t msg_len, const uint8_t *sig, uint32_t sig_len)
{
    uint8_t pub[57];
    uint32_t pub_len = 0;
    if(pkc_hex_to_bytes(pub_hex, pub, (uint32_t)sizeof(pub), &pub_len) != 0) {
        printf("Error: Bad public key hex\n");
        return -1;
    }

    uint8_t ctx_buf[255];
    uint32_t ctx_len = 0;
    if(ctx_hex != NULL && ctx_hex[0] != '\0') {
        if(pkc_hex_to_bytes(ctx_hex, ctx_buf, (uint32_t)sizeof(ctx_buf), &ctx_len) != 0) {
            printf("Error: Bad context hex\n");
            return -1;
        }
    }

#if NOXTLS_FEATURE_ED25519
    if(alg >= PKC_ALG_ED25519 && alg <= PKC_ALG_ED25519PH) {
        if(pub_len != 32 || sig_len != 64) {
            printf("Error: Ed25519 expects 32-byte public key and 64-byte signature\n");
            return -1;
        }
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        if(alg == PKC_ALG_ED25519) {
            rc = noxtls_ed25519_verify(pub, msg, msg_len, sig);
        } else if(alg == PKC_ALG_ED25519CTX) {
            rc = noxtls_ed25519ctx_verify(pub, ctx_buf, ctx_len, msg, msg_len, sig);
        } else {
            rc = noxtls_ed25519ph_verify(pub, msg, msg_len, sig);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            printf("Signature verification: SUCCESS\n");
        } else {
            printf("Signature verification: FAILED\n");
        }
        return rc == NOXTLS_RETURN_SUCCESS ? 0 : -1;
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(alg >= PKC_ALG_ED448 && alg <= PKC_ALG_ED448PH) {
        if(pub_len != 57 || sig_len != 114) {
            printf("Error: Ed448 expects 57-byte public key and 114-byte signature\n");
            return -1;
        }
        noxtls_return_t rc = NOXTLS_RETURN_FAILED;
        if(alg == PKC_ALG_ED448) {
            rc = noxtls_ed448_verify(pub, msg, msg_len, sig);
        } else if(alg == PKC_ALG_ED448CTX) {
            rc = noxtls_ed448ctx_verify(pub, ctx_buf, ctx_len, msg, msg_len, sig);
        } else {
            rc = noxtls_ed448ph_verify(pub, msg, msg_len, sig);
        }
        if(rc == NOXTLS_RETURN_SUCCESS) {
            printf("Signature verification: SUCCESS\n");
        } else {
            printf("Signature verification: FAILED\n");
        }
        return rc == NOXTLS_RETURN_SUCCESS ? 0 : -1;
    }
#endif
    printf("Error: Unsupported EdDSA algorithm for verify\n");
    return -1;
}

static int pkc_eddsa_genkey(pkc_alg_t alg)
{
#if NOXTLS_FEATURE_ED25519
    if(alg == PKC_ALG_ED25519) {
        uint8_t sk[32], pk[32];
        if(noxtls_ed25519_generate_key(sk, pk) != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        printf("private seed (hex): ");
        print_hex(sk, 32);
        printf("\npublic key (hex): ");
        print_hex(pk, 32);
        return 0;
    }
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    if(alg == PKC_ALG_ED448) {
        uint8_t sk[57], pk[57];
        if(noxtls_ed448_generate_key(sk, pk) != NOXTLS_RETURN_SUCCESS) {
            return -1;
        }
        printf("private seed (hex): ");
        print_hex(sk, 57);
        printf("\npublic key (hex): ");
        print_hex(pk, 57);
        return 0;
    }
#endif
    printf("Error: genkey for this EdDSA algorithm is not supported (use ed25519 or ed448)\n");
    return -1;
}
#endif /* NOXTLS_FEATURE_ED25519 || ED448 */

int rsa_encrypt_handler(const uint8_t *data, uint32_t data_len, rsa_key_size_t key_size)
{
    rsa_key_t key;
    noxtls_return_t rc;
    uint8_t *ciphertext = NULL;
    uint32_t ciphertext_len = 0;
    
    if(debug_lvl > 0) {
        printf("RSA Encryption\n");
        printf("Data length: %u bytes\n", data_len);
        printf("Key size: %u bits\n", (unsigned int)key_size);
    }
    
    /* Initialize key structure */
    rc = noxtls_rsa_key_init(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to initialize RSA key structure\n");
        return -1;
    }
    
    /* Generate key pair */
    if(debug_lvl > 0) {
        printf("Generating RSA key pair...\n");
    }
    rc = noxtls_rsa_key_generate(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to generate RSA key pair\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    if(debug_lvl > 0) {
        printf("Key pair generated successfully\n");
    }
    
    /* Allocate ciphertext buffer */
    ciphertext_len = key.key_bytes;
    ciphertext = (uint8_t*)malloc(ciphertext_len);
    if(!ciphertext) {
        printf("Error: Memory allocation failed\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Encrypt */
    rc = noxtls_rsa_encrypt(&key, data, data_len, ciphertext, &ciphertext_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Encryption failed\n");
        free(ciphertext);
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Print ciphertext */
    printf("Ciphertext: ");
    print_hex(ciphertext, ciphertext_len);
    
    /* Print public key for decryption */
    printf("\nPublic Key (n): ");
    print_hex(key.n, key.key_bytes);
    printf("Public Key (e): ");
    print_hex(key.e, key.key_bytes);
    
    free(ciphertext);
    noxtls_rsa_key_free(&key);
    
    return 0;
}

int rsa_decrypt_handler(uint8_t *ciphertext, uint32_t ciphertext_len, rsa_key_size_t key_size, const uint8_t *n, uint32_t n_len, const uint8_t *d, uint32_t d_len)
{
    rsa_key_t key;
    noxtls_return_t rc;
    uint8_t *plaintext = NULL;
    uint32_t plaintext_len = 0;
    
    if(debug_lvl > 0) {
        printf("RSA Decryption\n");
        printf("Ciphertext length: %u bytes\n", ciphertext_len);
        printf("Key size: %u bits\n", (unsigned int)key_size);
    }
    
    /* Initialize key structure */
    rc = noxtls_rsa_key_init(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to initialize RSA key structure\n");
        return -1;
    }
    
    /* Load private key components */
    if(n && n_len == key.key_bytes) {
        memcpy(key.n, n, n_len);
    } else {
        printf("Error: Invalid modulus (n) provided\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    if(d && d_len == key.key_bytes) {
        memcpy(key.d, d, d_len);
    } else {
        printf("Error: Invalid private exponent (d) provided\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Allocate plaintext buffer */
    plaintext_len = key.key_bytes;
    plaintext = (uint8_t*)malloc(plaintext_len);
    if(!plaintext) {
        printf("Error: Memory allocation failed\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Decrypt */
    rc = noxtls_rsa_decrypt(&key, ciphertext, ciphertext_len, plaintext, &plaintext_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Decryption failed\n");
        free(plaintext);
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Print plaintext */
    printf("Plaintext: ");
    print_hex(plaintext, plaintext_len);
    printf("Plaintext (ASCII): ");
    fwrite(plaintext, 1, plaintext_len, stdout);
    printf("\n");
    
    free(plaintext);
    noxtls_rsa_key_free(&key);
    
    return 0;
}

int rsa_sign_handler(const uint8_t *data, uint32_t data_len, rsa_key_size_t key_size, noxtls_hash_algos_t hash_algo)
{
    rsa_key_t key;
    noxtls_return_t rc;
    uint8_t *signature = NULL;
    uint32_t signature_len = 0;
    
    if(debug_lvl > 0) {
        printf("RSA Signature Generation\n");
        printf("Data length: %u bytes\n", data_len);
        printf("Key size: %u bits\n", (unsigned int)key_size);
    }
    
    /* Initialize key structure */
    rc = noxtls_rsa_key_init(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to initialize RSA key structure\n");
        return -1;
    }
    
    /* Generate key pair */
    if(debug_lvl > 0) {
        printf("Generating RSA key pair...\n");
    }
    rc = noxtls_rsa_key_generate(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to generate RSA key pair\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    if(debug_lvl > 0) {
        printf("Key pair generated successfully\n");
    }
    
    /* Allocate signature buffer */
    signature_len = key.key_bytes;
    signature = (uint8_t*)malloc(signature_len);
    if(!signature) {
        printf("Error: Memory allocation failed\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Sign */
    rc = noxtls_rsa_sign(&key, data, data_len, signature, &signature_len, hash_algo);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Signature generation failed\n");
        free(signature);
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Print signature */
    printf("Signature: ");
    print_hex(signature, signature_len);
    
    /* Print public key for verification */
    printf("\nPublic Key (n): ");
    print_hex(key.n, key.key_bytes);
    printf("Public Key (e): ");
    print_hex(key.e, key.key_bytes);
    
    free(signature);
    noxtls_rsa_key_free(&key);
    
    return 0;
}

int rsa_verify_handler(const uint8_t *data, uint32_t data_len, const uint8_t *signature, uint32_t signature_len, rsa_key_size_t key_size, noxtls_hash_algos_t hash_algo, const uint8_t *n, uint32_t n_len, const uint8_t *e, uint32_t e_len)
{
    rsa_key_t key;
    noxtls_return_t rc;
    
    if(debug_lvl > 0) {
        printf("RSA Signature Verification\n");
        printf("Data length: %u bytes\n", data_len);
        printf("Signature length: %u bytes\n", signature_len);
        printf("Key size: %u bits\n", (unsigned int)key_size);
    }
    
    /* Initialize key structure */
    rc = noxtls_rsa_key_init(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to initialize RSA key structure\n");
        return -1;
    }
    
    /* Load public key components */
    if(n && n_len == key.key_bytes) {
        memcpy(key.n, n, n_len);
    } else {
        printf("Error: Invalid modulus (n) provided\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    if(e && e_len == key.key_bytes) {
        memcpy(key.e, e, e_len);
    } else {
        printf("Error: Invalid public exponent (e) provided\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    /* Verify */
    rc = noxtls_rsa_verify(&key, data, data_len, signature, signature_len, hash_algo);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        printf("Signature verification: SUCCESS\n");
        noxtls_rsa_key_free(&key);
        return 0;
    } else {
        printf("Signature verification: FAILED\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
}

int rsa_genkey_handler(rsa_key_size_t key_size)
{
    rsa_key_t key;
    noxtls_return_t rc;
    
    if(debug_lvl > 0) {
        printf("RSA Key Generation\n");
        printf("Key size: %u bits\n", (unsigned int)key_size);
    }
    
    /* Initialize key structure */
    rc = noxtls_rsa_key_init(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to initialize RSA key structure\n");
        return -1;
    }
    
    /* Generate key pair */
    printf("Generating RSA key pair (this may take a while)...\n");
    rc = noxtls_rsa_key_generate(&key, key_size);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        printf("Error: Failed to generate RSA key pair\n");
        noxtls_rsa_key_free(&key);
        return -1;
    }
    
    printf("Key pair generated successfully!\n\n");
    
    /* Print public key */
    printf("Public Key:\n");
    printf("  Modulus (n): ");
    print_hex(key.n, key.key_bytes);
    printf("  Exponent (e): ");
    print_hex(key.e, key.key_bytes);
    
    /* Print private key */
    printf("\nPrivate Key:\n");
    printf("  Modulus (n): ");
    print_hex(key.n, key.key_bytes);
    printf("  Private Exponent (d): ");
    print_hex(key.d, key.key_bytes);
    
    /* Print prime numbers in hex */
    printf("\nPrime Components:\n");
    if(key.p) {
        printf("  Prime p (hex): ");
        print_hex(key.p, key.key_bytes / 2);
    } else {
        printf("  Prime p: (not available)\n");
    }
    if(key.q) {
        printf("  Prime q (hex): ");
        print_hex(key.q, key.key_bytes / 2);
    } else {
        printf("  Prime q: (not available)\n");
    }
    
    noxtls_rsa_key_free(&key);
    
    return 0;
}

int main(int argc, char **argv)
{
    pkc_operation_t operation = PKC_OP_ENCRYPT;
    int algorithm_specified = 0;
    pkc_alg_t alg = PKC_ALG_RSA;
    rsa_key_size_t key_size = RSA_2048_BIT;
    noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
    input_data_type_t input_type = INPUT_DATA_TYPE_STRING;
    int argc_skip = 1;
    uint8_t *data_buffer = NULL;
    uint32_t data_length = 0;
    const char *opt_key_file = NULL;
    const char *opt_pub_hex = NULL;
    const char *opt_ctx_hex = NULL;

    if(argc < 2) {
        print_usage(argv[0]);
        return -1;
    }

    if(strcmp(argv[argc_skip], "encrypt") == 0) {
        operation = PKC_OP_ENCRYPT;
        argc_skip++;
    } else if(strcmp(argv[argc_skip], "decrypt") == 0) {
        operation = PKC_OP_DECRYPT;
        argc_skip++;
    } else if(strcmp(argv[argc_skip], "sign") == 0) {
        operation = PKC_OP_SIGN;
        argc_skip++;
    } else if(strcmp(argv[argc_skip], "verify") == 0) {
        operation = PKC_OP_VERIFY;
        argc_skip++;
    } else if(strcmp(argv[argc_skip], "genkey") == 0) {
        operation = PKC_OP_GENKEY;
        argc_skip++;
    } else if(strcmp(argv[argc_skip], "-v") == 0 || strcmp(argv[argc_skip], "--version") == 0) {
        print_version();
        return 0;
    } else if(strcmp(argv[argc_skip], "-h") == 0 || strcmp(argv[argc_skip], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        printf("Error: Unknown operation '%s'\n", argv[argc_skip]);
        print_usage(argv[0]);
        return -1;
    }

    if(argc_skip >= argc) {
        printf("Error: Algorithm not specified\n");
        print_usage(argv[0]);
        return -1;
    }

    if(strcmp(argv[argc_skip], "rsa") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_RSA;
        argc_skip++;
#if NOXTLS_FEATURE_ED25519
    } else if(strcasecmp(argv[argc_skip], "ed25519") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_ED25519;
        argc_skip++;
    } else if(strcasecmp(argv[argc_skip], "ed25519ctx") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_ED25519CTX;
        argc_skip++;
    } else if(strcasecmp(argv[argc_skip], "ed25519ph") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_ED25519PH;
        argc_skip++;
#endif
#if NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3
    } else if(strcasecmp(argv[argc_skip], "ed448") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_ED448;
        argc_skip++;
    } else if(strcasecmp(argv[argc_skip], "ed448ctx") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_ED448CTX;
        argc_skip++;
    } else if(strcasecmp(argv[argc_skip], "ed448ph") == 0) {
        algorithm_specified = 1;
        alg = PKC_ALG_ED448PH;
        argc_skip++;
#endif
    } else {
        printf("Error: Unknown algorithm '%s'\n", argv[argc_skip]);
        print_usage(argv[0]);
        return -1;
    }

    if(!algorithm_specified) {
        printf("Error: Algorithm not specified\n");
        print_usage(argv[0]);
        return -1;
    }

    int arg_idx = argc_skip;
    while(arg_idx < argc && argv[arg_idx][0] == '-') {
        if(strcmp(argv[arg_idx], "-k") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -k option requires a key size\n");
                return -1;
            }
            arg_idx++;
            int size = atoi(argv[arg_idx]);
            if(size == 1024) {
                key_size = RSA_1024_BIT;
            } else if(size == 2048) {
                key_size = RSA_2048_BIT;
            } else if(size == 3072) {
                key_size = RSA_3072_BIT;
            } else if(size == 4096) {
                key_size = RSA_4096_BIT;
            } else {
                printf("Error: Invalid key size. Supported: 1024, 2048, 3072, 4096\n");
                return -1;
            }
            arg_idx++;
        } else if(strcmp(argv[arg_idx], "-K") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -K requires a private key file path\n");
                return -1;
            }
            opt_key_file = argv[++arg_idx];
            arg_idx++;
#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
        } else if(strcmp(argv[arg_idx], "-P") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -P requires hex public key\n");
                return -1;
            }
            opt_pub_hex = argv[++arg_idx];
            arg_idx++;
        } else if(strcmp(argv[arg_idx], "-C") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -C requires hex context\n");
                return -1;
            }
            opt_ctx_hex = argv[++arg_idx];
            arg_idx++;
#endif
        } else if(strcmp(argv[arg_idx], "-h") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -h option requires a hash algorithm\n");
                return -1;
            }
            arg_idx++;
            if(strcasecmp(argv[arg_idx], "md5") == 0) {
                hash_algo = NOXTLS_HASH_MD5;
            } else if(strcasecmp(argv[arg_idx], "sha1") == 0) {
                hash_algo = NOXTLS_HASH_SHA1;
            } else if(strcasecmp(argv[arg_idx], "sha256") == 0) {
                hash_algo = NOXTLS_HASH_SHA_256;
            } else {
                printf("Error: Invalid hash algorithm. Supported: md5, sha1, sha256\n");
                return -1;
            }
            arg_idx++;
        } else if(strcmp(argv[arg_idx], "-d") == 0) {
            debug_lvl = 1;
            arg_idx++;
        } else if(strcmp(argv[arg_idx], "-x") == 0) {
            input_type = INPUT_DATA_TYPE_HEX;
            arg_idx++;
        } else {
            arg_idx++;
        }
    }

    if(operation == PKC_OP_GENKEY) {
        if(alg == PKC_ALG_RSA) {
            return rsa_genkey_handler(key_size);
        }
#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
        if(pkc_alg_is_eddsa(alg)) {
            return pkc_eddsa_genkey(alg);
        }
#endif
        printf("Error: genkey not supported for this algorithm\n");
        return -1;
    }

    if(alg != PKC_ALG_RSA && (operation == PKC_OP_ENCRYPT || operation == PKC_OP_DECRYPT)) {
        printf("Error: encrypt/decrypt are only supported with rsa\n");
        return -1;
    }

    if(arg_idx >= argc) {
        printf("Error: No data provided\n");
        return -1;
    }

    if(operation == PKC_OP_VERIFY) {
        if(arg_idx + 1 >= argc) {
            printf("Error: Verify operation requires message and signature\n");
            return -1;
        }

        size_t msg_len = strlen(argv[arg_idx]);
        if(msg_len > UINT32_MAX) {
            printf("Error: Input too large\n");
            return -1;
        }
        data_buffer = (uint8_t *)malloc(msg_len + 1u);
        if(!data_buffer) {
            printf("Error: Memory allocation failed\n");
            return -1;
        }
        uint32_t msg_bin_len;
        if(input_type == INPUT_DATA_TYPE_HEX) {
            if(pkc_hex_to_bytes(argv[arg_idx], data_buffer, (uint32_t)(msg_len + 1u), &msg_bin_len) != 0) {
                free(data_buffer);
                printf("Error: Invalid message hex\n");
                return -1;
            }
        } else {
            memcpy(data_buffer, argv[arg_idx], msg_len);
            msg_bin_len = (uint32_t)msg_len;
        }

        arg_idx++;
        size_t sig_hex_len = strlen(argv[arg_idx]);
        if(sig_hex_len > UINT32_MAX) {
            free(data_buffer);
            printf("Error: Signature too large\n");
            return -1;
        }
        uint8_t *sig_buffer = (uint8_t *)malloc(sig_hex_len + 1u);
        if(!sig_buffer) {
            free(data_buffer);
            printf("Error: Memory allocation failed\n");
            return -1;
        }
        uint32_t signature_length = 0;
        if(pkc_hex_to_bytes(argv[arg_idx], sig_buffer, (uint32_t)(sig_hex_len + 1u), &signature_length) != 0) {
            free(data_buffer);
            free(sig_buffer);
            printf("Error: Invalid signature hex\n");
            return -1;
        }

#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
        if(pkc_alg_is_eddsa(alg)) {
            if(opt_pub_hex == NULL) {
                printf("Error: EdDSA verify requires -P <hex public key>\n");
                free(data_buffer);
                free(sig_buffer);
                return -1;
            }
            int vr = pkc_eddsa_verify(alg, opt_pub_hex, opt_ctx_hex, data_buffer, msg_bin_len, sig_buffer, signature_length);
            free(data_buffer);
            free(sig_buffer);
            return vr;
        }
#endif
        if(alg == PKC_ALG_RSA) {
            printf("Note: RSA verify with external keys is not implemented; use openssl or a PEM-aware tool.\n");
            printf("Signature length: %u bytes\n", signature_length);
            free(data_buffer);
            free(sig_buffer);
            return 0;
        }
        free(data_buffer);
        free(sig_buffer);
        printf("Error: Verify not supported for this algorithm\n");
        return -1;
    }

    size_t total_len = 0;
    int i;
    for(i = arg_idx; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        if(total_len > SIZE_MAX - arg_len - 1) {
            printf("Error: Input too large\n");
            return -1;
        }
        total_len += arg_len + 1;
    }

    if(total_len > UINT32_MAX) {
        printf("Error: Input too large\n");
        return -1;
    }
    data_buffer = (uint8_t *)malloc(total_len);
    if(!data_buffer) {
        printf("Error: Memory allocation failed\n");
        return -1;
    }

    data_length = 0;
    for(i = arg_idx; i < argc; i++) {
        if(input_type == INPUT_DATA_TYPE_HEX) {
            uint32_t len = 0;
            uint32_t remaining = (uint32_t)(total_len - (size_t)data_length);
            if(pkc_hex_to_bytes(argv[i], data_buffer + data_length, remaining, &len) != 0) {
                free(data_buffer);
                printf("Error: Invalid hex input\n");
                return -1;
            }
            data_length += len;
        } else {
            size_t len = strlen(argv[i]);
            if(len > UINT32_MAX - data_length) {
                free(data_buffer);
                printf("Error: Input too large\n");
                return -1;
            }
            memcpy(data_buffer + data_length, argv[i], len);
            data_length += (uint32_t)len;
            if(i < argc - 1) {
                data_buffer[data_length++] = ' ';
            }
        }
    }

    if(operation == PKC_OP_ENCRYPT) {
        return rsa_encrypt_handler(data_buffer, data_length, key_size);
    }
    if(operation == PKC_OP_SIGN) {
#if NOXTLS_FEATURE_ED25519 || (NOXTLS_FEATURE_ED448 && NOXTLS_FEATURE_SHA3)
        if(pkc_alg_is_eddsa(alg)) {
            if(opt_key_file == NULL) {
                printf("Error: EdDSA sign requires -K <private key PEM/DER>\n");
                free(data_buffer);
                return -1;
            }
            int sr = pkc_eddsa_sign(alg, opt_key_file, opt_ctx_hex, data_buffer, data_length);
            free(data_buffer);
            return sr;
        }
#endif
        return rsa_sign_handler(data_buffer, data_length, key_size, hash_algo);
    }
    if(operation == PKC_OP_DECRYPT) {
        printf("Note: Decryption requires private key. Using placeholder.\n");
        printf("Decryption not fully implemented for external keys yet.\n");
        free(data_buffer);
        return 0;
    }

    free(data_buffer);
    return 0;
}

