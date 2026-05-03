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

uint8_t debug_lvl = 0;

void print_usage(const char *name)
{
    printf("usage: %s [operation] [algorithm] <parameters>\n", name);
    printf("\nSupported Operations:\n\n");
    printf("  encrypt    - Encrypt data using public key\n");
    printf("  decrypt    - Decrypt data using private key\n");
    printf("  sign       - Sign data using private key\n");
    printf("  verify     - Verify signature using public key\n");
    printf("  genkey     - Generate RSA key pair\n");
    
    printf("\nSupported Algorithms:\n\n");
    printf("  rsa        - RSA (Rivest-Shamir-Adleman)\n");
    
    printf("\nCommandline Switches:\n\n");
    printf("  -k <size>      Key size in bits (1024, 2048, 3072, 4096) - default: 2048\n");
    printf("  -h <algo>      Hash algorithm for signatures (md5, sha1, sha256) - default: sha256\n");
    printf("  -d             Enable debug mode\n");
    printf("  -x             Interpret input data as hexadecimal string\n");
    printf("  -v             Version Information\n");
    
    printf("\nExamples:\n\n");
    printf("  %s encrypt rsa \"Hello World\"\n", name);
    printf("  %s decrypt rsa <hex_ciphertext>\n", name);
    printf("  %s sign rsa \"Message to sign\"\n", name);
    printf("  %s verify rsa \"Message\" <hex_signature>\n", name);
    printf("  %s genkey rsa -k 2048\n", name);
    
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
    rsa_key_size_t key_size = RSA_2048_BIT;
    noxtls_hash_algos_t hash_algo = NOXTLS_HASH_SHA_256;
    input_data_type_t input_type = INPUT_DATA_TYPE_STRING;
    int argc_skip = 1;  /* Skip program name */
    uint8_t *data_buffer = NULL;
    uint32_t data_length = 0;
    
    if(argc < 2) {
        print_usage(argv[0]);
        return -1;
    }
    
    /* Parse operation */
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
    
    /* Parse algorithm */
    if(strcmp(argv[argc_skip], "rsa") == 0) {
        algorithm_specified = 1;
        argc_skip++;
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
    
    /* Parse options */
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
    
    /* Handle genkey operation */
    if(operation == PKC_OP_GENKEY) {
        return rsa_genkey_handler(key_size);
    }
    
    /* Collect data arguments */
    if(arg_idx >= argc) {
        printf("Error: No data provided\n");
        return -1;
    }
    
    if(operation == PKC_OP_VERIFY) {
        /* Verify needs message and signature */
        if(arg_idx + 1 >= argc) {
            printf("Error: Verify operation requires message and signature\n");
            return -1;
        }
        
        /* Process message */
        size_t msg_len = strlen(argv[arg_idx]);
        if(msg_len > UINT32_MAX) {
            printf("Error: Input too large\n");
            return -1;
        }
        data_buffer = (uint8_t*)malloc(msg_len);
        if(!data_buffer) {
            printf("Error: Memory allocation failed\n");
            return -1;
        }
        
        if(input_type == INPUT_DATA_TYPE_HEX) {
            (void)noxtls_process_string_to_bytes(argv[arg_idx], data_buffer);
        } else {
            memcpy(data_buffer, argv[arg_idx], msg_len);
        }
        
        /* Process signature (hex) */
        arg_idx++;
        size_t sig_len = strlen(argv[arg_idx]);
        if(sig_len > UINT32_MAX) {
            free(data_buffer);
            printf("Error: Signature too large\n");
            return -1;
        }
        uint8_t *sig_buffer = (uint8_t*)malloc(sig_len);
        if(!sig_buffer) {
            free(data_buffer);
            printf("Error: Memory allocation failed\n");
            return -1;
        }
        uint32_t signature_length = noxtls_process_string_to_bytes(argv[arg_idx], sig_buffer);
        
        /* For now, verify with generated key (in real usage, keys would be loaded) */
        printf("Note: Verification requires public key. Using placeholder.\n");
        printf("Signature verification not fully implemented for external keys yet.\n");
        printf("Signature length: %u bytes\n", signature_length);
        
        free(data_buffer);
        free(sig_buffer);
        return 0;
    }
    
    /* Process input data */
    size_t total_len = 0;
    int i;
    for(i = arg_idx; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        if(total_len > SIZE_MAX - arg_len - 1) {
            printf("Error: Input too large\n");
            return -1;
        }
        total_len += arg_len + 1;  /* +1 for space */
    }
    
    if(total_len > UINT32_MAX) {
        printf("Error: Input too large\n");
        return -1;
    }
    data_buffer = (uint8_t*)malloc(total_len);
    if(!data_buffer) {
        printf("Error: Memory allocation failed\n");
        return -1;
    }
    
    data_length = 0;
    for(i = arg_idx; i < argc; i++) {
        if(input_type == INPUT_DATA_TYPE_HEX) {
            int len = noxtls_process_string_to_bytes(argv[i], data_buffer + data_length);
            if(len > 0) {
                if((uint32_t)len > UINT32_MAX - data_length) {
                    free(data_buffer);
                    printf("Error: Input too large\n");
                    return -1;
                }
                data_length += (uint32_t)len;
            }
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
    
    /* Execute operation */
    if(operation == PKC_OP_ENCRYPT) {
        return rsa_encrypt_handler(data_buffer, data_length, key_size);
    } else if(operation == PKC_OP_SIGN) {
        return rsa_sign_handler(data_buffer, data_length, key_size, hash_algo);
    } else if(operation == PKC_OP_DECRYPT) {
        printf("Note: Decryption requires private key. Using placeholder.\n");
        printf("Decryption not fully implemented for external keys yet.\n");
        free(data_buffer);
        return 0;
    }
    
    free(data_buffer);
    return 0;
}

