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
* Summary: AES Utility Main Application
*
*/

/**
 * @file aes_main.c
 * @brief AES encryption/decryption command-line utility (ECB, CBC, CTR, CFB, OFB, XTS, GCM).
 * @defgroup noxtls_app_aes AES utility
 * @details
 * Command-line tool for AES encrypt/decrypt. Requires algorithm (128, 192, 256),
 * key and optional IV/tweak depending on mode.
 * Parameters: command (encrypt/decrypt), algorithm, key, mode, IV as needed, input data.
 * Options:
 *   -k <hex_key>   Encryption key in hex (required). 128: 32 hex chars, 192: 48, 256: 64.
 *   -m <mode>      ecb, cbc, ctr, cfb, ofb, xts, gcm (default: ecb).
 *   -i <hex_iv>    IV/tweak in hex (required for cbc, ctr, cfb, ofb, xts; gcm uses 12-byte nonce).
 *   -d             Debug mode.
 *   -h             Interpret input as hex string.
 *   -v             Version.
 * @example
 * AES-128 ECB encrypt (key and plaintext in hex):
 *   aes -k 2b7e151628aed2a6abf7158809cf4f3c -m ecb -h 6bc1bee22e409f96e93d7e117393172a
 * AES-256 CBC with IV:
 *   aes -k 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 -m cbc -i 000102030405060708090a0b0c0d0e0f -h <hex_plaintext>
 * Show usage:
 *   aes
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#include "noxtls-lib/common/getopt_win.h"
#else
#include <unistd.h>
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "handlers.h"
#include "string_common.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#include "noxtls-lib/encryption/aes/noxtls_aes.h"
#include "noxtls-lib/encryption/aes/noxtls_aes_gcm.h"

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4
#define NOXTLS_AES_GCM_IV_LENGTH 12
#define NOXTLS_AES_GCM_TAG_LENGTH 16


int aes_128_handler(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv);
int aes_256_handler(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv);
int aes_192_handler(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv);


void print_usage(const char * name);
static int parse_offset_value(const char * value, size_t * offset);
static int read_binary_file(const char * path, uint8_t ** buffer, size_t * length);
static int write_binary_file(const char * path, const uint8_t * buffer, size_t length);
static int aes_encrypt_buffer(
    const uint8_t * data,
    uint32_t len,
    const uint8_t * key,
    uint32_t key_len,
    noxtls_aes_mode_t mode,
    uint8_t * iv,
    uint8_t ** output,
    uint32_t * output_len,
    uint8_t tag[NOXTLS_AES_GCM_TAG_LENGTH],
    int * has_tag);

uint8_t debug_lvl = 0;

/* Custom handler type for AES that includes key, mode, and IV */
typedef int (*aes_handler_func_t)(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv);

typedef struct {
    char algo[32];
    aes_handler_func_t handler;
} aes_handlers_t;

aes_handlers_t aes_handlers[] = {
    {"128", aes_128_handler},
    {"192", aes_192_handler},
    {"256", aes_256_handler}
};

void print_usage(const char * name)
{
    printf( "usage: %s [command] <parameters>\n", name);
    printf("\nSupported Commands\n\n");

    size_t i = 0;
    printf("\nSupported Algorithms\n\n");

    for(i = 0; i < sizeof(aes_handlers) / sizeof(aes_handlers[0]); i++)
    {
        printf("%s  \t\t\t\n", aes_handlers[i].algo);
    }

    printf("\n\n");

    printf("\nCommandline Switches\n\n");

    printf("-k <hex_key>\t\tEncryption key in hexadecimal format (required)\n");
    printf("-m <mode>\t\tCipher mode: ecb, cbc, ctr, cfb, ofb, xts, gcm (default: ecb)\n");
    printf("-i <hex_iv>\t\tInitialization Vector/Tweak in hexadecimal format (required for cbc, ctr, cfb, ofb, xts, gcm)\n");
    printf("-d \t\t\tEnable debug mode\n");
    printf("-h \t\t\tInterpret input data as hexadecimal string\n");
    printf("-f <file>\t\tRead plaintext/ciphertext input from file\n");
    printf("-s <offset>\t\tStart encryption at byte offset when using -f\n");
    printf("-o <file>\t\tWrite encrypted output to file when using -f\n");
    printf("-v \t\t\tVersion Information\n");

    printf("\nKey Sizes:\n");
    printf("  AES-128: 16 bytes (32 hex characters)\n");
    printf("  AES-192: 24 bytes (48 hex characters)\n");
    printf("  AES-256: 32 bytes (64 hex characters)\n");
    
    printf("\nCipher Modes:\n");
    printf("  ecb - Electronic Codebook (no IV required)\n");
    printf("  cbc - Cipher Block Chaining (IV required: 16 bytes = 32 hex characters)\n");
    printf("  ctr - Counter Mode (IV required: 16 bytes = 32 hex characters)\n");
    printf("  cfb - Cipher Feedback (IV required: 16 bytes = 32 hex characters)\n");
    printf("  ofb - Output Feedback (IV required: 16 bytes = 32 hex characters)\n");
    printf("  xts - XEX-based Tweaked CodeBook with ciphertext Stealing (tweak required: 16 bytes = 32 hex characters)\n");
    printf("  gcm - Galois/Counter Mode (nonce required: 12 bytes = 24 hex characters)\n");

    printf("\n\n");
}

static int parse_offset_value(const char * value, size_t * offset)
{
    char * endptr = NULL;
    unsigned long long parsed = 0;

    if(value == NULL || offset == NULL || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    parsed = strtoull(value, &endptr, 0);
    if(errno != 0 || endptr == value || *endptr != '\0') {
        return -1;
    }

    *offset = (size_t)parsed;
    return 0;
}

static int read_binary_file(const char * path, uint8_t ** buffer, size_t * length)
{
    FILE * file = NULL;
    long file_size = 0;
    uint8_t * file_buffer = NULL;

    if(path == NULL || buffer == NULL || length == NULL) {
        return -1;
    }

    file = fopen(path, "rb");
    if(file == NULL) {
        return -1;
    }

    if(fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }

    file_size = ftell(file);
    if(file_size < 0) {
        fclose(file);
        return -1;
    }

    if(fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }

    file_buffer = malloc((size_t)file_size);
    if(file_size > 0 && file_buffer == NULL) {
        fclose(file);
        return -1;
    }

    if(file_size > 0) {
        size_t read_count = fread(file_buffer, 1, (size_t)file_size, file);
        if(read_count != (size_t)file_size) {
            free(file_buffer);
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    *buffer = file_buffer;
    *length = (size_t)file_size;
    return 0;
}

static int write_binary_file(const char * path, const uint8_t * buffer, size_t length)
{
    FILE * file = NULL;

    if(path == NULL || (buffer == NULL && length > 0)) {
        return -1;
    }

    file = fopen(path, "wb");
    if(file == NULL) {
        return -1;
    }

    if(length > 0) {
        size_t write_count = fwrite(buffer, 1, length, file);
        if(write_count != length) {
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    return 0;
}

static int aes_encrypt_buffer(
    const uint8_t * data,
    uint32_t len,
    const uint8_t * key,
    uint32_t key_len,
    noxtls_aes_mode_t mode,
    uint8_t * iv,
    uint8_t ** output,
    uint32_t * output_len,
    uint8_t tag[NOXTLS_AES_GCM_TAG_LENGTH],
    int * has_tag)
{
    uint16_t key_bits = 0;
    uint32_t encrypt_len = 0;
    uint8_t * padded_data = NULL;
    uint8_t * encrypted = NULL;
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(data == NULL || key == NULL || output == NULL || output_len == NULL || has_tag == NULL) {
        return -1;
    }

    if(key_len == 16) {
        key_bits = NOXTLS_AES_128_BIT;
    } else if(key_len == 24) {
        key_bits = NOXTLS_AES_192_BIT;
    } else if(key_len == 32) {
        key_bits = NOXTLS_AES_256_BIT;
    } else {
        return -1;
    }

    *output = NULL;
    *output_len = 0;
    *has_tag = 0;

    if(mode == NOXTLS_AES_GCM) {
        encrypted = malloc(len);
        if(encrypted == NULL && len > 0) {
            return -1;
        }

        rc = noxtls_aes_gcm_encrypt((uint8_t *)key, key_bits, iv, NULL, 0, data, len, encrypted, tag);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            free(encrypted);
            return -1;
        }

        *output = encrypted;
        *output_len = len;
        *has_tag = 1;
        return 0;
    }

    if(mode == NOXTLS_AES_CTR || mode == NOXTLS_AES_CFB || mode == NOXTLS_AES_OFB || mode == NOXTLS_AES_XTS) {
        encrypt_len = len;
    } else {
        encrypt_len = ((len + NOXTLS_AES_BLOCK_LENGTH - 1) / NOXTLS_AES_BLOCK_LENGTH) * NOXTLS_AES_BLOCK_LENGTH;
    }

    padded_data = malloc(encrypt_len);
    encrypted = malloc(encrypt_len);
    if((padded_data == NULL || encrypted == NULL) && encrypt_len > 0) {
        free(padded_data);
        free(encrypted);
        return -1;
    }

    if(encrypt_len > 0) {
        memset(padded_data, 0, encrypt_len);
        memcpy(padded_data, data, len);
    }

    rc = noxtls_aes_encrypt_data((uint8_t *)key, padded_data, encrypt_len, iv, encrypted, key_bits, mode);
    free(padded_data);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(encrypted);
        return -1;
    }

    *output = encrypted;
    *output_len = encrypt_len;
    return 0;
}

void print_version(void)
{
    printf("NOXTLS AES v%u.%u.%u\n", (unsigned int)APP_VERSION_MAJOR, (unsigned int)APP_VERSION_MINOR, (unsigned int)APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright (c) 2019-2026 Argenox Technologies LLC. All Rights Reserved.\n");
}

int main(int argc, char ** argv)
{
    size_t i = 0;
    uint32_t data_length = 0;
    uint8_t * data_buffer = NULL;
    int argc_skip = 0;
    const char * input_file_path = NULL;
    const char * output_file_path = NULL;
    size_t file_offset = 0;


    input_data_type_t type = INPUT_DATA_TYPE_STRING;
    uint8_t * key_buffer = NULL;
    uint32_t key_length = 0;
    int key_specified = 0;
    noxtls_aes_mode_t cipher_mode = NOXTLS_AES_ECB;  /* Default to ECB */
    uint8_t * iv_buffer = NULL;
    uint32_t iv_length = 0;
    int iv_specified = 0;

    aes_handler_func_t function_handler = NULL;

    /* Check if algorithm is specified as first argument */
    if(argc < 2) {
        printf("No algorithm specified\n");
        print_usage(argv[0]);
        return -1;
    }

    
    for(i = 0; i < sizeof(aes_handlers) / sizeof(aes_handlers[0]); i++)
    {
        if(strncasecmp(argv[1], aes_handlers[i].algo, strlen(aes_handlers[i].algo)) == 0)
        {
            function_handler = aes_handlers[i].handler;
            break;
        }
    }

    if(function_handler == NULL) {
        printf("No algorithm specified\n");
        print_usage(argv[0]);
        return -1;
    }
    else {
        argc_skip = 2;  /* Skip program name (argv[0]) and algorithm (argv[1]) */
    }

    /* Manually parse options after the algorithm argument */
    int arg_idx = 2;  /* Start after program name (0) and algorithm (1) */
    while (arg_idx < argc)
    {
        if (argv[arg_idx][0] == '-')
        {
            if (strcmp(argv[arg_idx], "-d") == 0)
            {
                debug_lvl = 1;
                printf("Debug LVL = %d\n", debug_lvl);
                argc_skip++;
                arg_idx++;
            }
            else if (strcmp(argv[arg_idx], "-h") == 0)
            {
                type = INPUT_DATA_TYPE_HEX;
                argc_skip++;
                arg_idx++;
                /* -h expects a value, but we'll use the next argument as hex data */
                break;
            }
            else if (strcmp(argv[arg_idx], "-k") == 0)
            {
                /* -k expects a hex key as the next argument */
                if (arg_idx + 1 >= argc)
                {
                    printf("Error: -k option requires a hex key\n");
                    return -1;
                }
                arg_idx++;
                argc_skip += 2;  /* Skip both -k and the key value */
                
                /* Parse hex key */
                size_t key_hex_len = strlen(argv[arg_idx]);
                int parsed_len;
                key_buffer = malloc(key_hex_len * sizeof(uint8_t));
                if(key_buffer == NULL) {
                    printf("Error: Memory allocation failed\n");
                    return -1;
                }
                memset(key_buffer, 0, key_hex_len * sizeof(uint8_t));
                parsed_len = noxtls_hex_string_to_bytes(argv[arg_idx], key_buffer, key_hex_len);
                if(parsed_len < 0) {
                    printf("Error: invalid hex key\n");
                    free(key_buffer);
                    return -1;
                }
                key_length = (uint32_t)parsed_len;
                key_specified = 1;
                
                if(debug_lvl > 0) {
                    printf("Key specified: %u bytes\n", (unsigned int)key_length);
                }
                arg_idx++;
            }
            else if (strcmp(argv[arg_idx], "-m") == 0)
            {
                /* -m expects a mode name as the next argument */
                if (arg_idx + 1 >= argc)
                {
                    printf("Error: -m option requires a mode (ecb, cbc, ctr, cfb, ofb, xts, gcm)\n");
                    return -1;
                }
                arg_idx++;
                argc_skip += 2;  /* Skip both -m and the mode value */
                
                /* Parse mode */
                if (strcasecmp(argv[arg_idx], "ecb") == 0) {
                    cipher_mode = NOXTLS_AES_ECB;
                }
                else if (strcasecmp(argv[arg_idx], "cbc") == 0) {
                    cipher_mode = NOXTLS_AES_CBC;
                }
                else if (strcasecmp(argv[arg_idx], "ctr") == 0) {
                    cipher_mode = NOXTLS_AES_CTR;
                }
                else if (strcasecmp(argv[arg_idx], "cfb") == 0) {
                    cipher_mode = NOXTLS_AES_CFB;
                }
                else if (strcasecmp(argv[arg_idx], "ofb") == 0) {
                    cipher_mode = NOXTLS_AES_OFB;
                }
                else if (strcasecmp(argv[arg_idx], "xts") == 0) {
                    cipher_mode = NOXTLS_AES_XTS;
                }
                else if (strcasecmp(argv[arg_idx], "gcm") == 0) {
                    cipher_mode = NOXTLS_AES_GCM;
                }
                else {
                    printf("Error: Unknown mode '%s'. Supported modes: ecb, cbc, ctr, cfb, ofb, xts, gcm\n", argv[arg_idx]);
                    return -1;
                }
                
                if(debug_lvl > 0) {
                    printf("Mode specified: %s\n", argv[arg_idx]);
                }
                arg_idx++;
            }
            else if (strcmp(argv[arg_idx], "-i") == 0)
            {
                /* -i expects a hex IV as the next argument */
                if (arg_idx + 1 >= argc)
                {
                    printf("Error: -i option requires a hex IV\n");
                    return -1;
                }
                arg_idx++;
                argc_skip += 2;  /* Skip both -i and the IV value */
                
                /* Parse hex IV */
                size_t iv_hex_len = strlen(argv[arg_idx]);
                int parsed_len;
                iv_buffer = malloc(iv_hex_len * sizeof(uint8_t));
                if(iv_buffer == NULL) {
                    printf("Error: Memory allocation failed\n");
                    return -1;
                }
                memset(iv_buffer, 0, iv_hex_len * sizeof(uint8_t));
                parsed_len = noxtls_hex_string_to_bytes(argv[arg_idx], iv_buffer, iv_hex_len);
                if(parsed_len < 0) {
                    printf("Error: invalid hex IV\n");
                    free(iv_buffer);
                    if(key_buffer) free(key_buffer);
                    return -1;
                }
                iv_length = (uint32_t)parsed_len;
                iv_specified = 1;
                
                if(debug_lvl > 0) {
                    printf("IV specified: %u bytes\n", (unsigned int)iv_length);
                }
                arg_idx++;
            }
            else if (strcmp(argv[arg_idx], "-f") == 0)
            {
                if (arg_idx + 1 >= argc)
                {
                    printf("Error: -f option requires an input file path\n");
                    return -1;
                }
                input_file_path = argv[arg_idx + 1];
                argc_skip += 2;
                arg_idx += 2;
            }
            else if (strcmp(argv[arg_idx], "-o") == 0)
            {
                if (arg_idx + 1 >= argc)
                {
                    printf("Error: -o option requires an output file path\n");
                    return -1;
                }
                output_file_path = argv[arg_idx + 1];
                argc_skip += 2;
                arg_idx += 2;
            }
            else if (strcmp(argv[arg_idx], "-s") == 0)
            {
                if (arg_idx + 1 >= argc)
                {
                    printf("Error: -s option requires an offset value\n");
                    return -1;
                }
                if(parse_offset_value(argv[arg_idx + 1], &file_offset) != 0) {
                    printf("Error: invalid offset '%s'\n", argv[arg_idx + 1]);
                    return -1;
                }
                argc_skip += 2;
                arg_idx += 2;
            }
            else
            {
                /* Unknown option, skip it */
                argc_skip++;
                arg_idx++;
            }
        }
        else
        {
            /* First non-option argument, this is where data starts */
            break;
        }
    }
    (void)arg_idx;

    if(input_file_path == NULL && type == INPUT_DATA_TYPE_STRING)
    {
        int j = 0;
        size_t total_str_len = 0;

        data_buffer = malloc(4096 * sizeof(uint8_t));
        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }
        memset(data_buffer, 0, 4096 * sizeof(uint8_t));

        if(debug_lvl > 0) {
            printf("argc: %d    argc_skip=%d\n",argc ,argc_skip);
        }

        for(j = argc_skip; j <= (argc - 1); j++)
        {
            size_t str_len = strlen(argv[j]); /* Space */
            if(debug_lvl > 0) {
                printf("j=%d  %s\n", j, argv[j]);
            }

            memcpy(&data_buffer[total_str_len], argv[j], str_len);
            total_str_len += str_len;
            data_buffer[total_str_len++] = ' ';
        }

        if(total_str_len > 0)
            total_str_len -= 1; /* Remove null at the end of the string */        

        if(total_str_len > UINT32_MAX) {
            printf("Error: input too long\n");
            return -1;
        }
        data_length = (uint32_t)total_str_len; /* remove null terminator */

        if(debug_lvl > 0) {
            printf("total_str_len: %zu \n", total_str_len);
        }
    }
    else if(input_file_path == NULL && type == INPUT_DATA_TYPE_HEX)
    {
        if(argc_skip >= argc) {
            printf("Error: missing hex input\n");
            return -1;
        }
        size_t hex_len = strlen(argv[argc_skip]);
        int parsed_len;
        
        if(debug_lvl > 0) {
            printf("Hex\n");
            printf("Expected hex string: %s\n",argv[argc_skip]);
            printf("Hex string length: %zu\n", strlen(argv[argc_skip]));
        }

        data_buffer = malloc(hex_len * sizeof(uint8_t));

        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }

        memset(data_buffer, 0, hex_len * sizeof(uint8_t));

        parsed_len = noxtls_hex_string_to_bytes(argv[argc_skip], data_buffer, hex_len);
        if(parsed_len < 0) {
            printf("Error: invalid hex input\n");
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            free(data_buffer);
            return -1;
        }
        data_length = (uint32_t)parsed_len;

    }    

    /* Validate key if specified */
    if(key_specified) {
        uint32_t expected_key_len = 0;
        if(strcmp(argv[1], "128") == 0) {
            expected_key_len = 16;  /* AES-128: 16 bytes */
        }
        else if(strcmp(argv[1], "192") == 0) {
            expected_key_len = 24;  /* AES-192: 24 bytes */
        }
        else if(strcmp(argv[1], "256") == 0) {
            expected_key_len = 32;  /* AES-256: 32 bytes */
        }
        
        if(key_length != expected_key_len) {
            printf("Error: Key length mismatch. Expected %u bytes for AES-%s, got %u bytes\n", 
                   expected_key_len, argv[1], key_length);
            if(key_buffer) free(key_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }
    }
    else {
        printf("Error: Key not specified. Use -k <hex_key> to provide the encryption key.\n");
        if(data_buffer) free(data_buffer);
        return -1;
    }
    
    /* Validate IV for modes that require it */
    if(cipher_mode != NOXTLS_AES_ECB) {
        if(!iv_specified) {
            printf("Error: IV/tweak required for mode. Use -i <hex_iv> to provide the IV.\n");
            if(key_buffer) free(key_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }
        if(cipher_mode == NOXTLS_AES_GCM) {
            if(iv_length != NOXTLS_AES_GCM_IV_LENGTH) {
                printf("Error: GCM nonce must be 12 bytes (24 hex characters), got %u bytes\n", (unsigned int)iv_length);
                if(key_buffer) free(key_buffer);
                if(iv_buffer) free(iv_buffer);
                if(data_buffer) free(data_buffer);
                return -1;
            }
        } else if(iv_length != NOXTLS_AES_BLOCK_LENGTH) {
            printf("Error: IV must be 16 bytes (32 hex characters), got %u bytes\n", (unsigned int)iv_length);
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }
    }

    if(input_file_path != NULL) {
        uint8_t * file_buffer = NULL;
        size_t file_length = 0;
        size_t output_length = 0;
        uint8_t * encrypted_buffer = NULL;
        uint8_t * output_buffer = NULL;
        uint8_t tag[NOXTLS_AES_GCM_TAG_LENGTH] = {0};
        int has_tag = 0;
        uint32_t encrypted_length = 0;

        if(output_file_path == NULL) {
            printf("Error: -o <file> is required when using -f <file>\n");
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }

        if(read_binary_file(input_file_path, &file_buffer, &file_length) != 0) {
            printf("Error: failed to read input file '%s'\n", input_file_path);
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }

        if(file_offset > file_length) {
            printf("Error: offset %zu is beyond end of file (%zu bytes)\n", file_offset, file_length);
            free(file_buffer);
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }

        if((file_length - file_offset) > UINT32_MAX) {
            printf("Error: input region too large\n");
            free(file_buffer);
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }

        if((file_length - file_offset) > 0) {
            if(aes_encrypt_buffer(
                   &file_buffer[file_offset],
                   (uint32_t)(file_length - file_offset),
                   key_buffer,
                   key_length,
                   cipher_mode,
                   iv_buffer,
                   &encrypted_buffer,
                   &encrypted_length,
                   tag,
                   &has_tag) != 0) {
                printf("Error: AES encryption failed\n");
                free(file_buffer);
                if(key_buffer) free(key_buffer);
                if(iv_buffer) free(iv_buffer);
                if(data_buffer) free(data_buffer);
                return -1;
            }
        }

        output_length = file_offset + encrypted_length + (has_tag ? NOXTLS_AES_GCM_TAG_LENGTH : 0U);
        output_buffer = malloc(output_length);
        if(output_buffer == NULL && output_length > 0) {
            printf("Error: Memory allocation failed\n");
            free(encrypted_buffer);
            free(file_buffer);
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }

        if(file_offset > 0) {
            memcpy(output_buffer, file_buffer, file_offset);
        }
        if(encrypted_length > 0) {
            memcpy(output_buffer + file_offset, encrypted_buffer, encrypted_length);
        }
        if(has_tag) {
            memcpy(output_buffer + file_offset + encrypted_length, tag, NOXTLS_AES_GCM_TAG_LENGTH);
        }

        if(write_binary_file(output_file_path, output_buffer, output_length) != 0) {
            printf("Error: failed to write output file '%s'\n", output_file_path);
            free(output_buffer);
            free(encrypted_buffer);
            free(file_buffer);
            if(key_buffer) free(key_buffer);
            if(iv_buffer) free(iv_buffer);
            if(data_buffer) free(data_buffer);
            return -1;
        }

        printf("Encrypted %u bytes from offset %zu into %s\n", (unsigned int)(file_length - file_offset), file_offset, output_file_path);
        if(has_tag) {
            printf("Appended GCM tag:\n");
            noxtls_print_hash(tag, NOXTLS_AES_GCM_TAG_LENGTH);
        }

        free(output_buffer);
        free(encrypted_buffer);
        free(file_buffer);
    }
    else if(function_handler != NULL) {
        function_handler(data_buffer, data_length, key_buffer, key_length, cipher_mode, iv_buffer);
    }

    /* Cleanup */
    if(key_buffer) free(key_buffer);
    if(iv_buffer) free(iv_buffer);
    if(data_buffer) free(data_buffer);

    return 0;
}


int aes_128_handler(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv)
{
    uint8_t * output = NULL;
    uint32_t output_len = 0;
    uint8_t tag[NOXTLS_AES_GCM_TAG_LENGTH] = {0};
    int has_tag = 0;

    if(debug_lvl > 0)
        printf("%s - %u bytes data, %u bytes key, mode=%d\n", __func__, (unsigned int)len, (unsigned int)key_len, mode);

    if(key_len != 16) {
        printf("Error: AES-128 requires a 16-byte (32 hex characters) key\n");
        return -1;
    }

    if(aes_encrypt_buffer(data, len, key, key_len, mode, iv, &output, &output_len, tag, &has_tag) != 0) {
        printf("Error: AES encryption failed\n");
        return -1;
    }

    printf("Encrypted data:\n");
    if(output_len > UINT16_MAX) {
        printf("Error: output too large to display\n");
    } else {
        noxtls_print_hash(output, (uint16_t)output_len);
    }
    if(has_tag) {
        printf("Tag:\n");
        noxtls_print_hash(tag, NOXTLS_AES_GCM_TAG_LENGTH);
    }

    free(output);
    return 0;
}

int aes_192_handler(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv)
{
    uint8_t * output = NULL;
    uint32_t output_len = 0;
    uint8_t tag[NOXTLS_AES_GCM_TAG_LENGTH] = {0};
    int has_tag = 0;

    if(debug_lvl > 0)
        printf("%s - %u bytes data, %u bytes key, mode=%d\n", __func__, (unsigned int)len, (unsigned int)key_len, mode);

    if(key_len != 24) {
        printf("Error: AES-192 requires a 24-byte (48 hex characters) key\n");
        return -1;
    }

    if(aes_encrypt_buffer(data, len, key, key_len, mode, iv, &output, &output_len, tag, &has_tag) != 0) {
        printf("Error: AES encryption failed\n");
        return -1;
    }

    printf("Encrypted data:\n");
    if(output_len > UINT16_MAX) {
        printf("Error: output too large to display\n");
    } else {
        noxtls_print_hash(output, (uint16_t)output_len);
    }
    if(has_tag) {
        printf("Tag:\n");
        noxtls_print_hash(tag, NOXTLS_AES_GCM_TAG_LENGTH);
    }

    free(output);
    return 0;
}

int aes_256_handler(const uint8_t * data, uint32_t len, uint8_t * key, uint32_t key_len, noxtls_aes_mode_t mode, uint8_t * iv)
{
    uint8_t * output = NULL;
    uint32_t output_len = 0;
    uint8_t tag[NOXTLS_AES_GCM_TAG_LENGTH] = {0};
    int has_tag = 0;

    if(debug_lvl > 0)
        printf("%s - %u bytes data, %u bytes key, mode=%d\n", __func__, (unsigned int)len, (unsigned int)key_len, mode);

    if(key_len != 32) {
        printf("Error: AES-256 requires a 32-byte (64 hex characters) key\n");
        return -1;
    }

    if(aes_encrypt_buffer(data, len, key, key_len, mode, iv, &output, &output_len, tag, &has_tag) != 0) {
        printf("Error: AES encryption failed\n");
        return -1;
    }

    printf("Encrypted data:\n");
    if(output_len > UINT16_MAX) {
        printf("Error: output too large to display\n");
    } else {
        noxtls_print_hash(output, (uint16_t)output_len);
    }
    if(has_tag) {
        printf("Tag:\n");
        noxtls_print_hash(tag, NOXTLS_AES_GCM_TAG_LENGTH);
    }

    free(output);
    return 0;
}
