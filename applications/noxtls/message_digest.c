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
* File:    message_digest.c
* Summary: Handles all noxtls_message digest commands
*
*/

#ifdef __cplusplus
extern "C"
{
#endif

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#ifdef _WIN32
#define strncasecmp _strnicmp
#include "noxtls-lib/common/getopt_win.h"
#else
#include <unistd.h>
#endif

#ifdef _MSC_VER
#pragma warning(disable: 4710)  /* printf/stdio not inlined - CRT, harmless */
#endif

/* Includes */
#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls-lib/common/string_common.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#include "message_digest.h"
#include "noxtls-lib/mdigest/noxtls_sha.h"
#include "noxtls-lib/mdigest/md4/noxtls_md4.h"
#include "noxtls-lib/mdigest/md5/noxtls_md5.h"
#include "noxtls-lib/mdigest/sha1/noxtls_sha1.h"
#include "noxtls-lib/mdigest/sha256/noxtls_sha256.h"
#include "noxtls-lib/mdigest/sha512/noxtls_sha512.h"
#include "noxtls-lib/mdigest/sha3/noxtls_sha3.h"
#include "noxtls-lib/mdigest/ripemd160/noxtls_ripemd160.h"
#include "noxtls-lib/mdigest/blake2/noxtls_blake2.h"

int hash_md5_handler(uint8_t * data, uint32_t len);
int hash_sha1_handler(uint8_t * data, uint32_t len);
int hash_sha_224_handler(uint8_t * data, uint32_t len);
int hash_sha_256_handler(uint8_t * data, uint32_t len);
int hash_sha_384_handler(uint8_t * data, uint32_t len);
int hash_sha_512_handler(uint8_t * data, uint32_t len);
int hash_sha_512_224_handler(uint8_t * data, uint32_t len);
int hash_sha_512_256_handler(uint8_t * data, uint32_t len);
typedef struct {
    const char *name;
    const char *display_name;
    noxtls_hash_algos_t algo;
    uint32_t digest_len;
} digest_algorithm_t;
static int parse_offset_value(const char * value, size_t * offset);
static int read_binary_file(const char * path, uint8_t ** buffer, size_t * length);
static int write_text_file(const char * path, const char * text);
static int bytes_to_hex(const uint8_t * bytes, uint32_t bytes_len, char ** hex_out);
static int find_digest_algorithm(const char * algorithm, const digest_algorithm_t ** spec);
static int compute_digest_for_algorithm(
    const char * algorithm,
    const uint8_t * data,
    uint32_t len,
    uint8_t * digest,
    uint32_t * digest_len);
static int print_digest_hex(const uint8_t * digest, uint32_t digest_len, const char * label);

void print_digest_usage(void);

uint8_t debug_lvl = 0;

message_digest_handlers_t md_handlers[] = {
    {"MD5", hash_md5_handler},
    {"SHA1", hash_sha1_handler},
    {"SHA224", hash_sha_224_handler},
    {"SHA256", hash_sha_256_handler},
    {"SHA384", hash_sha_384_handler},
    {"SHA512", hash_sha_512_handler},
};

static const digest_algorithm_t digest_algorithms[] = {
#if NOXTLS_FEATURE_MD4
    {"MD4", "md4", NOXTLS_HASH_MD4, HASH_MD4_OUT_LEN},
#endif
#if NOXTLS_FEATURE_MD5
    {"MD5", "md5", NOXTLS_HASH_MD5, HASH_MD5_OUT_LEN},
#endif
#if NOXTLS_FEATURE_SHA1
    {"SHA1", "sha1", NOXTLS_HASH_SHA1, HASH_SHA1_OUT_LEN},
    {"SHA-1", NULL, NOXTLS_HASH_SHA1, HASH_SHA1_OUT_LEN},
#endif
#if NOXTLS_FEATURE_SHA224
    {"SHA224", "sha224", NOXTLS_HASH_SHA_224, 28u},
    {"SHA-224", NULL, NOXTLS_HASH_SHA_224, 28u},
#endif
#if NOXTLS_FEATURE_SHA256
    {"SHA256", "sha256", NOXTLS_HASH_SHA_256, HASH_SHA256_OUT_LEN},
    {"SHA-256", NULL, NOXTLS_HASH_SHA_256, HASH_SHA256_OUT_LEN},
#endif
#if NOXTLS_FEATURE_SHA384
    {"SHA384", "sha384", NOXTLS_HASH_SHA_384, 48u},
    {"SHA-384", NULL, NOXTLS_HASH_SHA_384, 48u},
#endif
#if NOXTLS_FEATURE_SHA512
    {"SHA512", "sha512", NOXTLS_HASH_SHA_512, HASH_SHA512_OUT_LEN},
    {"SHA-512", NULL, NOXTLS_HASH_SHA_512, HASH_SHA512_OUT_LEN},
    {"SHA512-224", "sha512-224", NOXTLS_HASH_SHA_512_224, HASH_SHA512_224_OUT_LEN},
    {"SHA512_224", NULL, NOXTLS_HASH_SHA_512_224, HASH_SHA512_224_OUT_LEN},
    {"SHA-512/224", NULL, NOXTLS_HASH_SHA_512_224, HASH_SHA512_224_OUT_LEN},
    {"SHA512-256", "sha512-256", NOXTLS_HASH_SHA_512_256, HASH_SHA512_256_OUT_LEN},
    {"SHA512_256", NULL, NOXTLS_HASH_SHA_512_256, HASH_SHA512_256_OUT_LEN},
    {"SHA-512/256", NULL, NOXTLS_HASH_SHA_512_256, HASH_SHA512_256_OUT_LEN},
#endif
#if NOXTLS_FEATURE_SHA3
    {"SHA3", "sha3", NOXTLS_HASH_SHA3_256, HASH_SHA3_256_OUT_LEN},
    {"SHA3-224", "sha3-224", NOXTLS_HASH_SHA3_224, HASH_SHA3_224_OUT_LEN},
    {"SHA3_224", NULL, NOXTLS_HASH_SHA3_224, HASH_SHA3_224_OUT_LEN},
    {"SHA3-256", "sha3-256", NOXTLS_HASH_SHA3_256, HASH_SHA3_256_OUT_LEN},
    {"SHA3_256", NULL, NOXTLS_HASH_SHA3_256, HASH_SHA3_256_OUT_LEN},
    {"SHA3-384", "sha3-384", NOXTLS_HASH_SHA3_384, HASH_SHA3_384_OUT_LEN},
    {"SHA3_384", NULL, NOXTLS_HASH_SHA3_384, HASH_SHA3_384_OUT_LEN},
    {"SHA3-512", "sha3-512", NOXTLS_HASH_SHA3_512, HASH_SHA3_512_OUT_LEN},
    {"SHA3_512", NULL, NOXTLS_HASH_SHA3_512, HASH_SHA3_512_OUT_LEN},
#endif
#if NOXTLS_FEATURE_RIPEMD160
    {"RIPEMD160", "ripemd160", NOXTLS_HASH_RIPEMD160, HASH_RIPEMD160_OUT_LEN},
    {"RIPEMD-160", NULL, NOXTLS_HASH_RIPEMD160, HASH_RIPEMD160_OUT_LEN},
#endif
#if NOXTLS_FEATURE_BLAKE2
    {"BLAKE2S-256", "blake2s-256", NOXTLS_HASH_BLAKE2S_256, HASH_BLAKE2S_256_OUT_LEN},
    {"BLAKE2S_256", NULL, NOXTLS_HASH_BLAKE2S_256, HASH_BLAKE2S_256_OUT_LEN},
    {"BLAKE2B-512", "blake2b-512", NOXTLS_HASH_BLAKE2B_512, HASH_BLAKE2B_512_OUT_LEN},
    {"BLAKE2B_512", NULL, NOXTLS_HASH_BLAKE2B_512, HASH_BLAKE2B_512_OUT_LEN},
#endif
};


void print_digest_usage(void)
{
    printf("usage: sha <algorithm> [options] [text...]\n");
    printf("       sha <algorithm> -f <file> [options]\n");
    printf("       noxtls dgst <algorithm> [options] [text...]\n\n");
    printf("Options:\n");
    printf("  -f <file>       Read input from file\n");
    printf("  -o <file>       Write hex digest to file\n");
    printf("  -s <offset>     Start hashing file input at byte offset\n");
    printf("  -h              Treat text input as hexadecimal bytes\n");
    printf("  -d              Enable hash debug output\n");
    printf("  --help          Show this help\n\n");
    printf("Supported algorithms:\n");

    size_t i = 0;
    size_t displayed = 0;
    for(i = 0; i < sizeof(digest_algorithms) / sizeof(digest_algorithms[0]); i++)
    {
        if(digest_algorithms[i].display_name == NULL) {
            continue;
        }
        printf("  %-14s%s",
               digest_algorithms[i].display_name,
               ((displayed + 1u) % 3u == 0u) ? "\n" : "");
        displayed++;
    }
    if(displayed % 3u != 0u) {
        printf("\n");
    }

    printf("\nExamples:\n");
    printf("  noxtls dgst sha256 hello world\n");
    printf("  noxtls dgst sha3-256 -f firmware.bin\n");
    printf("  noxtls dgst blake2b-512 -f firmware.bin -o firmware.blake2\n");
    printf("  noxtls dgst sha256 -h 68656c6c6f\n");
    printf("  sha sha256 hello world\n");
    printf("  sha sha256 -f firmware.bin\n");
    printf("  sha sha512 -f firmware.bin -o firmware.sha512\n");
    printf("  sha sha3 hello world\n\n");
}

int message_digest(int argc, char ** argv)
{
    uint32_t data_length = 0;
    uint8_t * data_buffer = NULL;
    int arg_idx = 1;
    int data_start_idx = -1;
    const char * input_file_path = NULL;
    const char * output_file_path = NULL;
    size_t file_offset = 0;
    uint8_t digest[HASH_SHA512_OUT_LEN] = {0};
    uint32_t digest_len = 0;
    char * digest_hex = NULL;

    input_data_type_t type = INPUT_DATA_TYPE_STRING;

    const digest_algorithm_t *algorithm_spec = NULL;

    if(argc <= 0 || argv == NULL || argv[0] == NULL ||
       strcmp(argv[0], "-h") == 0 ||
       strcmp(argv[0], "--help") == 0 ||
       strcmp(argv[0], "help") == 0) {
        print_digest_usage();
        return 0;
    }

    if(find_digest_algorithm(argv[0], &algorithm_spec) != 0 || algorithm_spec == NULL) {
        printf("Error: unknown or missing digest algorithm '%s'\n\n", argv[0]);
        print_digest_usage();
        return -1;
    }

    while(arg_idx < argc) {
        if(argv[arg_idx][0] != '-') {
            data_start_idx = arg_idx;
            break;
        }

        if(strcmp(argv[arg_idx], "-d") == 0) {
            debug_lvl = 1;
            printf("Debug LVL = %d\n", debug_lvl);
            arg_idx++;
        }
        else if(strcmp(argv[arg_idx], "-h") == 0) {
            type = INPUT_DATA_TYPE_HEX;
            arg_idx++;
        }
        else if(strcmp(argv[arg_idx], "-f") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -f option requires an input file path\n");
                return -1;
            }
            input_file_path = argv[arg_idx + 1];
            arg_idx += 2;
        }
        else if(strcmp(argv[arg_idx], "-o") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -o option requires an output file path\n");
                return -1;
            }
            output_file_path = argv[arg_idx + 1];
            arg_idx += 2;
        }
        else if(strcmp(argv[arg_idx], "-s") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -s option requires an offset value\n");
                return -1;
            }
            if(parse_offset_value(argv[arg_idx + 1], &file_offset) != 0) {
                printf("Error: invalid offset '%s'\n", argv[arg_idx + 1]);
                return -1;
            }
            arg_idx += 2;
        }
        else {
            printf("Error: unknown option '%s'\n", argv[arg_idx]);
            return -1;
        }
    }

    if(input_file_path != NULL) {
        uint8_t * file_buffer = NULL;
        size_t file_length = 0;
        const uint8_t * hash_input = NULL;

        if(read_binary_file(input_file_path, &file_buffer, &file_length) != 0) {
            printf("Error: failed to read input file '%s'\n", input_file_path);
            return -1;
        }

        if(file_offset > file_length) {
            printf("Error: offset %zu is beyond end of file (%zu bytes)\n", file_offset, file_length);
            free(file_buffer);
            return -1;
        }

        if((file_length - file_offset) > UINT32_MAX) {
            printf("Error: input region too large\n");
            free(file_buffer);
            return -1;
        }

        if((file_length - file_offset) > 0) {
            hash_input = &file_buffer[file_offset];
        } else {
            hash_input = (const uint8_t *)"";
        }

        if(compute_digest_for_algorithm(argv[0], hash_input, (uint32_t)(file_length - file_offset), digest, &digest_len) != 0) {
            printf("Error: failed to compute digest for %s\n", argv[0]);
            free(file_buffer);
            return -1;
        }

        if(output_file_path != NULL) {
            if(bytes_to_hex(digest, digest_len, &digest_hex) != 0) {
                printf("Error: failed to format digest output\n");
                free(file_buffer);
                return -1;
            }

            if(write_text_file(output_file_path, digest_hex) != 0) {
                printf("Error: failed to write output file '%s'\n", output_file_path);
                free(digest_hex);
                free(file_buffer);
                return -1;
            }

            printf("Digest written to %s from offset %zu\n", output_file_path, file_offset);
            free(digest_hex);
            digest_hex = NULL;
        } else {
            print_digest_hex(digest, digest_len, input_file_path);
        }

        free(file_buffer);
        return 0;
    }

    if(data_start_idx < 0 || data_start_idx >= argc) {
        printf("Error: missing input data\n");
        return -1;
    }

    if(type == INPUT_DATA_TYPE_STRING)
    {
        int j = 0;
        size_t total_str_len = 0;

        for(j = data_start_idx; j <= (argc - 1); j++) {
            total_str_len += strlen(argv[j]);
            if(j < argc - 1) {
                total_str_len++;
            }
        }
        if(total_str_len > UINT32_MAX) {
            printf("Error: input too long\n");
            return -1;
        }

        data_buffer = malloc(total_str_len == 0u ? 1u : total_str_len);
        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }

        total_str_len = 0;

        for(j = data_start_idx; j <= (argc - 1); j++)
        {
            size_t str_len = strlen(argv[j]);

            memcpy(&data_buffer[total_str_len], argv[j], str_len);
            total_str_len += str_len;
            if(j < argc - 1) {
                data_buffer[total_str_len++] = ' ';
            }
        }

        data_length = (uint32_t)total_str_len;
    }
    else
    {
        size_t hex_len = strlen(argv[data_start_idx]);
        int parsed_len;

        data_buffer = malloc(hex_len * sizeof(uint8_t));

        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }

        memset(data_buffer, 0, hex_len * sizeof(uint8_t));

        parsed_len = noxtls_hex_string_to_bytes(argv[data_start_idx], data_buffer, hex_len);
        if(parsed_len < 0) {
            free(data_buffer);
            printf("Error: invalid hex input\n");
            return -1;
        }
        data_length = (uint32_t)parsed_len;
    }

    if(data_buffer != NULL) {
        if(compute_digest_for_algorithm(argv[0], data_buffer, data_length, digest, &digest_len) != 0) {
            free(data_buffer);
            printf("Error: failed to compute digest for %s\n", argv[0]);
            return -1;
        }
        print_digest_hex(digest, digest_len, NULL);
    }

    free(data_buffer);
    return 0;
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

static int write_text_file(const char * path, const char * text)
{
    FILE * file = NULL;

    if(path == NULL || text == NULL) {
        return -1;
    }

    file = fopen(path, "wb");
    if(file == NULL) {
        return -1;
    }

    if(fputs(text, file) == EOF || fputc('\n', file) == EOF) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

static int bytes_to_hex(const uint8_t * bytes, uint32_t bytes_len, char ** hex_out)
{
    static const char hex_chars[] = "0123456789abcdef";
    size_t i = 0;
    char * output = NULL;

    if(bytes == NULL || hex_out == NULL) {
        return -1;
    }

    output = malloc((bytes_len * 2U) + 1U);
    if(output == NULL) {
        return -1;
    }

    for(i = 0; i < bytes_len; i++) {
        output[(i * 2U)] = hex_chars[(bytes[i] >> 4) & 0x0F];
        output[(i * 2U) + 1U] = hex_chars[bytes[i] & 0x0F];
    }
    output[bytes_len * 2U] = '\0';

    *hex_out = output;
    return 0;
}

static int find_digest_algorithm(const char * algorithm, const digest_algorithm_t ** spec)
{
    size_t i;

    if(algorithm == NULL || spec == NULL) {
        return -1;
    }

    for(i = 0; i < sizeof(digest_algorithms) / sizeof(digest_algorithms[0]); i++) {
        if(strncasecmp(algorithm, digest_algorithms[i].name, strlen(digest_algorithms[i].name)) == 0 &&
           strlen(algorithm) == strlen(digest_algorithms[i].name)) {
            *spec = &digest_algorithms[i];
            return 0;
        }
    }

    return -1;
}

static int compute_digest_for_algorithm(
    const char * algorithm,
    const uint8_t * data,
    uint32_t len,
    uint8_t * digest,
    uint32_t * digest_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    const digest_algorithm_t *spec = NULL;

    if(algorithm == NULL || data == NULL || digest == NULL || digest_len == NULL) {
        return -1;
    }

    if(find_digest_algorithm(algorithm, &spec) != 0 || spec == NULL) {
        return -1;
    }

    {
        noxtls_sha_ctx_t ctx;

#if NOXTLS_FEATURE_MD4
        noxtls_md4_set_debug(debug_lvl);
#endif
#if NOXTLS_FEATURE_MD5
        noxtls_md5_set_debug(debug_lvl);
#endif
#if NOXTLS_FEATURE_SHA1
        noxtls_sha1_set_debug(debug_lvl);
#endif
#if NOXTLS_FEATURE_SHA224 || NOXTLS_FEATURE_SHA256
        noxtls_sha256_set_debug(debug_lvl);
#endif
#if NOXTLS_FEATURE_SHA384 || NOXTLS_FEATURE_SHA512
        noxtls_sha512_set_debug(debug_lvl);
#endif
#if NOXTLS_FEATURE_SHA3
        noxtls_sha3_set_debug(debug_lvl);
#endif

        rc = noxtls_sha_init(&ctx, spec->algo);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha_update(&ctx, (uint8_t *)data, len);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha_finish(&ctx, digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        *digest_len = spec->digest_len;
        return 0;
    }
}

static int print_digest_hex(const uint8_t * digest, uint32_t digest_len, const char * label)
{
    char * digest_hex = NULL;

    if(bytes_to_hex(digest, digest_len, &digest_hex) != 0) {
        return -1;
    }

    if(label != NULL) {
        printf("%s  %s\n", digest_hex, label);
    } else {
        printf("%s\n", digest_hex);
    }

    free(digest_hex);
    return 0;
}

int hash_md5_handler(uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);

    uint8_t hash[16] = {0};
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc;

    noxtls_md5_set_debug(debug_lvl);
    rc = noxtls_md5_init(&ctx);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_md5_update(&ctx, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_md5_finish(&ctx, hash);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;

    noxtls_print_hash(hash, HASH_MD5_OUT_LEN);
    return 0;
}

int hash_sha1_handler(uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);

    uint8_t hash[32] = {0};
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc;

    noxtls_sha1_set_debug(debug_lvl);
    rc = noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_sha1_update(&ctx, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_sha1_finish(&ctx, hash);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;

    noxtls_print_hash(hash, HASH_SHA1_OUT_LEN);
    return 0;
}

int hash_sha_224_handler(uint8_t * data, uint32_t len)
{
    (void)data;
    (void)len;
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}

int hash_sha_256_handler(uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);

    uint8_t hash[32] = {0};
    noxtls_sha_ctx_t ctx;
    noxtls_return_t rc;

    noxtls_sha256_set_debug(debug_lvl);
    rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_sha256_update(&ctx, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_sha256_finish(&ctx, hash);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;

    noxtls_print_hash(hash, HASH_SHA256_OUT_LEN);
    return 0;
}

int hash_sha_384_handler(uint8_t * data, uint32_t len)
{
    (void)data;
    (void)len;
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}

int hash_sha_512_handler(uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);

    uint8_t hash[HASH_SHA512_OUT_LEN] = {0};
    noxtls_sha512_ctx_t ctx;
    noxtls_return_t rc;

    noxtls_sha512_set_debug(debug_lvl);
    rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_sha512_update(&ctx, data, len);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    rc = noxtls_sha512_finish(&ctx, hash);
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;

    noxtls_print_hash(hash, HASH_SHA512_OUT_LEN);
    return 0;
}

int hash_sha_512_224_handler(uint8_t * data, uint32_t len)
{
    (void)data;
    (void)len;
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}

int hash_sha_512_256_handler(uint8_t * data, uint32_t len)
{
    (void)data;
    (void)len;
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}




#ifdef __cplusplus
}
#endif
