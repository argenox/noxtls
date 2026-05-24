/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
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

/* Includes */
#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls-lib/common/string_common.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#include "message_digest.h"
#include "noxtls-lib/mdigest/md5/noxtls_md5.h"
#include "noxtls-lib/mdigest/sha1/noxtls_sha1.h"
#include "noxtls-lib/mdigest/sha256/noxtls_sha256.h"
    #include "noxtls-lib/mdigest/sha512/noxtls_sha512.h"

int hash_md5_handler(const uint8_t * data, uint32_t len);
int hash_sha1_handler(const uint8_t * data, uint32_t len);
int hash_sha_224_handler(const uint8_t * data, uint32_t len);
int hash_sha_256_handler(const uint8_t * data, uint32_t len);
int hash_sha_384_handler(const uint8_t * data, uint32_t len);
int hash_sha_512_handler(const uint8_t * data, uint32_t len);
int hash_sha_512_224_handler(const uint8_t * data, uint32_t len);
int hash_sha_512_256_handler(const uint8_t * data, uint32_t len);
static int parse_offset_value(const char * value, size_t * offset);
static int read_binary_file(const char * path, uint8_t ** buffer, size_t * length);
static int write_text_file(const char * path, const char * text);
static int bytes_to_hex(const uint8_t * bytes, uint32_t bytes_len, char ** hex_out);
static int compute_digest_for_algorithm(
    const char * algorithm,
    const uint8_t * data,
    uint32_t len,
    uint8_t * digest,
    uint32_t * digest_len);


uint8_t debug_lvl = 0;

message_digest_handlers_t md_handlers[] = {
    {"MD5", hash_md5_handler},
    {"SHA1", hash_sha1_handler},
    {"SHA224", hash_sha_224_handler},
    {"SHA256", hash_sha_256_handler},
    {"SHA384", hash_sha_384_handler},
    {"SHA512", hash_sha_512_handler},
    {"SHA512_224", hash_sha_512_224_handler},
    {"SHA512_256", hash_sha_512_256_handler},
};

/**
 * @brief Print the digest usage
 * 
 * @return void
 */
void print_digest_usage()
{    
    printf("\nSupported Digests\n\n");

    int i = 0;
    for(i = 0; i < sizeof(md_handlers) / sizeof(md_handlers[0]); i++)
    {
        printf("%s  \t\t\t\n", md_handlers[i].algo);
    }

    printf("\n\n");
}

/**
 * @brief Perform the message digest
 * 
 * @param[in] argc The argument count
 * @param[in] argv The argument vector
 * @return The return value
 */
int message_digest(int argc, char ** argv)
{
    uint32_t data_length = 0;
    uint8_t * data_buffer = NULL;
    int arg_idx = 1;
    int data_start_idx = -1;
    const char * input_file_path = NULL;
    const char * output_file_path = NULL;
    size_t file_offset = 0;

    input_data_type_t type = INPUT_DATA_TYPE_STRING;

    int (* function_handler)(const uint8_t * data, uint32_t len) = NULL;

    int i = 0;
    for(i = 0; i < sizeof(md_handlers) / sizeof(md_handlers[0]); i++)
    {
        if(strncasecmp(argv[0], md_handlers[i].algo, strlen(md_handlers[i].algo)) == 0)
        {
            function_handler = md_handlers[i].handler;
            break;
        }
    }

    if(function_handler == NULL) {
        printf("No algorithm specified\n");
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
        uint8_t digest[HASH_SHA512_OUT_LEN] = {0};
        uint32_t digest_len = 0;

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
            char * digest_hex = NULL;
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
        } else {
            noxtls_print_hash(digest, (uint16_t)digest_len);
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

        data_buffer = malloc(4096 * sizeof(uint8_t));
        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }
        memset(data_buffer, 0, 4096 * sizeof(uint8_t));

        for(j = data_start_idx; j <= (argc - 1); j++)
        {
            size_t str_len = strlen(argv[j]); /* Space */

            memcpy(&data_buffer[total_str_len], argv[j], str_len);
            total_str_len += str_len;
            data_buffer[total_str_len++] = ' ';
        }

        if(total_str_len > 0) {
            total_str_len -= 1;
        }

        if(total_str_len > UINT32_MAX) {
            free(data_buffer);
            printf("Error: input too long\n");
            return -1;
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

    if(function_handler != NULL) {
        function_handler(data_buffer, data_length);
    }

    free(data_buffer);
    return 0;
}

/**
 * @brief Parse the offset value
 * 
 * @param[in] value The value to parse the offset value from
 * @param[out] offset The offset to parse the offset value into
 * @return The return value
 */
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

/**
 * @brief Read the binary file
 * 
 * @param[in] path The path to read the binary file from
 * @param[out] buffer The buffer to read the binary file into
 * @param[out] length The length of the buffer to read the binary file into
 * @return The return value
 */
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

/**
 * @brief Write the text file
 * 
 * @param[in] path The path to write the text file to
 * @param[in] text The text to write to the text file
 * @return The return value
 */
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

/**
 * @brief Convert bytes to hex
 * 
 * @param[in] bytes The bytes to convert to hex
 * @param[in] bytes_len The length of the bytes to convert to hex
 * @param[out] hex_out The hex output
 * @return The return value
 */
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

/**
 * @brief Compute the digest for the algorithm
 * 
 * @param[in] algorithm The algorithm to compute the digest for
 * @param[in] data The data to compute the digest for
 * @param[in] len The length of the data to compute the digest for
 * @param[out] digest The digest output
 * @param[out] digest_len The length of the digest output
 * @return The return value
 */
static int compute_digest_for_algorithm(
    const char * algorithm,
    const uint8_t * data,
    uint32_t len,
    uint8_t * digest,
    uint32_t * digest_len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if(algorithm == NULL || data == NULL || digest == NULL || digest_len == NULL) {
        return -1;
    }

    if(strncasecmp(algorithm, "MD5", 3) == 0) {
        noxtls_sha_ctx_t ctx;
        noxtls_md5_set_debug(debug_lvl);
        rc = noxtls_md5_init(&ctx);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_md5_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_md5_finish(&ctx, digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        *digest_len = HASH_MD5_OUT_LEN;
        return 0;
    }

    if(strncasecmp(algorithm, "SHA1", 4) == 0) {
        noxtls_sha_ctx_t ctx;
        noxtls_sha1_set_debug(debug_lvl);
        rc = noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha1_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha1_finish(&ctx, digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        *digest_len = HASH_SHA1_OUT_LEN;
        return 0;
    }

    if(strncasecmp(algorithm, "SHA256", 6) == 0) {
        noxtls_sha_ctx_t ctx;
        noxtls_sha256_set_debug(debug_lvl);
        rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha256_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha256_finish(&ctx, digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        *digest_len = HASH_SHA256_OUT_LEN;
        return 0;
    }

    if(strncasecmp(algorithm, "SHA512", 6) == 0) {
        noxtls_sha512_ctx_t ctx;
        noxtls_sha512_set_debug(debug_lvl);
        rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha512_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        rc = noxtls_sha512_finish(&ctx, digest);
        if(rc != NOXTLS_RETURN_SUCCESS) return -1;
        *digest_len = HASH_SHA512_OUT_LEN;
        return 0;
    }

    return -1;
}

/**
 * @brief Compute the MD5 hash
 * 
 * @param[in] data The data to compute the MD5 hash for
 * @param[in] len The length of the data to compute the MD5 hash for
 * @return The return value
 */
int hash_md5_handler(const uint8_t * data, uint32_t len)
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

/**
 * @brief Compute the SHA1 hash
 * 
 * @param[in] data The data to compute the SHA1 hash for
 * @param[in] len The length of the data to compute the SHA1 hash for
 * @return The return value
 */
int hash_sha1_handler(const uint8_t * data, uint32_t len)
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

/**
 * @brief Compute the SHA224 hash
 * 
 * @param[in] data The data to compute the SHA224 hash for
 * @param[in] len The length of the data to compute the SHA224 hash for
 * @return The return value
 */
int hash_sha_224_handler(const uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}

/**
 * @brief Compute the SHA256 hash
 * 
 * @param[in] data The data to compute the SHA256 hash for
 * @param[in] len The length of the data to compute the SHA256 hash for
 * @return The return value
 */
int hash_sha_256_handler(const uint8_t * data, uint32_t len)
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

/**
 * @brief Compute the SHA384 hash
 * 
 * @param[in] data The data to compute the SHA384 hash for
 * @param[in] len The length of the data to compute the SHA384 hash for
 * @return The return value
 */
int hash_sha_384_handler(const uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}

/**
 * @brief Compute the SHA512 hash
 * 
 * @param[in] data The data to compute the SHA512 hash for
 * @param[in] len The length of the data to compute the SHA512 hash for
 * @return The return value
 */
int hash_sha_512_handler(const uint8_t * data, uint32_t len)
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

/**
 * @brief Compute the SHA512_224 hash
 * 
 * @param[in] data The data to compute the SHA512_224 hash for
 * @param[in] len The length of the data to compute the SHA512_224 hash for
 * @return The return value
 */
int hash_sha_512_224_handler(const uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}

/**
 * @brief Compute the SHA512_256 hash
 * 
 * @param[in] data The data to compute the SHA512_256 hash for
 * @param[in] len The length of the data to compute the SHA512_256 hash for
 * @return The return value
 */
int hash_sha_512_256_handler(const uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);
    return 0;
}




#ifdef __cplusplus
}
#endif
