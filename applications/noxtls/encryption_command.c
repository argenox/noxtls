/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    encryption_command.c
* Summary: Handles noxtls enc/dec commands
*
*/

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

#include "encryption_command.h"
#include "noxtls_common.h"
#include "noxtls-lib/common/string_common.h"
#include "noxtls-lib/encryption/aes/noxtls_aes.h"

typedef struct {
    const char *name;
    noxtls_aes_type_t type;
    uint32_t key_len;
} cipher_algorithm_t;

typedef struct {
    const char *name;
    noxtls_aes_mode_t mode;
    int needs_iv;
} cipher_mode_t;

static const cipher_algorithm_t cipher_algorithms[] = {
#if NOXTLS_FEATURE_AES_128
    {"128", NOXTLS_AES_128_BIT, 16U},
#endif
#if NOXTLS_FEATURE_AES_192
    {"192", NOXTLS_AES_192_BIT, 24U},
#endif
#if NOXTLS_FEATURE_AES_256
    {"256", NOXTLS_AES_256_BIT, 32U},
#endif
};

static const cipher_mode_t cipher_modes[] = {
#if NOXTLS_FEATURE_AES_ECB
    {"ecb", NOXTLS_AES_ECB, 0},
#endif
#if NOXTLS_FEATURE_AES_CBC
    {"cbc", NOXTLS_AES_CBC, 1},
#endif
#if NOXTLS_FEATURE_AES_CTR
    {"ctr", NOXTLS_AES_CTR, 1},
#endif
#if NOXTLS_FEATURE_AES_CFB
    {"cfb", NOXTLS_AES_CFB, 1},
#endif
#if NOXTLS_FEATURE_AES_OFB
    {"ofb", NOXTLS_AES_OFB, 1},
#endif
};

static int run_cipher_command(noxtls_aes_operation_t operation, int argc, char ** argv);
static int find_cipher_algorithm(const char * name, const cipher_algorithm_t ** spec);
static int find_cipher_mode(const char * name, const cipher_mode_t ** spec);
static int parse_offset_value(const char * value, size_t * offset);
static int read_binary_file(const char * path, uint8_t ** buffer, size_t * length);
static int write_binary_file(const char * path, const uint8_t * buffer, size_t length);
static int parse_hex_alloc(const char * hex, uint8_t ** out, uint32_t * out_len);
static int bytes_to_hex(const uint8_t * bytes, uint32_t bytes_len, char ** hex_out);
static int print_hex_output(const uint8_t * bytes, uint32_t bytes_len);
static int join_text_args(int start_idx, int argc, char ** argv, uint8_t ** out, uint32_t * out_len);
static int run_aes(
    noxtls_aes_operation_t operation,
    const cipher_algorithm_t * algorithm,
    const cipher_mode_t * mode,
    const uint8_t * key,
    const uint8_t * iv,
    const uint8_t * input,
    uint32_t input_len,
    uint8_t ** output,
    uint32_t * output_len);

/**
 * @brief Print the encryption usage
 * 
 * @param command The command
 */
void print_encryption_usage(const char * command)
{
    size_t i;
    size_t displayed;

    if(command == NULL) {
        command = "enc";
    }

    printf("usage: noxtls %s <algorithm> [options] [text...]\n", command);
    printf("       noxtls %s <algorithm> -f <file> -o <file> [options]\n\n", command);
    printf("Options:\n");
    printf("  -k <hex_key>    AES key in hexadecimal form\n");
    printf("  -m <mode>       Cipher mode: ecb, cbc, ctr, cfb, ofb (default: ecb)\n");
    printf("  -i <hex_iv>     IV for cbc, ctr, cfb, and ofb modes\n");
    printf("  -f <file>       Read input from file\n");
    printf("  -o <file>       Write binary output to file\n");
    printf("  -s <offset>     Start processing file input at byte offset\n");
    printf("  -h              Treat text input as hexadecimal bytes\n");
    printf("  --help          Show this help\n\n");
    printf("Supported algorithms:\n");

    displayed = 0;
    for(i = 0; i < sizeof(cipher_algorithms) / sizeof(cipher_algorithms[0]); i++) {
        printf("  %-14s%s",
               cipher_algorithms[i].name,
               ((displayed + 1U) % 3U == 0U) ? "\n" : "");
        displayed++;
    }
    if(displayed % 3U != 0U) {
        printf("\n");
    }

    printf("\nSupported modes:\n");
    displayed = 0;
    for(i = 0; i < sizeof(cipher_modes) / sizeof(cipher_modes[0]); i++) {
        printf("  %-14s%s",
               cipher_modes[i].name,
               ((displayed + 1U) % 3U == 0U) ? "\n" : "");
        displayed++;
    }
    if(displayed % 3U != 0U) {
        printf("\n");
    }

    printf("\nExamples:\n");
    printf("  noxtls enc 128 -k 2b7e151628aed2a6abf7158809cf4f3c hello\n");
    printf("  noxtls enc 128 -m cbc -i 000102030405060708090a0b0c0d0e0f -k 2b7e151628aed2a6abf7158809cf4f3c -h 6bc1bee22e409f96e93d7e117393172a\n");
    printf("  noxtls dec 128 -k 2b7e151628aed2a6abf7158809cf4f3c -h <ciphertext_hex>\n\n");
}

/**
 * @brief Run the encryption command
 * 
 * @param argc The argument count
 * @param argv The argument vector
 * @return The return value
 */
int encryption_encrypt_command(int argc, char ** argv)
{
    return run_cipher_command(NOXTLS_AES_OP_ENCRYPT, argc, argv);
}

/**
 * @brief Run the decryption command
 * 
 * @param argc The argument count
 * @param argv The argument vector
 * @return The return value
 */
int encryption_decrypt_command(int argc, char ** argv)
{
    return run_cipher_command(NOXTLS_AES_OP_DECRYPT, argc, argv);
}

/**
 * @brief Run the cipher command
 * 
 * @param operation The operation
 * @param argc The argument count
 * @param argv The argument vector
 * @return The return value
 */
static int run_cipher_command(noxtls_aes_operation_t operation, int argc, char ** argv)
{
    const char * command = (operation == NOXTLS_AES_OP_ENCRYPT) ? "enc" : "dec";
    const cipher_algorithm_t * algorithm = NULL;
    const cipher_mode_t * mode = NULL;
    const char * input_file_path = NULL;
    const char * output_file_path = NULL;
    size_t file_offset = 0;
    uint8_t * key = NULL;
    uint32_t key_len = 0;
    uint8_t * iv = NULL;
    uint32_t iv_len = 0;
    uint8_t * input = NULL;
    uint32_t input_len = 0;
    uint8_t * output = NULL;
    uint32_t output_len = 0;
    int input_is_hex = 0;
    int data_start_idx = -1;
    int arg_idx = 1;
    int rc = -1;

    if(argc <= 0 || argv == NULL || argv[0] == NULL ||
       strcmp(argv[0], "-h") == 0 ||
       strcmp(argv[0], "--help") == 0 ||
       strcmp(argv[0], "help") == 0) {
        print_encryption_usage(command);
        return 0;
    }

    if(find_cipher_algorithm(argv[0], &algorithm) != 0 || algorithm == NULL) {
        printf("Error: unknown or missing encryption algorithm '%s'\n\n", argv[0]);
        print_encryption_usage(command);
        return -1;
    }

    if(find_cipher_mode("ecb", &mode) != 0 || mode == NULL) {
        printf("Error: ECB mode is not available in this build\n");
        return -1;
    }

    while(arg_idx < argc) {
        if(argv[arg_idx][0] != '-') {
            data_start_idx = arg_idx;
            break;
        }

        if(strcmp(argv[arg_idx], "-h") == 0) {
            input_is_hex = 1;
            arg_idx++;
        } else if(strcmp(argv[arg_idx], "--help") == 0) {
            print_encryption_usage(command);
            return 0;
        } else if(strcmp(argv[arg_idx], "-k") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -k option requires a hex key\n");
                goto cleanup;
            }
            if(parse_hex_alloc(argv[arg_idx + 1], &key, &key_len) != 0) {
                printf("Error: invalid hex key\n");
                goto cleanup;
            }
            arg_idx += 2;
        } else if(strcmp(argv[arg_idx], "-i") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -i option requires a hex IV\n");
                goto cleanup;
            }
            if(parse_hex_alloc(argv[arg_idx + 1], &iv, &iv_len) != 0) {
                printf("Error: invalid hex IV\n");
                goto cleanup;
            }
            arg_idx += 2;
        } else if(strcmp(argv[arg_idx], "-m") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -m option requires a mode\n");
                goto cleanup;
            }
            if(find_cipher_mode(argv[arg_idx + 1], &mode) != 0 || mode == NULL) {
                printf("Error: unknown cipher mode '%s'\n\n", argv[arg_idx + 1]);
                print_encryption_usage(command);
                goto cleanup;
            }
            arg_idx += 2;
        } else if(strcmp(argv[arg_idx], "-f") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -f option requires an input file path\n");
                goto cleanup;
            }
            input_file_path = argv[arg_idx + 1];
            arg_idx += 2;
        } else if(strcmp(argv[arg_idx], "-o") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -o option requires an output file path\n");
                goto cleanup;
            }
            output_file_path = argv[arg_idx + 1];
            arg_idx += 2;
        } else if(strcmp(argv[arg_idx], "-s") == 0) {
            if(arg_idx + 1 >= argc) {
                printf("Error: -s option requires an offset value\n");
                goto cleanup;
            }
            if(parse_offset_value(argv[arg_idx + 1], &file_offset) != 0) {
                printf("Error: invalid offset '%s'\n", argv[arg_idx + 1]);
                goto cleanup;
            }
            arg_idx += 2;
        } else {
            printf("Error: unknown option '%s'\n\n", argv[arg_idx]);
            print_encryption_usage(command);
            goto cleanup;
        }
    }

    if(key == NULL) {
        printf("Error: key not specified. Use -k <hex_key>.\n");
        goto cleanup;
    }
    if(key_len != algorithm->key_len) {
        printf("Error: key length mismatch. Expected %u bytes for AES-%s, got %u bytes\n",
               (unsigned)algorithm->key_len, algorithm->name, (unsigned)key_len);
        goto cleanup;
    }
    if(mode->needs_iv) {
        if(iv == NULL) {
            printf("Error: IV required for %s mode. Use -i <hex_iv>.\n", mode->name);
            goto cleanup;
        }
        if(iv_len != NOXTLS_AES_BLOCK_LENGTH) {
            printf("Error: IV must be 16 bytes (32 hex characters), got %u bytes\n", (unsigned)iv_len);
            goto cleanup;
        }
    }

    if(input_file_path != NULL) {
        uint8_t * file_buffer = NULL;
        size_t file_length = 0;

        if(output_file_path == NULL) {
            printf("Error: -o <file> is required when using -f <file>\n");
            goto cleanup;
        }
        if(read_binary_file(input_file_path, &file_buffer, &file_length) != 0) {
            printf("Error: failed to read input file '%s'\n", input_file_path);
            goto cleanup;
        }
        if(file_offset > file_length) {
            printf("Error: offset %zu is beyond end of file (%zu bytes)\n", file_offset, file_length);
            free(file_buffer);
            goto cleanup;
        }
        if((file_length - file_offset) > UINT32_MAX) {
            printf("Error: input region too large\n");
            free(file_buffer);
            goto cleanup;
        }
        input_len = (uint32_t)(file_length - file_offset);
        input = malloc(input_len == 0U ? 1U : input_len);
        if(input == NULL) {
            free(file_buffer);
            goto cleanup;
        }
        if(input_len > 0) {
            memcpy(input, file_buffer + file_offset, input_len);
        }
        free(file_buffer);
    } else if(input_is_hex) {
        if(data_start_idx < 0) {
            printf("Error: missing hex input\n");
            goto cleanup;
        }
        if(parse_hex_alloc(argv[data_start_idx], &input, &input_len) != 0) {
            printf("Error: invalid hex input\n");
            goto cleanup;
        }
    } else {
        if(join_text_args(data_start_idx, argc, argv, &input, &input_len) != 0) {
            printf("Error: failed to prepare input data\n");
            goto cleanup;
        }
    }

    if(run_aes(operation, algorithm, mode, key, iv, input, input_len, &output, &output_len) != 0) {
        printf("Error: AES %s failed\n", operation == NOXTLS_AES_OP_ENCRYPT ? "encryption" : "decryption");
        goto cleanup;
    }

    if(output_file_path != NULL) {
        if(write_binary_file(output_file_path, output, output_len) != 0) {
            printf("Error: failed to write output file '%s'\n", output_file_path);
            goto cleanup;
        }
        printf("%s %u bytes into %s\n",
               operation == NOXTLS_AES_OP_ENCRYPT ? "Encrypted" : "Decrypted",
               (unsigned)input_len,
               output_file_path);
    } else {
        if(print_hex_output(output, output_len) != 0) {
            printf("Error: failed to format output\n");
            goto cleanup;
        }
    }

    rc = 0;

cleanup:
    free(key);
    free(iv);
    free(input);
    free(output);
    return rc;
}

/**
 * @brief Find the cipher algorithm
 * 
 * @param name The name
 * @param spec The specification
 * @return The return value
 */
static int find_cipher_algorithm(const char * name, const cipher_algorithm_t ** spec)
{
    size_t i;

    if(name == NULL || spec == NULL) {
        return -1;
    }
    for(i = 0; i < sizeof(cipher_algorithms) / sizeof(cipher_algorithms[0]); i++) {
        if(strcmp(name, cipher_algorithms[i].name) == 0) {
            *spec = &cipher_algorithms[i];
            return 0;
        }
    }
    return -1;
}

/**
 * @brief Find the cipher mode
 * 
 * @param name The name
 * @param spec The specification
 * @return The return value
 */
static int find_cipher_mode(const char * name, const cipher_mode_t ** spec)
{
    size_t i;

    if(name == NULL || spec == NULL) {
        return -1;
    }
    for(i = 0; i < sizeof(cipher_modes) / sizeof(cipher_modes[0]); i++) {
        if(strcasecmp(name, cipher_modes[i].name) == 0) {
            *spec = &cipher_modes[i];
            return 0;
        }
    }
    return -1;
}

/**
 * @brief Parse the offset value
 * 
 * @param value The value
 * @param offset The offset
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
 * @brief Read a binary file
 * 
 * @param path The path
 * @param buffer The buffer
 * @param length The length
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

    file_buffer = malloc((size_t)file_size == 0U ? 1U : (size_t)file_size);
    if(file_buffer == NULL) {
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
 * @brief Write a binary file
 * 
 * @param path The path
 * @param buffer The buffer
 * @param length The length
 * @return The return value
 */
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

/**
 * @brief Parse a hex string and allocate memory
 * 
 * @param hex The hex string
 * @param out The output
 * @param out_len The output length
 * @return The return value
 */
static int parse_hex_alloc(const char * hex, uint8_t ** out, uint32_t * out_len)
{
    size_t hex_len;
    uint8_t * buffer = NULL;
    int parsed_len;

    if(hex == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    hex_len = strlen(hex);
    if(hex_len / 2U > UINT32_MAX) {
        return -1;
    }
    buffer = malloc(hex_len == 0U ? 1U : hex_len);
    if(buffer == NULL) {
        return -1;
    }
    memset(buffer, 0, hex_len == 0U ? 1U : hex_len);

    parsed_len = noxtls_hex_string_to_bytes(hex, buffer, hex_len);
    if(parsed_len < 0) {
        free(buffer);
        return -1;
    }

    *out = buffer;
    *out_len = (uint32_t)parsed_len;
    return 0;
}

/**
 * @brief Convert bytes to a hex string
 * 
 * @param bytes The bytes
 * @param bytes_len The length of the bytes
 * @param hex_out The hex output
 * @return The return value
 */
static int bytes_to_hex(const uint8_t * bytes, uint32_t bytes_len, char ** hex_out)
{
    static const char hex_chars[] = "0123456789abcdef";
    char * output = NULL;
    uint32_t i;

    if(bytes == NULL || hex_out == NULL) {
        return -1;
    }
    if(bytes_len > (UINT32_MAX - 1U) / 2U) {
        return -1;
    }

    output = malloc((size_t)bytes_len * 2U + 1U);
    if(output == NULL) {
        return -1;
    }

    for(i = 0; i < bytes_len; i++) {
        output[(size_t)i * 2U] = hex_chars[(bytes[i] >> 4) & 0x0Fu];
        output[(size_t)i * 2U + 1U] = hex_chars[bytes[i] & 0x0Fu];
    }
    output[(size_t)bytes_len * 2U] = '\0';

    *hex_out = output;
    return 0;
}

/**
 * @brief Print the hex output
 * 
 * @param bytes The bytes
 * @param bytes_len The length of the bytes
 * @return The return value
 */
static int print_hex_output(const uint8_t * bytes, uint32_t bytes_len)
{
    char * hex = NULL;

    if(bytes_to_hex(bytes, bytes_len, &hex) != 0) {
        return -1;
    }
    printf("%s\n", hex);
    free(hex);
    return 0;
}

/**
 * @brief Join the text arguments
 * 
 * @param start_idx The start index
 * @param argc The argument count
 * @param argv The argument vector
 * @param out The output
 * @param out_len The output length
 * @return The return value
 */
static int join_text_args(int start_idx, int argc, char ** argv, uint8_t ** out, uint32_t * out_len)
{
    size_t total_len = 0;
    uint8_t * buffer = NULL;
    int i;

    if(out == NULL || out_len == NULL) {
        return -1;
    }
    if(start_idx < 0) {
        start_idx = argc;
    }

    for(i = start_idx; i < argc; i++) {
        total_len += strlen(argv[i]);
        if(i < argc - 1) {
            total_len++;
        }
    }
    if(total_len > UINT32_MAX) {
        return -1;
    }

    buffer = malloc(total_len == 0U ? 1U : total_len);
    if(buffer == NULL) {
        return -1;
    }

    total_len = 0;
    for(i = start_idx; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        memcpy(buffer + total_len, argv[i], arg_len);
        total_len += arg_len;
        if(i < argc - 1) {
            buffer[total_len++] = ' ';
        }
    }

    *out = buffer;
    *out_len = (uint32_t)total_len;
    return 0;
}

/**
 * @brief Run the AES
 * 
 * @param operation The operation
 * @param algorithm The algorithm
 * @param mode The mode
 * @param key The key
 * @param iv The IV
 * @param input The input
 * @param input_len The length of the input
 * @param output The output
 * @param output_len The length of the output
 * @return The return value
 */
static int run_aes(
    noxtls_aes_operation_t operation,
    const cipher_algorithm_t * algorithm,
    const cipher_mode_t * mode,
    const uint8_t * key,
    const uint8_t * iv,
    const uint8_t * input,
    uint32_t input_len,
    uint8_t ** output,
    uint32_t * output_len)
{
    noxtls_aes_context_t ctx;
    uint8_t * result = NULL;
    uint32_t update_len = 0;
    uint32_t final_len = 0;
    noxtls_return_t rc;

    if(algorithm == NULL || mode == NULL || key == NULL || input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }
    if(input_len > UINT32_MAX - NOXTLS_AES_BLOCK_LENGTH) {
        return -1;
    }

    result = malloc((size_t)input_len + NOXTLS_AES_BLOCK_LENGTH);
    if(result == NULL) {
        return -1;
    }

    rc = noxtls_aes_init(&ctx, key, iv, algorithm->type, mode->mode, operation);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(result);
        return -1;
    }
    rc = noxtls_aes_update(&ctx, input, input_len, result, &update_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(result);
        return -1;
    }
    rc = noxtls_aes_final(&ctx, result + update_len, &final_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        free(result);
        return -1;
    }

    *output = result;
    *output_len = update_len + final_len;
    return 0;
}
