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
#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

#include "noxtls-lib/common/getopt_compat.h"
#ifdef _MSC_VER
#pragma warning(disable: 4710)  /* printf/stdio not inlined - CRT, harmless */
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

int hash_md5_handler(uint8_t * data, uint32_t len);
int hash_sha1_handler(uint8_t * data, uint32_t len);
int hash_sha_224_handler(uint8_t * data, uint32_t len);
int hash_sha_256_handler(uint8_t * data, uint32_t len);
int hash_sha_384_handler(uint8_t * data, uint32_t len);
int hash_sha_512_handler(uint8_t * data, uint32_t len);
int hash_sha_512_224_handler(uint8_t * data, uint32_t len);
int hash_sha_512_256_handler(uint8_t * data, uint32_t len);

void print_digest_usage(void);

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


void print_digest_usage(void)
{
    printf("\nSupported Digests\n\n");

    size_t i = 0;
    for(i = 0; i < sizeof(md_handlers) / sizeof(md_handlers[0]); i++)
    {
        printf("%s  \t\t\t\n", md_handlers[i].algo);
    }

    printf("\n\n");
}

int message_digest(int argc, char ** argv)
{
    int c;
   // uint32_t length = 0;
    uint32_t data_length = 0;
    uint8_t * data_buffer = NULL;
    int argc_skip = 0;


    input_data_type_t type = INPUT_DATA_TYPE_STRING;

    int (* function_handler)(uint8_t * data, uint32_t len) = NULL;

    size_t i = 0;
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
    else {
        argc_skip++;
    }

    while ((c = noxtls_getopt (argc, argv, "dh:")) != -1)
    {
        switch (c)
        {
          case 'h':

            type = INPUT_DATA_TYPE_HEX;
            argc_skip++;
            break;
          case 'd':
            
                debug_lvl = 1;
                printf("Debug LVL = %d\n", debug_lvl);
                argc_skip++;
                break;
          default:

            if(debug_lvl > 0)
                printf("Default\n");

            #if 0
            memcpy(data_buffer, argv[argc-1], length);
            data_length = length;
            processed = 1;
            #endif
            break;
        }
    }


    if(type == INPUT_DATA_TYPE_STRING)
    {
        int j = 0;
        int total_str_len = 0;

        data_buffer = malloc(4096 * sizeof(uint8_t));
        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }
        memset(data_buffer, 0, 4096 * sizeof(uint8_t));

        printf("argc: %d    argc_skip=%d\n",argc ,argc_skip);

        for(j = argc_skip; j <= (argc - 1); j++)
        {
            int str_len = (int)strlen(argv[j]); /* Space */
            printf("j=%d  %s\n", j, argv[j]);

            memcpy(&data_buffer[total_str_len], argv[j], (size_t)str_len);
            total_str_len += str_len;
            data_buffer[total_str_len++] = ' ';
        }

        if(total_str_len > 0)
        total_str_len -= 1; /* Remove null at the end of the string */        

        data_length = total_str_len; /* remove null terminator */

        printf("total_str_len: %d \n",total_str_len);
    }
    else if(type == INPUT_DATA_TYPE_HEX)
    {
        size_t hex_len = strlen(argv[argc_skip]);
        int parsed_len;

        printf("Hex\n");
        printf("Expected hex string: %s\n", argv[argc_skip]);
        printf("Hex string length: %zu\n", hex_len);

        data_buffer = malloc(hex_len * sizeof(uint8_t));

        if(data_buffer == NULL) {
            printf("Error");
            return -1;
        }

        memset(data_buffer, 0, hex_len * sizeof(uint8_t));

        parsed_len = noxtls_hex_string_to_bytes(argv[argc_skip], data_buffer, hex_len);
        if(parsed_len < 0) {
            free(data_buffer);
            printf("Error: invalid hex input\n");
            return -1;
        }
        data_length = (uint32_t)parsed_len;

    }

    if(function_handler != NULL && data_buffer != NULL) {
        function_handler(data_buffer, data_length);
    }

    return 0;
}

int hash_md5_handler(uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);

    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[16] = {0};
    noxtls_sha_ctx_t ctx;
    
    do
    {
        noxtls_md5_set_debug(debug_lvl);
        rc = noxtls_md5_init(&ctx);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_md5_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_md5_finish(&ctx, hash);
    } while(0);
    
    if(rc != NOXTLS_RETURN_SUCCESS)
        return -1;
    noxtls_print_hash(hash, HASH_MD5_OUT_LEN);

    return 0;
}

int hash_sha1_handler(uint8_t * data, uint32_t len)
{
    if(debug_lvl > 0)
        printf("%s - %u bytes\n", __func__, (unsigned int)len);

    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[32] = {0};
    noxtls_sha_ctx_t ctx;
    
    do
    {
        noxtls_sha1_set_debug(debug_lvl);
        rc = noxtls_sha1_init(&ctx, NOXTLS_HASH_SHA1);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_sha1_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_sha1_finish(&ctx, hash);
    } while(0);
    
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

    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[32] = {0};
    noxtls_sha_ctx_t ctx;
    
    do
    {
        noxtls_sha256_set_debug(debug_lvl);
        rc = noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_sha256_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_sha256_finish(&ctx, hash);
    } while(0);
    
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

    noxtls_return_t rc = NOXTLS_RETURN_FAILED;
    
    uint8_t hash[HASH_SHA512_OUT_LEN] = {0};
    noxtls_sha512_ctx_t ctx;
    
    do
    {
        noxtls_sha512_set_debug(debug_lvl);
        rc = noxtls_sha512_init(&ctx, NOXTLS_HASH_SHA_512);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_sha512_update(&ctx, data, len);
        if(rc != NOXTLS_RETURN_SUCCESS)
            break;
        rc = noxtls_sha512_finish(&ctx, hash);
    } while(0);
    
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
