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
* File:    aes_handler.c
* Summary: Handles all AES commands
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
/* Includes */
#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "noxtls_common.h"
#include "string_common.h"
#include "noxtls-lib/mdigest/noxtls_hash.h"
#include "noxtls-lib/mdigest/md5/noxtls_md5.h"
#include "message_digest.h"


int aes_128_handler(uint8_t * data, uint32_t len);
int aes_256_handler(uint8_t * data, uint32_t len);
int aes_192_handler(uint8_t * data, uint32_t len);


uint8_t debug_lvl = 0;

message_digest_handlers_t aes_handlers[] = {
    {"128", aes_128_handler},
    {"192", aes_192_handler},
    {"256", aes_256_handler}
};

/**
 * @brief Print the usage information
 *
 * @return void
 */
void print_digest_usage()
{    
    printf("\nSupported Digests\n\n");

    int i = 0;
    for(i = 0; i < sizeof(aes_handlers) / sizeof(aes_handlers[0]); i++)
    {
        printf("%s  \t\t\t\n", aes_handlers[i].algo);
    }

    printf("\n\n");
}

/**
 * @brief Handle the AES commands
 *
 * @param[in] argc The number of arguments
 * @param[in] argv The arguments
 * @return 0 on success, -1 on failure
 */
int aes_handler(int argc, char ** argv)
{
    int c;   
    uint32_t data_length = 0;
    uint8_t * data_buffer;
    int argc_skip = 0;


    input_data_type_t type = INPUT_DATA_TYPE_STRING;

    int (* function_handler)(uint8_t * data, uint32_t len) = NULL;

    int i = 0;
    for(i = 0; i < sizeof(aes_handlers) / sizeof(aes_handlers[0]); i++)
    {
        if(strncasecmp(argv[0], aes_handlers[i].algo, strlen(aes_handlers[i].algo)) == 0)
        {
            function_handler = aes_handlers[i].handler;
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

            memcpy(&data_buffer[total_str_len], argv[j], str_len);
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
        printf("Expected hex string: %s\n",argv[argc_skip]);
        printf("Hex string length: %zu\n", strlen(argv[argc_skip]));

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

    if(function_handler != NULL) {
        function_handler(data_buffer, data_length);
    }

    return 0;
}

/**
 * @brief Handle the AES-128 commands
 *
 * @param[in] data The data to handle
 * @param[in] len The length of the data
 * @return 0 on success, -1 on failure
 */
int aes_128_handler(uint8_t * data, uint32_t len)
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
 * @brief Handle the AES-192 commands
 *
 * @param[in] data The data to handle
 * @param[in] len The length of the data
 * @return 0 on success, -1 on failure
 */
int aes_192_handler(uint8_t * data, uint32_t len)
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
 * @brief Handle the AES-256 commands
 *
 * @param[in] data The data to handle
 * @param[in] len The length of the data
 * @return 0 on success, -1 on failure
 */
int aes_256_handler(uint8_t * data, uint32_t len)
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




#ifdef __cplusplus
}
#endif
