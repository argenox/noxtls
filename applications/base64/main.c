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
* Summary: Base64 Utility
*
*/

/**
 * @file main.c
 * @brief Base64 encode/decode command-line utility.
 * @defgroup noxtls_app_base64 Base64 utility
 * @details
 * Encode strings or hex to Base64, or decode Base64 to hex.
 * Parameters: one switch (-s, -x, -d, -D) then input as needed.
 * Options:
 *   -s    Encode string to Base64
 *   -x    Encode hex to Base64
 *   -d    Decode Base64 to hex (lowercase)
 *   -D    Decode Base64 to hex (uppercase)
 *   -v    Version
 *   -h    Help
 * @example
 * Encode a string:
 *   base64 -s "Hello World"
 * Encode hex to Base64:
 *   base64 -x 48656c6c6f
 * Decode Base64:
 *   base64 -d SGVsbG8=
 *   base64 -h
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include "noxtls-lib/common/getopt_win.h"
#else
#include <unistd.h>
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "utility.h"
#include "asn1.h"
#include "base64.h"
#include "string_common.h"

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4


void print_array_hex(const uint8_t * data, uint32_t len);
void print_array_char(const uint8_t * data, uint32_t len);

typedef enum
{
    BASE64_ENCODE_STRING,
    BASE64_ENCODE_BINARY_HEX,
    BASE64_DECODE,
    BASE64_TEST
} base64_op_t;



void print_usage(const char * name)
{
    printf( "usage: %s [switch] <parameters>\n", name);
    
    printf("\nCommandline Switches\n\n");

    printf("-s \tEncode String to Base64\n");
    printf("-x \tEncode Hex to Base64\n");
    printf("-dD \tDecode Base64 to hex\n");
    printf("-v \tVersion Information\n");
    printf("-h \tHelp\n");    

    printf("\n\n");
}

void print_version(void)
{
    printf("Base64 v%u.%u.%u\n", (unsigned int)APP_VERSION_MAJOR, (unsigned int)APP_VERSION_MINOR, (unsigned int)APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright Argenox Technologies LLC. All Rights Reserved.\n");
}


void run_tests(void)
{

}

int main(int argc, char ** argv)
{
    int c;
    uint8_t * input_data = NULL;
    uint8_t * output = NULL;
    uint8_t * conv_data = NULL;

    base64_op_t op = BASE64_TEST;
    int length = 0;
    int op_set = 0;
    uint32_t input_len = 0;
    uint32_t output_len = 0;
    uint32_t conv_length = 0;


    /* check for command line arguments */
    if (argc < 2)
    {
        print_usage(argv[0]);
        return -1;
    }

    while ((c = getopt (argc, argv, "vhs:x:d:D:t")) != -1)
    {
        switch (c)
        {
            case 's': /* Input to encode is a string */
            
                op = BASE64_ENCODE_STRING;
                op_set = 1;
                {
                    size_t input_len_sz = strlen(optarg);
                    if(input_len_sz > UINT32_MAX) {
                        return -1;
                    }
                    input_len = (uint32_t)input_len_sz;
                }
                input_data = (uint8_t *) malloc(sizeof(uint8_t) * input_len);
                if(input_data == NULL) {
                    return -1;
                }

                memcpy(input_data, optarg, input_len);
                break;

            case 'x': /* Input to encode is hex */
                op = BASE64_ENCODE_BINARY_HEX;
                op_set = 1;
                {
                    size_t input_len_sz = strlen(optarg);
                    if(input_len_sz > UINT32_MAX) {
                        return -1;
                    }
                    input_len = (uint32_t)input_len_sz;
                }
                input_data = (uint8_t *) malloc(sizeof(uint8_t) * input_len);
                if(input_data == NULL) {
                    return -1;
                }

                memcpy(input_data, optarg, input_len);
                break;

            case 'D':
            case 'd': /* Input to decode is string */
                op = BASE64_DECODE;
                op_set = 1;
                {
                    size_t input_len_sz = strlen(optarg);
                    if(input_len_sz > UINT32_MAX) {
                        return -1;
                    }
                    input_len = (uint32_t)input_len_sz;
                }
                input_data = (uint8_t *) malloc(sizeof(uint8_t) * input_len);
                if(input_data == NULL) {
                    return -1;
                }

                memcpy(input_data, optarg, input_len);
                break;

            case 'v':
                print_version();
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 't':
                op = BASE64_TEST;
                op_set = 1;
                break;

        }
    }

    if(!op_set && op != BASE64_ENCODE_STRING && op != BASE64_ENCODE_BINARY_HEX && op != BASE64_DECODE) {
        print_usage(argv[0]);
        return -1;
    }

    switch(op)
    {
        case BASE64_ENCODE_STRING:
            output_len = input_len * 4;
            output_len /= 3;

            if(output_len < 4)
                output_len = 4;
            
            output = (uint8_t *) malloc(sizeof(uint8_t) * output_len);
            if(output == NULL) {
                return -1;
            }
            length = noxtls_base64_encode(input_data, input_len, (char *)output);
            if(length < 0 || (uint32_t)length != output_len) {
                printf("Output Length Error: %d != %u\n", length, output_len);
            }
            print_array_char(output, length);


            break;
        case BASE64_ENCODE_BINARY_HEX:

            conv_length = input_len / 2;
            if(conv_length > UINT16_MAX) {
                return -1;
            }

            conv_data = (uint8_t *) malloc(sizeof(uint8_t) * conv_length);
            if(conv_data == NULL) {
                return -1;
            }
            memset(conv_data, 0, sizeof(uint8_t) * conv_length);

            noxtls_hex_string_to_bytes((char *)input_data, conv_data, (uint16_t)conv_length);

            print_array_hex(conv_data, conv_length);

            output_len = conv_length * 4;
            output_len /= 3;

            if(output_len < 4)
                output_len = 4;
            
            output = (uint8_t *) malloc(sizeof(uint8_t) * output_len);
            if(output == NULL) {
                return -1;
            }
            length = noxtls_base64_encode(conv_data, conv_length, (char *)output);
            if(length < 0 || (uint32_t)length != output_len) {
                printf("Output Length Error: %d != %u\n", length, output_len);
            }
            print_array_char(output, length);


            break;
        case BASE64_DECODE:

            output_len = input_len * 3;
            output_len /= 4;

            if(output_len < 3)
                output_len = 3;
            
            output = (uint8_t *) malloc(sizeof(uint8_t) * output_len);
            if(output == NULL) {
                return -1;
            }

            length = noxtls_base64_decode((char *)input_data, input_len, (uint8_t *)output);
            if(length < 0 || (uint32_t)length != output_len) {
                printf("Output Length Error: %d != %u\n", length, output_len);
            }
            print_array_char(output, length);

            break;
        case BASE64_TEST:
            run_tests();
            break;
    }


    if(input_data != NULL) {
        free(input_data);
    }

    if(output != NULL) {
        free(output);
    }

    if(conv_data != NULL) {
        free(conv_data);
    }

    return 0;    
}

void print_array_hex(const uint8_t * data, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++)
    {
        printf("%x", data[i]);
    }

    printf("\n");
}

void print_array_char(const uint8_t * data, uint32_t len)
{
    uint32_t i;
    for(i = 0; i < len; i++)
    {
        printf("%c", data[i]);
    }

    printf("\n");
}