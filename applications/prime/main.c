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
* Summary: Prime Utility
*
*/

/**
 * @file main.c
 * @brief Prime number utility using NoxTLS.
 * @defgroup noxtls_app_prime Prime utility
 * @details
 * Command-line switches: -s encode string to Base64, -x encode hex to Base64,
 * -d/-D decode Base64 to hex, -v version, -h help. Parameters depend on switch.
 * @example
 * prime -h
 * prime -v
 * prime -s "input string"
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "noxtls-lib/common/getopt_compat.h"
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
    uint8_t * input_data = NULL;
    uint8_t * output = NULL;
    uint8_t * conv_data = NULL;

    base64_op_t op = BASE64_TEST;
    int op_set = 0;
    int exit_after_help = 0;
    int length = 0;
    size_t input_len = 0;
    size_t output_len = 0;
    size_t conv_length = 0;
    int exit_code = 0;


    /* check for command line arguments */
    if (argc < 2)
    {
        print_usage(argv[0]);
        return -1;
    }

    do {
        int c;
        while ((c = noxtls_getopt (argc, argv, "vhs:x:d:D:t")) != -1)
        {
            switch (c)
            {
            case 's': /* Input to encode is a string */
            {
                size_t opt_len = strlen(optarg);
                if(opt_len > UINT32_MAX) {
                    exit_code = -1;
                    break;
                }
                op = BASE64_ENCODE_STRING;
                op_set = 1;
                input_len = opt_len;
                input_data = (uint8_t *) malloc(sizeof(uint8_t) * input_len);
                if(input_data == NULL) {
                    exit_code = -1;
                    break;
                }

                memcpy(input_data, optarg, input_len);
                break;
            }

            case 'x': /* Input to encode is hex */
            {
                size_t opt_len = strlen(optarg);
                if(opt_len > UINT32_MAX) {
                    exit_code = -1;
                    break;
                }
                op = BASE64_ENCODE_BINARY_HEX;
                op_set = 1;
                input_len = opt_len;
                input_data = (uint8_t *) malloc(sizeof(uint8_t) * input_len);
                if(input_data == NULL) {
                    exit_code = -1;
                    break;
                }

                memcpy(input_data, optarg, input_len);
                break;
            }

            case 'D':
            case 'd': /* Input to decode is string */
            {
                size_t opt_len = strlen(optarg);
                if(opt_len > UINT32_MAX) {
                    exit_code = -1;
                    break;
                }
                op = BASE64_DECODE;
                op_set = 1;
                input_len = opt_len;
                input_data = (uint8_t *) malloc(sizeof(uint8_t) * input_len);
                if(input_data == NULL) {
                    exit_code = -1;
                    break;
                }

                memcpy(input_data, optarg, input_len);
                break;
            }

            case 'v':
                print_version();
                exit_after_help = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit_after_help = 1;
                break;
            case 't':
                op = BASE64_TEST;
                op_set = 1;
                break;

            }
            if(exit_code != 0) {
                break;
            }
        }

        if(exit_code != 0) {
            break;
        }

        if(exit_after_help) {
            break;
        }

        if(!op_set) {
            print_usage(argv[0]);
            exit_code = -1;
            break;
        }

        switch(op)
        {
        case BASE64_ENCODE_STRING:
            if(input_len > (SIZE_MAX / 4)) {
                exit_code = -1;
                break;
            }
            output_len = (input_len * 4) / 3;

            if(output_len < 4)
                output_len = 4;
            
            output = (uint8_t *) malloc(sizeof(uint8_t) * output_len);
            if(output == NULL) {
                exit_code = -1;
                break;
            }
            if(output_len > UINT32_MAX) {
                exit_code = -1;
                break;
            }
            length = noxtls_base64_encode(input_data, (uint32_t)input_len, (char *)output);
            if(length < 0 || (size_t)length != output_len) {
                printf("Output Length Error: %d != %u\n", length, (unsigned)output_len);
            }
            if(length > 0) {
                print_array_char(output, (uint32_t)length);
            }


            break;
        case BASE64_ENCODE_BINARY_HEX:

            if((input_len % 2u) != 0u) {
                exit_code = -1;
                break;
            }
            conv_length = input_len / 2;

            conv_data = (uint8_t *) malloc(sizeof(uint8_t) * conv_length);
            if(conv_data == NULL) {
                exit_code = -1;
                break;
            }
            memset(conv_data, 0, sizeof(uint8_t) * conv_length);

            length = noxtls_hex_string_to_bytes((char *)input_data, conv_data, conv_length);
            if(length < 0 || (size_t)length != conv_length) {
                exit_code = -1;
                break;
            }

            if(conv_length > UINT32_MAX) {
                exit_code = -1;
                break;
            }
            print_array_hex(conv_data, (uint32_t)conv_length);

            if(conv_length > (SIZE_MAX / 4)) {
                exit_code = -1;
                break;
            }
            output_len = (conv_length * 4) / 3;

            if(output_len < 4)
                output_len = 4;
            
            output = (uint8_t *) malloc(sizeof(uint8_t) * output_len);
            if(output == NULL) {
                exit_code = -1;
                break;
            }
            if(output_len > UINT32_MAX) {
                exit_code = -1;
                break;
            }
            length = noxtls_base64_encode(conv_data, (uint32_t)conv_length, (char *)output);
            if(length < 0 || (size_t)length != output_len) {
                printf("Output Length Error: %d != %u\n", length, (unsigned)output_len);
            }
            if(length > 0) {
                print_array_char(output, (uint32_t)length);
            }


            break;
        case BASE64_DECODE:

            if(input_len > (SIZE_MAX / 3)) {
                exit_code = -1;
                break;
            }
            output_len = (input_len * 3) / 4;

            if(output_len < 3)
                output_len = 3;
            
            output = (uint8_t *) malloc(sizeof(uint8_t) * output_len);
            if(output == NULL) {
                exit_code = -1;
                break;
            }

            if(output_len > UINT32_MAX) {
                exit_code = -1;
                break;
            }
            length = noxtls_base64_decode((char *)input_data, (uint32_t)input_len, (uint8_t *)output);
            if(length < 0 || (size_t)length != output_len) {
                printf("Output Length Error: %d != %u\n", length, (unsigned)output_len);
            }
            if(length > 0) {
                print_array_char(output, (uint32_t)length);
            }

            break;
        case BASE64_TEST:
            run_tests();
            break;
        }
    } while(0);

    if(input_data != NULL) {
        free(input_data);
    }

    if(output != NULL) {
        free(output);
    }

    if(conv_data != NULL) {
        free(conv_data);
    }

    return exit_code;    
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