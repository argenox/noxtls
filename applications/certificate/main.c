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
* File:    main.c
* Summary: Certificate handling application
*
*/

/**
 * @file main.c
 * @brief Certificate handling utility (GCC/MinGW; may be excluded with MSVC).
 * @defgroup noxtls_app_certificate Certificate application
 * @details
 * Demo application that loads a sample certificate from disk and displays
 * or processes it. Options: -v version, -h help. Primarily for testing
 * certificate loading; see cert utility for full CLI operations.
 * @example
 * certificate
 * certificate -h
 * certificate -v
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include "noxtls-lib/common/getopt_win.h"
#else
#include <unistd.h>
#endif

#include "noxtls-lib/common/noxtls_memory.h"
#include "noxtls-lib/common/noxtls_memory_compat.h"
#include "utility/utility.h"
#include "noxtls-lib/certs/asn1.h"
#include "utility/base64.h"
#include "noxtls-lib/certs/certificates.h"

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4


typedef struct {
    char cmd[32];
    int (*handler)(int argc, char ** argv);
    char description[256];

} command_list_t;


command_list_t commands[]  = {
    /* {"dgst", &message_digest, "Generates the noxtls_message digest"} */
};
#define NUM_COMMANDS 0

void print_usage(const char * name)
{
    printf( "usage: %s [command] <parameters>\n", name);
    printf("\nSupported Commands\n\n");

    int i;
    for(i = 0; i < NUM_COMMANDS; i++)
    {
        printf("%s  \t\t\t%s\n", commands[i].cmd, commands[i].description);
    }

    printf("\nCommandline Switches\n\n");

    printf("-v \t\t\tVersion Information\n");
    printf("-h \t\t\tHelp\n");    

    printf("\n\n");
}

void print_version(void)
{
    printf("NOXTLS v%u.%u.%u\n", (unsigned int)APP_VERSION_MAJOR, (unsigned int)APP_VERSION_MINOR, (unsigned int)APP_VERSION_BUILD);
    printf("Build %s %s\n", __DATE__, __TIME__);
    printf("Copyright Argenox Technologies LLC. All Rights Reserved.\n");
}

int main(int argc, char ** argv)
{
    uint8_t * buffer = NULL;

    (void)argc;
    (void)argv;

    int res = noxtls_load_file("../../data/2048b-rsa-example-cert.der", &buffer);

    printf("Result: %d\n", res);

    if(res > 0) 
        noxtls_parse_der(buffer, res);

    printf("res: \n");

    uint32_t output_len = res * 4;
    output_len /= 3;

    if(output_len < 4)
        output_len = 4;
    
    uint8_t * cert_output = NULL;
    cert_output = (uint8_t *) malloc(sizeof(uint8_t) * output_len * 2);
    if(cert_output == NULL) {
        return -1;
    }
    memset(cert_output, 0, sizeof(uint8_t) * output_len * 2);
    uint32_t pem_cert_length = 0;

    /*int pem_cert_length = noxtls_base64_encode(buffer, res, (char *)cert_output);
    if(pem_cert_length != output_len) {
        printf("Output Length Error: %d != %d\n", pem_cert_length, output_len);
    }*/


    noxtls_certificate_der_to_pem(buffer, res, cert_output, &pem_cert_length);

    noxtls_write_text_file("2048b-rsa-example-cert.pem", cert_output, pem_cert_length);
    free(buffer);

    printf("Loading PEM\n");
    res = noxtls_load_text_file("2048b-rsa-example-cert.pem", &buffer);
    uint32_t der_cert_length = 0;
    memset(cert_output, 0, sizeof(uint8_t) * output_len * 2);

    printf("Result: %d\n", res);
    noxtls_certificate_pem_to_der(buffer, res, cert_output, &der_cert_length);

    printf("DER LEngth: %u\n", (unsigned int)der_cert_length);
    noxtls_write_file("2048b-rsa-example-cert.der", cert_output, der_cert_length);
    free(buffer);



    return 0;    
}