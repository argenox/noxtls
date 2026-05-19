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
* Summary: NOXTLS Utility Main Application
*
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "noxtls-lib/common/getopt_compat.h"
#include "message_digest.h"

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 1
#define APP_VERSION_BUILD 4


typedef struct {
    char cmd[32];
    int (*handler)(int argc, char ** argv);
    char description[256];

} command_list_t;


command_list_t commands[]  = {
    {"dgst", &message_digest, "Generates the noxtls_message digest"}
};



void print_usage(const char * name)
{
    printf( "usage: %s [command] <parameters>\n", name);
    printf("\nSupported Commands\n\n");

    int i = 0;
    for(i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
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
    int command_found = 0;

    /* check for command line arguments */
    if (argc < 2)
    {
        print_usage(argv[0]);
        return -1;
    }

    /* Find top level command */
    int i = 0;
    for(i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
    {
        if(strncmp(argv[1], commands[i].cmd, strlen(commands[i].cmd)) == 0)
        {
            commands[i].handler(argc - 2, &argv[2]);
            command_found = 1;
            break;
        }
    }

    if(command_found == 0)
    {
        int c;
        while ((c = noxtls_getopt (argc, argv, "vh")) != -1)
        {
            switch (c)
            {
                case 'v':
                    print_version();
                    break;
                case 'h':
                    print_usage(argv[0]);
                    break;

            }
        }
    }

    return 0;    
}