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
* Summary: Definitions for Message Digest handling
*
*/

#ifndef _MESSAGE_DIGEST_H_
#define _MESSAGE_DIGEST_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>

typedef struct {
    char algo[32];
    int (*handler)(const uint8_t * data, uint32_t len);
    char description[256];

} message_digest_handlers_t;

typedef enum {

    INPUT_DATA_TYPE_STRING,
    INPUT_DATA_TYPE_HEX
} input_data_type_t;

int message_digest(int argc, char ** argv);

#endif /* _MESSAGE_DIGEST_H_ */
