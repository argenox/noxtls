/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
* This file is part of the NoxTLS Library.
*
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from
* Argenox Technologies LLC.
*
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
*
* File:    handlers.h
* Summary: Definitions for Message Digest handling
*
*****************************************************************************/

/** @addtogroup noxtls_common */
/** @{ */

#ifndef _HANDLERS_H_
#define _HANDLERS_H_

/* Standard Includes */
#include <stdint.h>
#include <stdio.h>
#include "noxtls_config.h"

typedef struct {
    char algo[32];
    int (*handler)(uint8_t * data, uint32_t len);
    char description[256];

} handlers_t;

typedef enum {

    INPUT_DATA_TYPE_STRING,
    INPUT_DATA_TYPE_HEX
} input_data_type_t;


#endif /* _HANDLERS_H_ */
