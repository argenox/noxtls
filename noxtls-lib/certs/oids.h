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
* File:    noxtls_oids.h
* Summary: NOXTLS OIDS Definitions
*
*/

/** @addtogroup noxtls_certs */
/** @{ */

#ifndef _NOXTLS_OIDS_H_
#define _NOXTLS_OIDS_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif


#define PKCS_BASE "1.2.840.113549.1"


NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct oid_item_t
{
	uint32_t id;
	char * name;
	const struct oid_item_t * items;

} oid_item_t;
NOXTLS_MSVC_WARNING_POP


extern const oid_item_t base_oids[3];

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_OIDS_H_ */
