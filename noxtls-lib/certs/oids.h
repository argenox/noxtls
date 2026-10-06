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
* File:    noxtls_oids.h
* Summary: NoxTLS OIDS Definitions
*
*****************************************************************************/

/** @addtogroup noxtls_certs */
/** @{ */

#ifndef NOXTLS_OIDS_H_
#define NOXTLS_OIDS_H_

#include <stdint.h>
#include "noxtls_common.h"

#ifdef __cplusplus
extern "C" {
#endif

NOXTLS_MSVC_WARNING_PUSH
NOXTLS_MSVC_DISABLE_PADDING
typedef struct oid_item_t
{
	uint32_t id;
	/* Dir 1.1: OID label text; signedness of plain char is not relied upon. */
	const uint8_t * name;
	const struct oid_item_t * items;

} oid_item_t;
NOXTLS_MSVC_WARNING_POP

extern const oid_item_t base_oids[3];

#ifdef __cplusplus
}
#endif

#endif /* NOXTLS_OIDS_H_ */
