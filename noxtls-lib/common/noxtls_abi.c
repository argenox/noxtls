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
* File:    noxtls_abi.c
* Summary: Definitions of the link-time ABI fingerprint symbols
*
*****************************************************************************/

/**
 * @file noxtls_abi.c
 * @brief Define the ABI fingerprint symbols that noxtls_abi.h references.
 *
 * It lives in noxtls_common, which every NoxTLS library links, because crypto
 * translation units that include the TLS headers reference it too. It has no
 * other content, so the reference pulls nothing else from the archive.
 */

#include <stdint.h>

#include "noxtls_tls_common.h"

/** Fingerprint of this build's layout (noxtls_abi.h). */
const uint8_t NOXTLS_ABI_SYMBOL = 1U;

#if defined(NOXTLS_ABI_LAYOUT_ID)
/** Fingerprint a consumer without NOXTLS_ABI_LAYOUT_ID requires. */
extern const uint8_t NOXTLS_ABI_BASE_SYMBOL;
const uint8_t NOXTLS_ABI_BASE_SYMBOL = 1U;
#endif
