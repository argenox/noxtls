/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
* Licensed under the GNU General Public License v2.0 or later,
* or alternatively under a commercial license from Argenox Technologies LLC.
* See the LICENSE file in the project root for full details.
* CONTACT: info@argenox.com
*
* File:    tls13_link_ut.c
* Summary: TLS 1.3 context linkage with DTLS enabled or disabled
*****************************************************************************/
/** @file tls13_link_ut.c
 * @brief Check that TLS users can link without the optional DTLS implementation.
 * @ingroup noxtls_dtls13_recovery
 */
#include "tls/noxtls_tls13.h"
#include "runner.h"
#include "test_assert.h"

static tls13_context_t s_context;

/** @brief Link and initialize TLS 1.3 without requiring any DTLS-only symbol.
 * @return Zero on success. */
REGISTER_TEST(tls13_link_context_lifecycle)
{
    UTNOX_EQUALS(noxtls_tls13_context_init(NULL, TLS_ROLE_CLIENT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls13_context_init(&s_context, TLS_ROLE_CLIENT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls13_context_free(&s_context), NOXTLS_RETURN_SUCCESS);
    return 0;
}

#if defined(_MSC_VER)
/** @brief Register tests where compiler constructor registration is unavailable. */
void utnox_register_tests(void)
{
    register_test(__reg_tls13_link_context_lifecycle.name, __reg_tls13_link_context_lifecycle.func);
}
#endif
