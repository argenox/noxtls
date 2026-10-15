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
* File:    key_share_memory_ut.c
* Summary: Bounded key-share parsing and allocation regressions
*****************************************************************************/
/** @file key_share_memory_ut.c
 * @brief Verify bounded RFC 8446 section 4.2.8 key-share allocation and rejection.
 * @ingroup noxtls_common
 */
#include "noxtls_tls_common.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_test.h"
#include "runner.h"
#include "test_assert.h"
#include <string.h>
#include <stdbool.h>

#define TEST_POOL_BYTES 1024U
#define TEST_SHARE_BYTES 32U
static uint64_t s_pool[TEST_POOL_BYTES / sizeof(uint64_t)];

/** @brief A single X25519 share fits a small heap; freeing restores its budget.
 * @return Zero on success. */
REGISTER_TEST(key_share_memory_one_entry)
{
    uint8_t wire[2U + 4U + TEST_SHARE_BYTES] = {0U, 36U, 0U, 29U, 0U, TEST_SHARE_BYTES};
    size_t allocated, used, peak;
    memset(wire + 6U, 0x5a, TEST_SHARE_BYTES);
    UTNOX_EQUALS(noxtls_mem_init((uint8_t *)s_pool, sizeof(s_pool)), NOXTLS_RETURN_SUCCESS);
    tls_key_share_list_extension_t share;
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, sizeof(wire), &share), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(share.count, 1U);
    UTNOX_EQUALS(share.entries[0].group, 29U);
    UTNOX_EQUALS(share.entries[0].key_exchange_len, TEST_SHARE_BYTES);
    UTNOX_EQUALS(memcmp(share.entries[0].key_exchange, wire + 6U, TEST_SHARE_BYTES), 0);
    UTNOX_EQUALS(noxtls_mem_get_stats(&allocated, &used, &peak), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(peak < TEST_POOL_BYTES, true);
    (void)noxtls_free(share.entries[0].key_exchange);
    (void)noxtls_free(share.entries);
    UTNOX_EQUALS(noxtls_mem_cleanup(), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief Malformed vectors are rejected before allocating or copying entries.
 * @return Zero on success. */
REGISTER_TEST(key_share_memory_rejects_boundaries)
{
    tls_key_share_list_extension_t share;
    uint8_t wire[] = {0U, 5U, 0U, 29U, 0U, 1U, 0x5aU, 0U};
    noxtls_mem_test_stats_t stats;
    UTNOX_EQUALS(noxtls_mem_init((uint8_t *)s_pool, sizeof(s_pool)), NOXTLS_RETURN_SUCCESS);
    noxtls_mem_test_stats_reset();
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(NULL, 2U, &share), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 2U, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 1U, &share), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 6U, &share), NOXTLS_RETURN_BAD_DATA);
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 8U, &share), NOXTLS_RETURN_BAD_DATA);
    wire[1] = 3U;
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 5U, &share), NOXTLS_RETURN_BAD_DATA);
    wire[1] = 4U;
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 6U, &share), NOXTLS_RETURN_BAD_DATA);
    noxtls_mem_test_get_stats(&stats);
    UTNOX_EQUALS(stats.allocation_attempts, 0U);
    wire[1] = 0U;
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, 2U, &share), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(share.count, 0U);
    UTNOX_EQUALS(share.entries, NULL);
    UTNOX_EQUALS(noxtls_mem_cleanup(), NOXTLS_RETURN_SUCCESS);
    return 0;
}

/** @brief A later allocation failure frees all prior entries without widening the budget.
 * @return Zero on success. */
REGISTER_TEST(key_share_memory_partial_failure_cleanup)
{
    const uint8_t wire[] = {0U, 10U, 0U, 29U, 0U, 1U, 0x5aU, 0U, 23U, 0U, 1U, 0x66U};
    tls_key_share_list_extension_t share;
    size_t allocated, used, peak;
    for (size_t fail = 0U; fail < 3U; ++fail) {
        UTNOX_EQUALS(noxtls_mem_init((uint8_t *)s_pool, sizeof(s_pool)), NOXTLS_RETURN_SUCCESS);
        noxtls_mem_test_fail_after(fail);
        UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, sizeof(wire), &share), NOXTLS_RETURN_FAILED);
        noxtls_mem_test_fail_reset();
        UTNOX_EQUALS(noxtls_mem_get_stats(&allocated, &used, &peak), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(used, 0U);
        UTNOX_EQUALS(noxtls_mem_cleanup(), NOXTLS_RETURN_SUCCESS);
    }

    UTNOX_EQUALS(noxtls_mem_init((uint8_t *)s_pool, sizeof(s_pool)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_tls_parse_extension_key_share(wire, sizeof(wire), &share), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(share.count, 2U);
    for (uint32_t i = 0U; i < share.count; ++i) {
        (void)noxtls_free(share.entries[i].key_exchange);
    }

    (void)noxtls_free(share.entries);
    UTNOX_EQUALS(noxtls_mem_cleanup(), NOXTLS_RETURN_SUCCESS);
    return 0;
}

#if defined(_MSC_VER)
/** @brief Register tests where compiler constructor registration is unavailable. */
void utnox_register_tests(void)
{
    register_test(__reg_key_share_memory_one_entry.name, __reg_key_share_memory_one_entry.func);
    register_test(__reg_key_share_memory_rejects_boundaries.name, __reg_key_share_memory_rejects_boundaries.func);
    register_test(__reg_key_share_memory_partial_failure_cleanup.name, __reg_key_share_memory_partial_failure_cleanup.func);
}
#endif
