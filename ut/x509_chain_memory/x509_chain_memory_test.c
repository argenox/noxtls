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
* File:    x509_chain_memory_test.c
* Summary: Bounded certificate-chain allocation regressions
*
*****************************************************************************/

#include "noxtls_x509.h"
#include "common/noxtls_memory.h"
#include "common/noxtls_memory_test.h"
#include "../mtls_policy/mtls_test_pki.h"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)
#define SMALL_POOL_BYTES (3U * sizeof(x509_certificate_t) + 1024U)
#define GROW_POOL_BYTES (40U * sizeof(x509_certificate_t) + 4096U)
static uint64_t small_pool[(SMALL_POOL_BYTES + 7U) / 8U];
static uint64_t grow_pool[(GROW_POOL_BYTES + 7U) / 8U];
static x509_certificate_t source;
/** @brief Three independently owned one-certificate chains fit a bounded heap.
 * @return Zero on success.
 */
static int small_chains(void)
{
    x509_certificate_chain_t chains[3];
    size_t allocated, used, peak;
    noxtls_mem_test_fail_reset();
    CHECK(noxtls_mem_init((uint8_t *)small_pool, sizeof(small_pool)) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_init(&source) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(NULL) == NOXTLS_RETURN_NULL);
    for (unsigned i = 0U; i < 3U; ++i) {
        CHECK(noxtls_x509_certificate_chain_init(&chains[i]) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_x509_certificate_chain_add(&chains[i], &source) == NOXTLS_RETURN_SUCCESS);
        CHECK(chains[i].count == 1U);
    }
    for (unsigned i = 0U; i < 3U; ++i)
        CHECK(noxtls_x509_certificate_chain_free(&chains[i]) == NOXTLS_RETURN_SUCCESS);

    CHECK(noxtls_mem_get_stats(&allocated, &used, &peak) == NOXTLS_RETURN_SUCCESS);
    CHECK(used == 0U);
    CHECK(noxtls_mem_cleanup() == NOXTLS_RETURN_SUCCESS);
    return 0;
}
/** @brief Chains still grow beyond eight entries and clone DER independently.
 * @return Zero on success.
 */
static int growth_and_copy(void)
{
    x509_certificate_chain_t chain;
    size_t allocated, used, peak;
    CHECK(noxtls_mem_init((uint8_t *)grow_pool, sizeof(grow_pool)) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_init(&source) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_parse_der(&source, mtls_ca_cert, sizeof(mtls_ca_cert)) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_init(&chain) == NOXTLS_RETURN_SUCCESS);
    for (unsigned i = 0U; i < 9U; ++i) {
        CHECK(noxtls_x509_certificate_chain_add(&chain, &source) == NOXTLS_RETURN_SUCCESS);
        CHECK(chain.count == i + 1U);
        CHECK(chain.certs[i].raw_data != source.raw_data);
        CHECK(chain.certs[i].raw_data_len == source.raw_data_len);
        CHECK(memcmp(chain.certs[i].raw_data, source.raw_data, source.raw_data_len) == 0);
    }
    CHECK(noxtls_x509_certificate_free(&source) == NOXTLS_RETURN_SUCCESS);
    CHECK(chain.certs[0].parsed != 0);
    CHECK(chain.certs[8].raw_data_len == sizeof(mtls_ca_cert));
    CHECK(noxtls_x509_certificate_chain_free(&chain) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_mem_get_stats(&allocated, &used, &peak) == NOXTLS_RETURN_SUCCESS);
    CHECK(used == 0U);
    CHECK(noxtls_mem_cleanup() == NOXTLS_RETURN_SUCCESS);
    return 0;
}
/** @brief Refused allocations preserve the existing chain and remain freeable.
 * @return Zero on success.
 */
static int allocation_failures(void)
{
    x509_certificate_chain_t chain;
    size_t allocated, used, peak;
    CHECK(noxtls_mem_init((uint8_t *)small_pool, sizeof(small_pool)) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_init(&source) == NOXTLS_RETURN_SUCCESS);
    /* chain_init allocates nothing, so it succeeds even when the heap refuses every request;
     * the first add then fails cleanly and leaves the chain empty. */
    noxtls_mem_test_fail_after(0U);
    CHECK(noxtls_x509_certificate_chain_init(&chain) == NOXTLS_RETURN_SUCCESS);
    CHECK(chain.certs == NULL && chain.count == 0U && chain.capacity == 0U);
    CHECK(noxtls_x509_certificate_chain_add(&chain, &source) != NOXTLS_RETURN_SUCCESS);
    CHECK(chain.certs == NULL && chain.count == 0U);
    CHECK(noxtls_x509_certificate_chain_free(&chain) == NOXTLS_RETURN_SUCCESS);
    noxtls_mem_test_fail_reset();
    CHECK(noxtls_x509_certificate_chain_init(&chain) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_x509_certificate_chain_add(&chain, &source) == NOXTLS_RETURN_SUCCESS);
    while (chain.count < chain.capacity)
        CHECK(noxtls_x509_certificate_chain_add(&chain, &source) == NOXTLS_RETURN_SUCCESS);

    x509_certificate_t *previous = chain.certs;
    uint32_t count = chain.count;
    noxtls_mem_test_fail_after(0U);
    CHECK(noxtls_x509_certificate_chain_add(&chain, &source) != NOXTLS_RETURN_SUCCESS);
    CHECK(chain.certs == previous && chain.count == count);
    noxtls_mem_test_fail_reset();
    CHECK(noxtls_x509_certificate_chain_free(&chain) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_mem_get_stats(&allocated, &used, &peak) == NOXTLS_RETURN_SUCCESS);
    CHECK(used == 0U);
    CHECK(noxtls_mem_cleanup() == NOXTLS_RETURN_SUCCESS);
    return 0;
}
/** @brief Execute actual X.509 APIs against the bounded allocator.
 * @return Zero only when every regression passes.
 */
int main(void)
{
    if (small_chains() || growth_and_copy() || allocation_failures()) return 1;

    puts("Certificate-chain memory: PASS");
    return 0;
}
