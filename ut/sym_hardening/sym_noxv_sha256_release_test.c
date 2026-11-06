/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    sym_noxv_sha256_release_test.c
* Summary: The NoxV SHA-256 adapter drops its cached chaining value (the
*          digest of a finished hash) and clears the engine when the hash
*          finishes. The engine is modelled in software through the adapter's
*          external I/O hooks, as in tests/regression.
*****************************************************************************/
#include <stdio.h>
#include <string.h>

#undef NOXTLS_FEATURE_NOXV_HW_ACCEL
#define NOXTLS_FEATURE_NOXV_HW_ACCEL 1
#define NOXTLS_NOXV_SHA256_EXTERNAL_IO 1
#include "../../noxtls-lib/mdigest/sha256/noxtls_sha256.c"
#include "../../noxtls-lib/mdigest/sha256/noxtls_sha256_accel_noxv_port.c"

static noxtls_sha_ctx_t g_hw;
static uint8_t g_hw_block[64];
static unsigned g_failures;
static unsigned g_clears;
static unsigned g_starts;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL line %u: %s\n", (unsigned)__LINE__, #c); g_failures++; } } while (0)

uintptr_t noxtls_noxv_sha256_irq_save(void) { return 1u; }
void noxtls_noxv_sha256_irq_restore(uintptr_t s) { (void)s; }
void noxtls_noxv_sha256_mmio_write(uint32_t offset, uint32_t value)
{
    if ((offset >= 8u) && (offset < 72u)) {
        unsigned i = offset - 8u;
        g_hw_block[i] = (uint8_t)(value >> 24);
        g_hw_block[i + 1u] = (uint8_t)(value >> 16);
        g_hw_block[i + 2u] = (uint8_t)(value >> 8);
        g_hw_block[i + 3u] = (uint8_t)value;
    } else if (offset == 0u) {
        if ((value == 2u) || (value == 4u)) {
            g_starts++;
            if (value == 2u) {
                (void)noxtls_sha256_init(&g_hw, NOXTLS_HASH_SHA_256);
            }
            (void)noxtls_sha256_round_software(&g_hw, g_hw_block);
        } else if (value == 8u) {
            g_clears++;
        }
    }
}
uint32_t noxtls_noxv_sha256_mmio_read(uint32_t offset)
{
    if (offset == 4u) {
        return 6u;
    }
    return g_hw.u.md32.h[(offset - 72u) / 4u];
}

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < n; i++) {
        if (b[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    noxtls_sha_ctx_t ctx;
    noxtls_sha_ctx_t other;
    uint8_t data[150];
    uint8_t digest[32];
    unsigned i;
    unsigned clears_before;

    for (i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i * 7u + 3u);
    }
    CHECK(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_sha256_update(&ctx, data, sizeof(data)) == NOXTLS_RETURN_SUCCESS);
    CHECK(g_starts > 0u);                      /* the hardware path was used */
    CHECK(s_active_ctx == &ctx);
    CHECK(!all_zero(s_active_digest, sizeof(s_active_digest)));
    clears_before = g_clears;
    CHECK(noxtls_sha256_finish(&ctx, digest) == NOXTLS_RETURN_SUCCESS);
    CHECK(s_active_ctx == NULL);
    CHECK(all_zero(s_active_digest, sizeof(s_active_digest)));
    CHECK(g_clears > clears_before);           /* engine registers cleared */

    /* Interleaved contexts: the cache follows the last hardware user and is
     * cleared when that context finishes; the other context continues in
     * software and still produces the same digest. */
    {
        uint8_t ref[32];
        CHECK(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_sha256_update(&ctx, data, sizeof(data)) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_sha256_finish(&ctx, ref) == NOXTLS_RETURN_SUCCESS);

        CHECK(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_sha256_update(&ctx, data, 64u) == NOXTLS_RETURN_SUCCESS);
        CHECK(s_active_ctx == &ctx);
        CHECK(noxtls_sha256_init(&other, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_sha256_finish(&other, digest) == NOXTLS_RETURN_SUCCESS);
        CHECK(s_active_ctx == NULL);
        CHECK(all_zero(s_active_digest, sizeof(s_active_digest)));
        CHECK(noxtls_sha256_update(&ctx, &data[64], sizeof(data) - 64u) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_sha256_finish(&ctx, digest) == NOXTLS_RETURN_SUCCESS);
        CHECK(memcmp(digest, ref, sizeof(ref)) == 0);
        CHECK(s_active_ctx == NULL);
        CHECK(all_zero(s_active_digest, sizeof(s_active_digest)));
    }

    printf("sym_noxv_sha256_release_test: %s\n", g_failures ? "FAIL" : "PASS");
    return g_failures ? 1 : 0;
}
