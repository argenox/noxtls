#include <stdio.h>
#include <string.h>
#undef NOXTLS_FEATURE_NOXV_HW_ACCEL
#define NOXTLS_FEATURE_NOXV_HW_ACCEL 1
#include "../../noxtls-lib/mdigest/sha256/noxtls_sha256.c"

#if !NOXTLS_FEATURE_NOXV_HW_ACCEL
#error This regression must exercise the actual accelerated SHA update path.
#endif

noxtls_return_t noxtls_sha256_blocks_accel_port(noxtls_sha_ctx_t *, const uint8_t *, uint32_t);

static noxtls_sha_ctx_t hardware;
static uint8_t hardware_block[64];
static unsigned starts, fail_on, irq_depth, failures;
static unsigned invalid_result;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #c); failures++; } } while (0)

uintptr_t noxtls_noxv_sha256_irq_save(void) { irq_depth++; return 17u; }
void noxtls_noxv_sha256_irq_restore(uintptr_t s) { CHECK(s == 17u && irq_depth == 1u); irq_depth--; }
void noxtls_noxv_sha256_mmio_write(uint32_t offset, uint32_t value)
{
    if (offset >= 8u && offset < 72u) {
        unsigned i = offset - 8u;
        hardware_block[i] = (uint8_t)(value >> 24);
        hardware_block[i + 1u] = (uint8_t)(value >> 16);
        hardware_block[i + 2u] = (uint8_t)(value >> 8);
        hardware_block[i + 3u] = (uint8_t)value;
    } else if (offset == 0u && (value == 2u || value == 4u)) {
        starts++;
        if (value == 2u) CHECK(noxtls_sha256_init(&hardware, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
        CHECK(noxtls_sha256_round_software(&hardware, hardware_block) == NOXTLS_RETURN_SUCCESS);
    }
}
uint32_t noxtls_noxv_sha256_mmio_read(uint32_t offset)
{
    CHECK(irq_depth == 1u);
    if (offset == 4u) {
        if (fail_on == starts) return invalid_result ? 2u : 0u;
        return 6u;
    }
    CHECK(offset >= 72u && offset < 104u);
    return hardware.h[(offset - 72u) / 4u];
}
static void digest_matches(const uint8_t *data, unsigned length, const char *expected)
{
    noxtls_sha_ctx_t ctx;
    uint8_t digest[32];
    char hex[65];
    unsigned i;
    CHECK(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_sha256_update(&ctx, data, length) == NOXTLS_RETURN_SUCCESS);
    CHECK(noxtls_sha256_finish(&ctx, digest) == NOXTLS_RETURN_SUCCESS);
    for (i = 0; i < 32u; i++) sprintf(hex + i * 2u, "%02x", digest[i]);
    CHECK(strcmp(hex, expected) == 0);
    CHECK(irq_depth == 0u);
}
int main(void)
{
    noxtls_sha_ctx_t ctx, before;
    uint8_t data[192];
    unsigned i;
    for (i = 0; i < sizeof(data); i++) data[i] = (uint8_t)i;
    CHECK(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
    before = ctx; starts = 0u; fail_on = 2u;
    CHECK(noxtls_sha256_blocks_accel_port(&ctx, data, 2u) == NOXTLS_RETURN_TIMEOUT);
    CHECK(starts == 2u && irq_depth == 0u);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    starts = 0u; fail_on = 2u;
    digest_matches(data, 128u, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5");
    starts = 0u; fail_on = 0u;
    digest_matches(data, 128u, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5");
    starts = 0u; fail_on = 2u; invalid_result = 1u;
    digest_matches(data, 128u, "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5");
    CHECK(noxtls_sha256_init(&ctx, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS);
    starts = 0u; fail_on = 0u; invalid_result = 0u;
    CHECK(noxtls_sha256_update(&ctx, data, 64u) == NOXTLS_RETURN_SUCCESS);
    before = ctx; fail_on = 3u;
    CHECK(noxtls_sha256_blocks_accel_port(&ctx, data + 64u, 2u) == NOXTLS_RETURN_TIMEOUT);
    CHECK(memcmp(&ctx, &before, sizeof(ctx)) == 0);
    CHECK(noxtls_sha256_update(&ctx, data + 64u, 128u) == NOXTLS_RETURN_SUCCESS);
    {
        uint8_t digest[32]; char hex[65];
        CHECK(noxtls_sha256_finish(&ctx, digest) == NOXTLS_RETURN_SUCCESS);
        for (i = 0; i < 32u; i++) sprintf(hex + i * 2u, "%02x", digest[i]);
        CHECK(strcmp(hex, "8b4a544837a1a0280fa8a7c82865c27a1064b3cc6281fda0753566b9bb104a87") == 0);
    }
    CHECK(irq_depth == 0u);
    printf("NoxV SHA batch publication and known-vector fallback: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
