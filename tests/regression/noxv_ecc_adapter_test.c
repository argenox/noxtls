/* Actual NoxV P-256 adapter exercised through its weak MMIO seam. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pkc/ecc/noxtls_ecc.h"

noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *,
    const uint8_t *, const ecc_point_t *, const ecc_curve_params_t *);

static uint32_t regs[0x130 / 4];
static uint32_t status_value;
static uint32_t status_reads;
static uint32_t zeroizes;
static uint32_t writes;

uint32_t noxtls_noxv_ecc_p256_mmio_read(uint32_t offset)
{
    if(offset == 4u) { ++status_reads; return status_value; }
    return regs[offset / 4u];
}

void noxtls_noxv_ecc_p256_mmio_write(uint32_t offset, uint32_t value)
{
    ++writes;
    regs[offset / 4u] = value;
    if(offset == 0u && value == 8u) {
        ++zeroizes;
        memset(&regs[0x10 / 4], 0, 8u * sizeof(uint32_t));
    }
}

static int check(int condition, const char *label)
{
    if(!condition) fprintf(stderr, "FAIL: %s\n", label);
    return condition;
}

static const uint8_t two_g_x[32] = {
    0x7c,0xf2,0x7b,0x18,0x8d,0x03,0x4f,0x7e,
    0x8a,0x52,0x38,0x03,0x04,0xb5,0x1a,0xc3,
    0xc0,0x89,0x69,0xe2,0x77,0xf2,0x1b,0x35,
    0xa6,0x0b,0x48,0xfc,0x47,0x66,0x99,0x78
};
static const uint8_t two_g_y[32] = {
    0x07,0x77,0x55,0x10,0xdb,0x8e,0xd0,0x40,
    0x29,0x3d,0x9a,0xc6,0x9f,0x74,0x30,0xdb,
    0xba,0x7d,0xad,0xe6,0x3c,0xe9,0x82,0x29,
    0x9e,0x04,0xb7,0x9d,0x22,0x78,0x73,0xd1
};

static uint32_t be_word(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

int main(void)
{
    ecc_curve_params_t curve;
    ecc_point_t result;
    uint8_t scalar[32] = {0};
    uint32_t before;
    uint32_t i;
    noxtls_return_t rc;
    int ok = 1;
    memset(&curve, 0, sizeof(curve));
    memset(&result, 0, sizeof(result));
    rc = noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1);
    if(!check(rc == NOXTLS_RETURN_SUCCESS, "initialize curve")) return 1;
    scalar[31] = 2u;
    for(i = 0; i < 8u; ++i) {
        regs[(0xf0 / 4) + i] = be_word(two_g_x + 4u * i);
        regs[(0x110 / 4) + i] = be_word(two_g_y + 4u * i);
    }

    status_value = 6u;
    rc = noxtls_ecc_point_multiply_accel_port(&result, scalar, &curve.G, &curve);
    ok &= check(rc == NOXTLS_RETURN_SUCCESS, "valid hardware result accepted");
    ok &= check(memcmp(result.x, two_g_x, 32) == 0 &&
                memcmp(result.y, two_g_y, 32) == 0, "big-endian output matches 2G");
    ok &= check(regs[0x70 / 4] == be_word(curve.G.x), "big-endian X input");
    ok &= check(regs[0x90 / 4] == be_word(curve.G.y), "big-endian Y input");
    ok &= check(result.size == 32u && zeroizes == 1u, "success zeroizes scalar");
    ok &= check(noxtls_ecc_accel_operation_count() == 1u &&
                noxtls_ecc_accel_is_ready(), "success telemetry");

    status_value = 2u; /* DONE without VALID. */
    rc = noxtls_ecc_point_multiply_accel_port(&result, scalar, &curve.G, &curve);
    ok &= check(rc == NOXTLS_RETURN_FAILED && zeroizes == 2u, "invalid result fails and zeroizes");
    status_value = 6u | 0x10u; /* VALID with hardware error. */
    rc = noxtls_ecc_point_multiply_accel_port(&result, scalar, &curve.G, &curve);
    ok &= check(rc == NOXTLS_RETURN_FAILED && zeroizes == 3u, "error bits fail and zeroize");

    status_value = 0u;
    status_reads = 0u;
    rc = noxtls_ecc_point_multiply_accel_port(&result, scalar, &curve.G, &curve);
    ok &= check(rc == NOXTLS_RETURN_TIMEOUT && status_reads == 32u &&
                zeroizes == 4u, "bounded timeout zeroizes");
    ok &= check(noxtls_ecc_accel_last_rc() == NOXTLS_RETURN_TIMEOUT &&
                noxtls_ecc_accel_last_status() == 0u, "timeout telemetry");
    before = writes;
    curve.size = 31u;
    rc = noxtls_ecc_point_multiply_accel_port(&result, scalar, &curve.G, &curve);
    ok &= check(rc == NOXTLS_RETURN_NOT_SUPPORTED && writes == before,
                "unsupported curve makes no hardware writes");
    curve.size = 32u;
    rc = noxtls_ecc_point_multiply_accel_port(NULL, scalar, &curve.G, &curve);
    ok &= check(rc == NOXTLS_RETURN_NULL && writes == before,
                "null output makes no hardware writes");

    status_reads = 0u;
    before = noxtls_ecc_accel_fallback_count();
    rc = noxtls_ecc_point_multiply(&result, scalar, &curve.G, &curve);
    /* Only NOT_SUPPORTED may fall back to software; a hardware timeout is
     * reported to the caller with the result wiped. */
    ok &= check(rc == NOXTLS_RETURN_TIMEOUT && result.size == 0u &&
                memcmp(result.x, two_g_x, 32) != 0,
                "hardware timeout propagates and wipes the result");
    ok &= check(status_reads == 32u &&
                noxtls_ecc_accel_fallback_count() == before,
                "actual wrapper does not count a fallback after hardware failure");
    ok &= check(noxtls_ecc_accel_operation_count() == 1u,
                "failed hardware never increments successful operations");
    (void)noxtls_ecc_curve_free(&curve);
    puts(ok ? "noxv_ecc_adapter_test: PASS" : "noxv_ecc_adapter_test: FAIL");
    return ok ? 0 : 1;
}
