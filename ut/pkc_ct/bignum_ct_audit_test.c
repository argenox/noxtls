/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    bignum_ct_audit_test.c
* Summary: Regression tests for the constant-time bignum / RSA / DSA audit fixes
*
* Covers:
*   - noxtls_bn_mod_ct() against noxtls_bn_mod() (odd and even moduli, leading zero bytes,
*     every dividend length class, aliasing, zero modulus);
*   - noxtls_bn_mod_inv_prime_ct() against noxtls_bn_mod_inv(), zero and composite inputs;
*   - secret-exponent modular exponentiation: the number of Montgomery steps does not depend
*     on leading zero bytes of the exponent (service-callback count), results unchanged;
*   - RSA public-key validation (even n, e = 1, even e, oversized e);
*   - RSA key generation: modulus always has the requested bit length;
*   - constant-time PKCS#1 v1.5 unpadding: output contract on success and failure;
*   - DSA and ECDSA (P-384, P-521) sign / verify round trips through the constant-time paths.
*
* Timing itself is not measured here: these tests pin the functional contracts.
*****************************************************************************/

#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "mdigest/noxtls_hash.h"
#include "pkc/rsa/noxtls_bignum.h"
#if NOXTLS_FEATURE_RSA
#include "pkc/rsa/noxtls_rsa.h"
#endif
#if NOXTLS_FEATURE_DSA
#include "pkc/dsa/noxtls_dsa.h"
#endif
#if NOXTLS_FEATURE_ECDSA
#include "pkc/ecc/noxtls_ecc.h"
#include "pkc/ecdsa/noxtls_ecdsa.h"
#endif

static int g_failures = 0;
static int g_checks = 0;

static int check(int cond, const char *what)
{
    g_checks += 1;
    if(!cond) {
        g_failures += 1;
        (void)printf("FAIL: %s\n", what);
    }
    return cond;
}

static uint32_t g_rng = 0x2545F491U;
static uint8_t rnd8(void)
{
    g_rng ^= g_rng << 13U;
    g_rng ^= g_rng >> 17U;
    g_rng ^= g_rng << 5U;
    return (uint8_t)(g_rng >> 24U);
}
static void rnd_fill(uint8_t *b, uint32_t n)
{
    uint32_t i;
    for(i = 0U; i < n; i += 1U) { b[i] = rnd8(); }
}

/* ---------------------------------------------------------------- bn_mod_ct */
static void test_bn_mod_ct(void)
{
    static const uint32_t mod_lens[] = { 1U, 2U, 3U, 4U, 5U, 7U, 8U, 9U, 16U, 20U, 28U, 32U, 33U, 48U, 64U, 66U, 128U };
    uint8_t a[300];
    uint8_t mod[130];
    uint8_t r1[130];
    uint8_t r2[130];
    uint8_t buf[300];
    uint32_t mi;
    char what[160];
    int ok = 1;

    for(mi = 0U; mi < (uint32_t)(sizeof(mod_lens) / sizeof(mod_lens[0])); mi += 1U) {
        uint32_t ml = mod_lens[mi];
        uint32_t variant;
        for(variant = 0U; variant < 6U; variant += 1U) {
            uint32_t a_lens[9];
            uint32_t li;
            rnd_fill(mod, ml);
            if((variant & 1U) == 0U) { mod[ml - 1U] |= 1U; } else { mod[ml - 1U] &= 0xFEU; }
            if((variant >= 2U) && (variant < 4U) && (ml >= 2U)) { mod[0] = 0U; }   /* leading zero */
            if(variant >= 4U) { mod[0] |= 0x80U; }
            if(noxtls_bn_is_zero(mod, ml) != 0) { mod[ml - 1U] = 3U; }
            a_lens[0] = 0U; a_lens[1] = 1U; a_lens[2] = ml - 1U; a_lens[3] = ml; a_lens[4] = ml + 1U;
            a_lens[5] = 2U * ml; a_lens[6] = (2U * ml) + 1U; a_lens[7] = (2U * ml) + 8U; a_lens[8] = (2U * ml) + 8U;
            for(li = 0U; li < 9U; li += 1U) {
                uint32_t al = a_lens[li];
                int32_t rep;
                for(rep = 0; rep < 4; rep += 1) {
                    rnd_fill(a, al);
                    if((rep == 1) && (al > 1U)) { a[0] = 0U; }               /* zero top byte */
                    if((rep == 2) && (al > 2U)) { (void)memset(a, 0, al - 1U); }
                    if(li == 8U) { (void)memcpy(a, mod, (al < ml) ? al : ml); } /* a close to mod */
                    (void)memset(r1, 0xA5, sizeof(r1));
                    (void)memset(r2, 0x5A, sizeof(r2));
                    if((noxtls_bn_mod(r1, a, al, mod, ml) != NOXTLS_RETURN_SUCCESS) ||
                       (noxtls_bn_mod_ct(r2, a, al, mod, ml) != NOXTLS_RETURN_SUCCESS) ||
                       (memcmp(r1, r2, ml) != 0)) {
                        (void)snprintf(what, sizeof(what), "bn_mod_ct == bn_mod (mod_len %u, variant %u, a_len %u, rep %d)",
                                       (unsigned)ml, (unsigned)variant, (unsigned)al, (int)rep);
                        ok = check(0, what);
                    }
                    /* aliasing: result at the start of the dividend */
                    if(al >= ml) {
                        (void)memcpy(buf, a, al);
                        if((noxtls_bn_mod_ct(buf, buf, al, mod, ml) != NOXTLS_RETURN_SUCCESS) ||
                           (memcmp(buf, r1, ml) != 0)) {
                            (void)snprintf(what, sizeof(what), "bn_mod_ct aliased (mod_len %u, a_len %u)", (unsigned)ml, (unsigned)al);
                            ok = check(0, what);
                        }
                    }
                }
            }
        }
    }
    (void)check(ok, "bn_mod_ct matches bn_mod on all shapes");

    /* modulus 1 -> 0; zero modulus rejected */
    {
        uint8_t one[4] = { 0U, 0U, 0U, 1U };
        uint8_t zero[4] = { 0U, 0U, 0U, 0U };
        uint8_t out[4] = { 9U, 9U, 9U, 9U };
        rnd_fill(a, 40U);
        (void)check((noxtls_bn_mod_ct(out, a, 40U, one, 4U) == NOXTLS_RETURN_SUCCESS) &&
                    (noxtls_bn_is_zero(out, 4U) != 0), "bn_mod_ct: x mod 1 == 0");
        (void)check(noxtls_bn_mod_ct(out, a, 40U, zero, 4U) == NOXTLS_RETURN_INVALID_PARAM, "bn_mod_ct: zero modulus rejected");
        (void)check(noxtls_bn_mod_ct(out, a, 40U, one, 0U) == NOXTLS_RETURN_INVALID_PARAM, "bn_mod_ct: zero mod_len rejected");
        (void)check(noxtls_bn_mod_ct(NULL, a, 40U, one, 4U) == NOXTLS_RETURN_NULL, "bn_mod_ct: NULL result");
    }
}

/* ------------------------------------------------------- mod_inv_prime_ct */
static const uint8_t s_m127[16] = {  /* 2^127 - 1 */
    0x7FU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU
};

static void test_mod_inv_prime_ct(void)
{
    uint8_t a[40];
    uint8_t inv1[16];
    uint8_t inv2[16];
    int i;
    int ok = 1;

    for(i = 0; i < 32; i += 1) {
        uint32_t al = (i < 16) ? 16U : 40U;   /* also unreduced inputs */
        rnd_fill(a, al);
        if(al == 16U) { a[0] &= 0x7FU; }
        if(noxtls_bn_mod_inv_prime_ct(inv2, a, al, s_m127, 16U) != NOXTLS_RETURN_SUCCESS) {
            ok = 0;
            continue;
        }
        if(al == 16U) {
            if((noxtls_bn_mod_inv(inv1, a, 16U, s_m127, 16U) != NOXTLS_RETURN_SUCCESS) || (memcmp(inv1, inv2, 16U) != 0)) {
                ok = 0;
            }
        }
    }
    (void)check(ok, "mod_inv_prime_ct agrees with mod_inv mod 2^127-1");
    /* aliasing */
    rnd_fill(a, 16U); a[0] &= 0x7FU;
    (void)noxtls_bn_mod_inv(inv1, a, 16U, s_m127, 16U);
    (void)check((noxtls_bn_mod_inv_prime_ct(a, a, 16U, s_m127, 16U) == NOXTLS_RETURN_SUCCESS) && (memcmp(a, inv1, 16U) == 0),
                "mod_inv_prime_ct aliased");
    /* zero input and a multiple of p fail */
    (void)memset(a, 0, sizeof(a));
    (void)check(noxtls_bn_mod_inv_prime_ct(inv2, a, 16U, s_m127, 16U) == NOXTLS_RETURN_FAILED, "mod_inv_prime_ct: 0 fails");
    (void)memcpy(a, s_m127, 16U);
    (void)check(noxtls_bn_mod_inv_prime_ct(inv2, a, 16U, s_m127, 16U) == NOXTLS_RETURN_FAILED, "mod_inv_prime_ct: p fails");
    (void)check(noxtls_bn_is_zero(inv2, 16U) != 0, "mod_inv_prime_ct: result zeroed on failure");
    /* composite modulus 15: Fermat gives no inverse, the check catches it */
    {
        const uint8_t m15[1] = { 15U };
        const uint8_t two[1] = { 2U };
        const uint8_t m16[1] = { 16U };
        uint8_t out[1];
        (void)check(noxtls_bn_mod_inv_prime_ct(out, two, 1U, m15, 1U) == NOXTLS_RETURN_FAILED, "mod_inv_prime_ct: composite modulus fails");
        (void)check(noxtls_bn_mod_inv_prime_ct(out, two, 1U, m16, 1U) == NOXTLS_RETURN_INVALID_PARAM, "mod_inv_prime_ct: even modulus rejected");
    }
}

/* ------------------------------------------------ exponent length (issue 162) */
static uint32_t g_service_calls = 0U;
static void count_service(void) { g_service_calls += 1U; }

static void test_mod_exp_no_trim(const uint8_t *p, uint32_t p_len)
{
    uint8_t base[256];
    uint8_t e_full[20];
    uint8_t e_short[20];
    uint8_t r1[256];
    uint8_t r2[256];
    uint32_t calls_full;
    uint32_t calls_short;

    if(p_len > sizeof(base)) { return; }
    rnd_fill(base, p_len);
    base[0] = 0U;
    rnd_fill(e_full, 20U);
    e_full[0] |= 0x80U;
    (void)memcpy(e_short, e_full, 20U);
    e_short[0] = 0U;
    e_short[1] = 0U;     /* two zero top bytes */

    g_service_calls = 0U;
    (void)check(noxtls_bn_mod_exp_service(r1, base, e_full, 20U, p, p_len, count_service) == NOXTLS_RETURN_SUCCESS, "mod_exp (full exponent)");
    calls_full = g_service_calls;
    g_service_calls = 0U;
    (void)check(noxtls_bn_mod_exp_service(r1, base, e_short, 20U, p, p_len, count_service) == NOXTLS_RETURN_SUCCESS, "mod_exp (exponent with zero top bytes)");
    calls_short = g_service_calls;
    (void)check((calls_full == calls_short) && (calls_full > 0U),
                "mod_exp: same number of Montgomery steps with and without zero top exponent bytes");
    /* result unchanged against the public path with the trimmed exponent */
    (void)check(noxtls_bn_mod_exp_public(r2, base, &e_short[2], 18U, p, p_len) == NOXTLS_RETURN_SUCCESS, "mod_exp_public");
    (void)check(memcmp(r1, r2, p_len) == 0, "mod_exp: zero top bytes give the same value as the trimmed exponent");
    /* even modulus through the public path still works (ladder with trimmed public exponent) */
    {
        uint8_t m_even[32];
        uint8_t e_pub[8] = { 0U, 0U, 0U, 0U, 0U, 1U, 0U, 1U };
        uint8_t x1[32];
        uint8_t x2[32];
        rnd_fill(m_even, 32U);
        m_even[0] |= 0x80U;
        m_even[31] &= 0xFEU;
        (void)check(noxtls_bn_mod_exp_public(x1, base, e_pub, 8U, m_even, 32U) == NOXTLS_RETURN_SUCCESS, "mod_exp_public even modulus");
        (void)check(noxtls_bn_mod_exp(x2, base, &e_pub[5], 3U, m_even, 32U) == NOXTLS_RETURN_SUCCESS, "mod_exp even modulus");
        (void)check(memcmp(x1, x2, 32U) == 0, "mod_exp_public even modulus matches the ladder");
    }
}

#if NOXTLS_FEATURE_DSA
static const uint8_t s_d1024_p[128] = {
    0xF6U, 0xEFU, 0x72U, 0x1BU, 0x7CU, 0x7FU, 0x2CU, 0x85U, 0x9BU, 0x31U, 0x32U, 0x3CU,
    0xE8U, 0x76U, 0xAAU, 0xCAU, 0x09U, 0x67U, 0x89U, 0xFFU, 0x3CU, 0x5FU, 0x50U, 0x6BU,
    0x30U, 0x28U, 0x80U, 0x61U, 0xEAU, 0x67U, 0x3DU, 0xD7U, 0x83U, 0x2DU, 0xAFU, 0x08U,
    0x2BU, 0x9EU, 0x53U, 0x96U, 0x6FU, 0x6CU, 0x70U, 0x20U, 0x1AU, 0x09U, 0x39U, 0x48U,
    0x45U, 0x19U, 0x2CU, 0xE3U, 0xE9U, 0xE3U, 0xA1U, 0x98U, 0x12U, 0xE6U, 0xA8U, 0x6BU,
    0x72U, 0x1DU, 0xCFU, 0xACU, 0xE2U, 0xF7U, 0xA3U, 0x58U, 0x0DU, 0x5CU, 0xF6U, 0x4AU,
    0x15U, 0xE9U, 0xDEU, 0x76U, 0x5CU, 0x81U, 0xEFU, 0xEAU, 0x41U, 0xECU, 0x10U, 0x9EU,
    0xF5U, 0x57U, 0xB5U, 0x3BU, 0x8EU, 0xA8U, 0x5AU, 0x18U, 0xF8U, 0xC7U, 0xB3U, 0x2DU,
    0xAAU, 0x3EU, 0x82U, 0x01U, 0x4AU, 0x55U, 0xC6U, 0x93U, 0xB6U, 0x60U, 0xCFU, 0xBAU,
    0x90U, 0xF2U, 0xCEU, 0xDFU, 0x6AU, 0xD9U, 0x0AU, 0x71U, 0x1BU, 0x79U, 0xB2U, 0x4FU,
    0xF0U, 0xEBU, 0x22U, 0x23U, 0x94U, 0xF5U, 0x9BU, 0x67U,
};
static const uint8_t s_d1024_q[20] = {
    0xA2U, 0x00U, 0x60U, 0xB1U, 0xAFU, 0x90U, 0x2AU, 0x0FU, 0x92U, 0x9FU, 0xBDU, 0x11U,
    0x4BU, 0x65U, 0x92U, 0xF8U, 0xB0U, 0x4FU, 0x50U, 0x9FU,
};
static const uint8_t s_d1024_g[128] = {
    0x6AU, 0x71U, 0xE4U, 0xD5U, 0x50U, 0xE0U, 0xB6U, 0xCAU, 0x31U, 0x71U, 0x44U, 0x3CU,
    0x45U, 0x84U, 0xBEU, 0x57U, 0x25U, 0x62U, 0x86U, 0x5DU, 0x5AU, 0xDBU, 0x11U, 0x51U,
    0x43U, 0x82U, 0x39U, 0xEBU, 0xDAU, 0x27U, 0xD4U, 0x21U, 0x84U, 0x8EU, 0x12U, 0x44U,
    0xCEU, 0x87U, 0xE8U, 0xE1U, 0xFBU, 0x41U, 0x03U, 0xBAU, 0xA8U, 0xEDU, 0x26U, 0x80U,
    0x48U, 0x2EU, 0x51U, 0x47U, 0x9FU, 0xA5U, 0x17U, 0xAAU, 0xEEU, 0x39U, 0x33U, 0x77U,
    0x6DU, 0x40U, 0xD1U, 0x12U, 0x11U, 0x3AU, 0x94U, 0x10U, 0x78U, 0xD5U, 0x68U, 0x03U,
    0x48U, 0x81U, 0xF9U, 0xE0U, 0x91U, 0x70U, 0x06U, 0xFBU, 0x1FU, 0x7BU, 0x20U, 0x4BU,
    0x20U, 0x5BU, 0x8EU, 0x63U, 0x13U, 0x1FU, 0x77U, 0x88U, 0xCCU, 0x48U, 0xF3U, 0x1CU,
    0x1AU, 0x39U, 0xB8U, 0x27U, 0x98U, 0x56U, 0x2CU, 0x71U, 0x23U, 0x50U, 0xB8U, 0x20U,
    0x2EU, 0xE8U, 0x86U, 0xFDU, 0x69U, 0x40U, 0xDCU, 0x54U, 0xFEU, 0x3DU, 0x56U, 0x69U,
    0xC3U, 0x9BU, 0xEFU, 0x4CU, 0xDEU, 0x1DU, 0x49U, 0x02U,
};
static const uint8_t s_d1024_x[20] = {
    0x16U, 0xC2U, 0xBFU, 0x60U, 0xA6U, 0x29U, 0x15U, 0xC4U, 0x8FU, 0x6DU, 0x9AU, 0xA1U,
    0x89U, 0x6FU, 0x58U, 0x05U, 0xF7U, 0x9CU, 0x0BU, 0x8FU,
};
static const uint8_t s_d1024_y[128] = {
    0x42U, 0xC5U, 0x85U, 0x40U, 0x8DU, 0x68U, 0x22U, 0x2EU, 0xC6U, 0x4CU, 0xCAU, 0xB7U,
    0xB6U, 0xC7U, 0xEAU, 0xA5U, 0xB8U, 0x25U, 0x4EU, 0xF5U, 0xBDU, 0xE3U, 0x9BU, 0xF9U,
    0xB5U, 0xE1U, 0xD3U, 0x73U, 0x20U, 0xC4U, 0x68U, 0x24U, 0xACU, 0xF3U, 0xE3U, 0x96U,
    0xEFU, 0xF2U, 0x44U, 0x9FU, 0x37U, 0x8EU, 0x31U, 0xCFU, 0x92U, 0x4CU, 0x81U, 0xD8U,
    0xB8U, 0x2DU, 0xEEU, 0x57U, 0x9CU, 0xE8U, 0x98U, 0x00U, 0x4EU, 0x46U, 0xE1U, 0x1CU,
    0xFDU, 0xB7U, 0x76U, 0xC1U, 0xADU, 0xA1U, 0xE9U, 0x09U, 0x43U, 0x62U, 0x13U, 0x18U,
    0x71U, 0xDFU, 0x4FU, 0x72U, 0x4DU, 0x8EU, 0xC1U, 0xE8U, 0x0EU, 0x39U, 0xEAU, 0xCCU,
    0xD8U, 0x01U, 0xFAU, 0xBDU, 0xEAU, 0x92U, 0xDAU, 0x93U, 0x52U, 0x28U, 0xB4U, 0x9AU,
    0x30U, 0xB6U, 0xDDU, 0x59U, 0x01U, 0x44U, 0x13U, 0xEFU, 0xBBU, 0x18U, 0x2BU, 0x08U,
    0xBCU, 0x44U, 0x4CU, 0x27U, 0x48U, 0x86U, 0x01U, 0x3FU, 0x1EU, 0x31U, 0x33U, 0x93U,
    0x2BU, 0xFEU, 0x06U, 0x65U, 0x52U, 0x56U, 0x2DU, 0xC5U,
};
static const uint8_t s_d2048_p[256] = {
    0x80U, 0x4CU, 0xD6U, 0xD6U, 0x06U, 0xEBU, 0x05U, 0x5DU, 0xE0U, 0x2FU, 0xDCU, 0xD2U,
    0x7DU, 0x4CU, 0xDBU, 0x7EU, 0xAFU, 0x37U, 0x50U, 0xFAU, 0x80U, 0xB7U, 0x5CU, 0x40U,
    0x34U, 0x61U, 0x06U, 0xB1U, 0x7CU, 0xC6U, 0x1CU, 0x88U, 0xA6U, 0x5EU, 0xC1U, 0xD2U,
    0x0BU, 0x31U, 0xC2U, 0xFCU, 0x41U, 0x59U, 0x26U, 0xC3U, 0x63U, 0x0AU, 0xB7U, 0x98U,
    0x6AU, 0x8DU, 0xFEU, 0x98U, 0xE5U, 0x34U, 0xDDU, 0x65U, 0xF5U, 0x2BU, 0xCDU, 0x30U,
    0xFCU, 0x50U, 0x66U, 0x7FU, 0xFDU, 0xC8U, 0x68U, 0xD0U, 0x41U, 0x2FU, 0x1FU, 0x6EU,
    0xF6U, 0xE0U, 0x8FU, 0xC3U, 0xD5U, 0x65U, 0x30U, 0xF3U, 0xE3U, 0x2FU, 0x49U, 0x5CU,
    0x88U, 0x77U, 0x34U, 0x0DU, 0xA6U, 0x01U, 0xD5U, 0x61U, 0xE2U, 0x77U, 0x00U, 0xA7U,
    0x52U, 0x21U, 0x2EU, 0xD5U, 0x23U, 0xECU, 0x87U, 0xD6U, 0x2EU, 0xF6U, 0x1AU, 0x06U,
    0x50U, 0xB0U, 0x30U, 0x23U, 0x1EU, 0xEAU, 0x34U, 0xD7U, 0xE5U, 0x4DU, 0x09U, 0x87U,
    0x98U, 0x90U, 0xA6U, 0xD9U, 0x12U, 0x0BU, 0x56U, 0xFFU, 0x47U, 0xA7U, 0xFEU, 0xF9U,
    0x21U, 0x64U, 0xD1U, 0x4CU, 0xAFU, 0xCCU, 0xB4U, 0xF4U, 0xB8U, 0x21U, 0x5CU, 0x4DU,
    0xC3U, 0xCFU, 0xA8U, 0x7CU, 0x08U, 0x01U, 0xB2U, 0xBEU, 0xF6U, 0x25U, 0x24U, 0x38U,
    0x78U, 0x18U, 0x76U, 0x93U, 0xB7U, 0x1EU, 0x14U, 0x5EU, 0x20U, 0x91U, 0xC3U, 0x4BU,
    0xCEU, 0x27U, 0x7DU, 0xD0U, 0xD7U, 0x5CU, 0x32U, 0x98U, 0xA1U, 0xFFU, 0x67U, 0xB4U,
    0x62U, 0xCDU, 0xB6U, 0x70U, 0x25U, 0x3DU, 0x74U, 0x38U, 0xA3U, 0x33U, 0x26U, 0x08U,
    0xD6U, 0xC3U, 0x6BU, 0xE0U, 0x91U, 0xE7U, 0xD0U, 0x6EU, 0xBDU, 0x00U, 0x9DU, 0x10U,
    0x25U, 0x99U, 0xBCU, 0x66U, 0xC4U, 0xD6U, 0x01U, 0xD1U, 0xD2U, 0x0BU, 0x51U, 0x13U,
    0x55U, 0x50U, 0xCCU, 0x4EU, 0x88U, 0x19U, 0x96U, 0x27U, 0xB2U, 0x30U, 0x71U, 0x0BU,
    0x1DU, 0x25U, 0x32U, 0x8EU, 0xC3U, 0x9AU, 0xE2U, 0x68U, 0x97U, 0x1CU, 0xD0U, 0x22U,
    0x9EU, 0x25U, 0xD4U, 0x14U, 0x86U, 0x86U, 0xFBU, 0x0FU, 0x29U, 0x9DU, 0x4AU, 0xF2U,
    0xA1U, 0x26U, 0x5EU, 0x23U,
};
static const uint8_t s_d2048_q[32] = {
    0xDCU, 0xF1U, 0x84U, 0x5EU, 0xDFU, 0xB0U, 0xE7U, 0xBAU, 0xEDU, 0xA9U, 0x4FU, 0x5AU,
    0xF7U, 0xF1U, 0x95U, 0xA6U, 0x3CU, 0xDDU, 0x28U, 0xAAU, 0x7EU, 0xE5U, 0xA4U, 0x51U,
    0x8BU, 0x20U, 0xE0U, 0xF1U, 0x80U, 0xB8U, 0x49U, 0x13U,
};
static const uint8_t s_d2048_g[256] = {
    0x3FU, 0x14U, 0x48U, 0x12U, 0xF3U, 0x0AU, 0x2BU, 0xA2U, 0x19U, 0x30U, 0x6DU, 0xFAU,
    0x96U, 0x8BU, 0xA2U, 0x06U, 0x86U, 0x95U, 0xAEU, 0x05U, 0x0BU, 0xA1U, 0xADU, 0x67U,
    0x93U, 0x32U, 0x3AU, 0x93U, 0x61U, 0x0EU, 0x5EU, 0xFCU, 0x46U, 0xABU, 0x0DU, 0x5FU,
    0x86U, 0x66U, 0xAAU, 0xC2U, 0x18U, 0x69U, 0xF2U, 0x8BU, 0x73U, 0x6DU, 0x42U, 0x16U,
    0xAAU, 0x32U, 0xA5U, 0x30U, 0x76U, 0xB2U, 0xF3U, 0xF5U, 0x2AU, 0x71U, 0xD1U, 0xBAU,
    0xA6U, 0x33U, 0x13U, 0x2CU, 0xF6U, 0xBFU, 0x85U, 0xB2U, 0x90U, 0x38U, 0xDEU, 0x58U,
    0xD9U, 0xF9U, 0x9CU, 0x73U, 0x23U, 0x39U, 0xF6U, 0xF6U, 0x54U, 0x26U, 0x1CU, 0xA5U,
    0x30U, 0x70U, 0x1AU, 0x4AU, 0x0FU, 0x5DU, 0x36U, 0x46U, 0x99U, 0x2EU, 0x21U, 0x92U,
    0xEFU, 0xBEU, 0x21U, 0x1AU, 0xBBU, 0x8EU, 0x76U, 0x28U, 0xFAU, 0x8BU, 0xA4U, 0x46U,
    0x45U, 0xF6U, 0x34U, 0x7CU, 0x42U, 0x93U, 0x6AU, 0xF6U, 0x69U, 0xECU, 0x74U, 0xD7U,
    0xDFU, 0x45U, 0x7BU, 0x62U, 0x7AU, 0x13U, 0xAFU, 0xB5U, 0x7CU, 0x5DU, 0x4BU, 0x11U,
    0xFEU, 0xD0U, 0x7BU, 0x57U, 0x67U, 0xABU, 0x16U, 0x6AU, 0xD5U, 0xFDU, 0x5AU, 0xAEU,
    0xF0U, 0x3AU, 0x13U, 0xCDU, 0x07U, 0xFFU, 0xA0U, 0x34U, 0xCEU, 0x4DU, 0x2EU, 0x02U,
    0xEDU, 0x0DU, 0x18U, 0x7FU, 0xADU, 0xC4U, 0x3CU, 0x12U, 0xF2U, 0x1CU, 0x47U, 0xB2U,
    0x52U, 0x5EU, 0x2AU, 0x7BU, 0x62U, 0xC0U, 0x09U, 0x8BU, 0x07U, 0x70U, 0x57U, 0xAAU,
    0xAAU, 0xA9U, 0xA6U, 0xD1U, 0x01U, 0xA1U, 0x05U, 0xD0U, 0x31U, 0x83U, 0xB7U, 0x2AU,
    0xEDU, 0xC0U, 0xA9U, 0x76U, 0x5AU, 0xC8U, 0xA8U, 0x64U, 0x39U, 0x8FU, 0xFEU, 0xCEU,
    0xE9U, 0xDCU, 0x80U, 0x55U, 0xBBU, 0xA5U, 0x4DU, 0x6CU, 0x5DU, 0xF0U, 0x10U, 0xDBU,
    0x74U, 0xB0U, 0x03U, 0x3FU, 0xABU, 0x00U, 0xC0U, 0x23U, 0xB5U, 0xC8U, 0xF1U, 0x40U,
    0xA8U, 0xE4U, 0x0EU, 0xD8U, 0xE2U, 0x40U, 0x76U, 0xC4U, 0xF9U, 0xDEU, 0x29U, 0x33U,
    0x5FU, 0x1EU, 0xCCU, 0x34U, 0x80U, 0x9DU, 0x2BU, 0xF7U, 0x73U, 0xB2U, 0xA8U, 0x15U,
    0x9EU, 0x36U, 0x3AU, 0x11U,
};
static const uint8_t s_d2048_x[32] = {
    0x7AU, 0x16U, 0x01U, 0x79U, 0xBAU, 0xB5U, 0xF4U, 0x15U, 0x82U, 0x3EU, 0x02U, 0x41U,
    0xE0U, 0x9FU, 0xE5U, 0x58U, 0xDEU, 0x59U, 0x04U, 0x09U, 0xF4U, 0x09U, 0x48U, 0xB4U,
    0xEDU, 0x6DU, 0x34U, 0xB4U, 0x01U, 0xE6U, 0x7DU, 0xCDU,
};
static const uint8_t s_d2048_y[256] = {
    0x49U, 0xE9U, 0x22U, 0x86U, 0x7AU, 0x30U, 0xF7U, 0x7DU, 0xC7U, 0xB0U, 0xE3U, 0x77U,
    0x0EU, 0xE4U, 0x20U, 0xD2U, 0x72U, 0x4DU, 0xD6U, 0x27U, 0x1EU, 0x7CU, 0x47U, 0xB3U,
    0xD2U, 0x8FU, 0xB7U, 0xEEU, 0xADU, 0x16U, 0x98U, 0x9DU, 0x73U, 0x10U, 0x29U, 0xFAU,
    0xC5U, 0x46U, 0x40U, 0xACU, 0x1DU, 0x34U, 0xAAU, 0x92U, 0xC0U, 0x6FU, 0x09U, 0x0AU,
    0x57U, 0xFDU, 0x7DU, 0xF0U, 0x61U, 0x53U, 0xAEU, 0x8EU, 0x86U, 0x19U, 0x61U, 0x94U,
    0xFCU, 0x7DU, 0xD6U, 0x4DU, 0xB7U, 0x6AU, 0x1CU, 0x2AU, 0x20U, 0xA4U, 0x7FU, 0x67U,
    0xD1U, 0xB1U, 0x10U, 0x2EU, 0x2AU, 0xB7U, 0x5EU, 0xD9U, 0xAFU, 0x95U, 0xB8U, 0x70U,
    0xD0U, 0xA7U, 0xE0U, 0x1AU, 0x1AU, 0x92U, 0x28U, 0x0BU, 0x71U, 0x5BU, 0xA6U, 0xABU,
    0x71U, 0x4FU, 0xC3U, 0x2EU, 0x55U, 0x03U, 0x82U, 0xE6U, 0x6EU, 0xF6U, 0xFDU, 0xE1U,
    0xE0U, 0xF6U, 0x60U, 0x4AU, 0x0EU, 0x77U, 0x29U, 0x0CU, 0xFCU, 0x04U, 0x78U, 0x74U,
    0x50U, 0x73U, 0x24U, 0x2DU, 0xBEU, 0xF4U, 0x3FU, 0x9FU, 0xBBU, 0x16U, 0x47U, 0x98U,
    0x07U, 0xC3U, 0xF3U, 0xD5U, 0x08U, 0xDBU, 0x1AU, 0xACU, 0xC1U, 0xA2U, 0xA6U, 0xFFU,
    0xA0U, 0x61U, 0x10U, 0x56U, 0x35U, 0x92U, 0x28U, 0x86U, 0xC1U, 0x78U, 0x63U, 0x24U,
    0x0EU, 0xC5U, 0x96U, 0xE6U, 0x73U, 0x65U, 0x96U, 0x25U, 0x46U, 0x45U, 0x56U, 0xECU,
    0x85U, 0xABU, 0x96U, 0x38U, 0xECU, 0x56U, 0xF5U, 0xD3U, 0x5FU, 0x9CU, 0x2BU, 0xC6U,
    0x70U, 0x29U, 0xFAU, 0x3FU, 0x45U, 0xECU, 0x63U, 0xC2U, 0x97U, 0x4AU, 0x3DU, 0x66U,
    0x94U, 0xF6U, 0xA8U, 0xDCU, 0x5DU, 0xBCU, 0x72U, 0x05U, 0x53U, 0x93U, 0x46U, 0xEAU,
    0x47U, 0x15U, 0xA2U, 0x11U, 0x75U, 0x5AU, 0x84U, 0x24U, 0x09U, 0xAEU, 0xF2U, 0xEAU,
    0x34U, 0x37U, 0xC5U, 0x0EU, 0x25U, 0xACU, 0x7DU, 0x32U, 0xE8U, 0x1FU, 0xD3U, 0x16U,
    0xE6U, 0x0CU, 0x6BU, 0xC3U, 0xE6U, 0xBCU, 0xB1U, 0x6BU, 0xBDU, 0x18U, 0x69U, 0xE4U,
    0x19U, 0x90U, 0x48U, 0x48U, 0xDFU, 0x52U, 0x67U, 0x78U, 0x90U, 0x2EU, 0x43U, 0x9EU,
    0x56U, 0xC7U, 0x4BU, 0xB6U,
};

static void dsa_round_trip(const char *name, const uint8_t *p, uint32_t p_len, const uint8_t *q, uint32_t q_len,
                           const uint8_t *g, const uint8_t *x, const uint8_t *y)
{
    dsa_key_t key;
    dsa_signature_t sig;
    uint8_t msg[32];
    char what[128];
    int i;
    int ok = 1;

    if(!check(noxtls_dsa_key_init(&key, p, p_len, q, q_len, g, p_len) == NOXTLS_RETURN_SUCCESS, "dsa_key_init")) {
        return;
    }
    (void)check(noxtls_dsa_key_set_private(&key, x) == NOXTLS_RETURN_SUCCESS, "dsa_key_set_private");
    (void)check(noxtls_dsa_key_set_public(&key, y) == NOXTLS_RETURN_SUCCESS, "dsa_key_set_public");
    for(i = 0; i < 12; i += 1) {
        rnd_fill(msg, sizeof(msg));
        (void)noxtls_dsa_signature_init(&sig, q_len);
        if((noxtls_dsa_sign(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) ||
           (noxtls_dsa_verify(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS)) {
            ok = 0;
        }
        msg[0] ^= 1U;
        if(noxtls_dsa_verify(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS) {
            ok = 0;
        }
    }
    (void)snprintf(what, sizeof(what), "DSA %s sign/verify round trips", name);
    (void)check(ok, what);
    /* generated key: y = g^x through the constant-time reduction / exponentiation */
    if(check(noxtls_dsa_key_generate(&key) == NOXTLS_RETURN_SUCCESS, "dsa_key_generate")) {
        rnd_fill(msg, sizeof(msg));
        (void)noxtls_dsa_signature_init(&sig, q_len);
        (void)snprintf(what, sizeof(what), "DSA %s generated key round trip", name);
        (void)check((noxtls_dsa_sign(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS) &&
                    (noxtls_dsa_verify(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) == NOXTLS_RETURN_SUCCESS), what);
    }
    (void)noxtls_dsa_key_free(&key);
}

static void test_dsa(void)
{
    dsa_round_trip("1024/160", s_d1024_p, 128U, s_d1024_q, 20U, s_d1024_g, s_d1024_x, s_d1024_y);
    dsa_round_trip("2048/256", s_d2048_p, 256U, s_d2048_q, 32U, s_d2048_g, s_d2048_x, s_d2048_y);
    test_mod_exp_no_trim(s_d1024_p, 128U);
    test_mod_exp_no_trim(s_d2048_p, 256U);
}
#endif /* NOXTLS_FEATURE_DSA */

#if NOXTLS_FEATURE_RSA
static void test_rsa_public_validation(void)
{
    uint8_t n[256];
    rsa_key_t k;
    const uint8_t e65537[3] = { 0x01U, 0x00U, 0x01U };
    const uint8_t e3[1] = { 3U };
    const uint8_t e1[1] = { 1U };
    const uint8_t e_even[3] = { 0x01U, 0x00U, 0x02U };
    uint8_t e_big[9];
    uint8_t e_max[10];

    (void)memset(e_big, 0xFF, sizeof(e_big));
    (void)memset(e_max, 0xFF, sizeof(e_max));
    e_max[0] = 0U;
    e_max[1] = 0U;   /* 8 significant bytes after leading zeros: accepted */
    rnd_fill(n, sizeof(n));
    n[0] |= 0x80U;
    n[255] |= 1U;
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e65537, 3U) == NOXTLS_RETURN_SUCCESS, "init_public: odd n, e = 65537");
    (void)noxtls_rsa_key_free(&k);
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e3, 1U) == NOXTLS_RETURN_SUCCESS, "init_public: e = 3");
    (void)noxtls_rsa_key_free(&k);
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e_max, 10U) == NOXTLS_RETURN_SUCCESS, "init_public: 64-bit e");
    (void)noxtls_rsa_key_free(&k);
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e1, 1U) == NOXTLS_RETURN_INVALID_PARAM, "init_public: e = 1 rejected");
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e_even, 3U) == NOXTLS_RETURN_INVALID_PARAM, "init_public: even e rejected");
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e_big, 9U) == NOXTLS_RETURN_INVALID_PARAM, "init_public: 72-bit e rejected");
    n[255] &= 0xFEU;
    (void)check(noxtls_rsa_key_init_public(&k, RSA_2048_BIT, n, 256U, e65537, 3U) == NOXTLS_RETURN_INVALID_PARAM, "init_public: even n rejected");
}

static int all_bytes(const uint8_t *b, uint32_t n, uint8_t v)
{
    uint32_t i;
    for(i = 0U; i < n; i += 1U) {
        if(b[i] != v) { return 0; }
    }
    return 1;
}

static void test_rsa_keygen_and_unpad(void)
{
    rsa_key_t key;
    int i;
    int len_ok = 1;

    for(i = 0; i < 3; i += 1) {
        if(!check(noxtls_rsa_key_generate(&key, RSA_1024_BIT) == NOXTLS_RETURN_SUCCESS, "rsa_key_generate 1024")) {
            (void)noxtls_rsa_key_free(&key);
            return;
        }
        if(((key.n[0] & 0x80U) == 0U) || ((key.p[0] & 0xC0U) != 0xC0U) || ((key.q[0] & 0xC0U) != 0xC0U)) {
            len_ok = 0;
        }
        if(i < 2) {
            (void)noxtls_rsa_key_free(&key);
        }
    }
    (void)check(len_ok, "rsa_key_generate: n has the full requested bit length, p and q top two bits set");

    {
        uint8_t msg[48];
        uint8_t ct[128];
        uint8_t pt[64];
        uint8_t block[128];
        uint32_t ct_len = sizeof(ct);
        uint32_t pt_len = 0U;
        uint32_t j;

        rnd_fill(msg, sizeof(msg));
        (void)check(noxtls_rsa_encrypt(&key, msg, 48U, ct, &ct_len) == NOXTLS_RETURN_SUCCESS, "rsa_encrypt 48");
        pt_len = 48U;
        (void)check((noxtls_rsa_decrypt(&key, ct, ct_len, pt, &pt_len) == NOXTLS_RETURN_SUCCESS) && (pt_len == 48U) &&
                    (memcmp(pt, msg, 48U) == 0), "rsa_decrypt 48 into 48");
        /* message longer than the output buffer: fails, len 0, buffer zeroed */
        (void)memset(pt, 0xAA, sizeof(pt));
        pt_len = 47U;
        (void)check(noxtls_rsa_decrypt(&key, ct, ct_len, pt, &pt_len) == NOXTLS_RETURN_FAILED, "rsa_decrypt 48 into 47 fails");
        (void)check((pt_len == 0U) && all_bytes(pt, 47U, 0U) && all_bytes(&pt[47], 17U, 0xAAU),
                    "rsa_decrypt too small: zeros written, length 0, nothing past the buffer");
        /* short message into a large buffer: message then zeros */
        ct_len = sizeof(ct);
        (void)check(noxtls_rsa_encrypt(&key, msg, 10U, ct, &ct_len) == NOXTLS_RETURN_SUCCESS, "rsa_encrypt 10");
        (void)memset(pt, 0xAA, sizeof(pt));
        pt_len = 48U;
        (void)check((noxtls_rsa_decrypt(&key, ct, ct_len, pt, &pt_len) == NOXTLS_RETURN_SUCCESS) && (pt_len == 10U) &&
                    (memcmp(pt, msg, 10U) == 0) && all_bytes(&pt[10], 38U, 0U) && all_bytes(&pt[48], 16U, 0xAAU),
                    "rsa_decrypt 10 into 48: message then zeros");
        /* buffer larger than key_bytes - 11: only key_bytes - 11 bytes written */
        {
            uint8_t big[140];
            (void)memset(big, 0xAA, sizeof(big));
            pt_len = (uint32_t)sizeof(big);
            (void)check((noxtls_rsa_decrypt(&key, ct, ct_len, big, &pt_len) == NOXTLS_RETURN_SUCCESS) && (pt_len == 10U) &&
                        (memcmp(big, msg, 10U) == 0) && all_bytes(&big[10], 117U - 10U, 0U) && all_bytes(&big[117], 140U - 117U, 0xAAU),
                        "rsa_decrypt into oversized buffer writes key_bytes - 11 bytes");
        }
        /* empty message */
        ct_len = sizeof(ct);
        pt_len = 48U;
        (void)check((noxtls_rsa_encrypt(&key, msg, 0U, ct, &ct_len) == NOXTLS_RETURN_SUCCESS) &&
                    (noxtls_rsa_decrypt(&key, ct, ct_len, pt, &pt_len) == NOXTLS_RETURN_SUCCESS) && (pt_len == 0U),
                    "rsa_decrypt empty message");
        /* invalid padding blocks: type 1, missing separator, short padding */
        for(j = 0U; j < 3U; j += 1U) {
            (void)memset(block, 0x5C, sizeof(block));
            block[0] = 0x00U;
            block[1] = 0x02U;
            if(j == 0U) { block[1] = 0x01U; block[100] = 0U; }   /* wrong block type */
            if(j == 2U) { block[5] = 0U; }                       /* only 3 padding bytes */
            (void)check(noxtls_bn_mod_exp_public(ct, block, key.e, key.e_len, key.n, 128U) == NOXTLS_RETURN_SUCCESS, "raw RSA encrypt");
            (void)memset(pt, 0xAA, sizeof(pt));
            pt_len = 48U;
            (void)check((noxtls_rsa_decrypt(&key, ct, 128U, pt, &pt_len) == NOXTLS_RETURN_FAILED) && (pt_len == 0U) &&
                        all_bytes(pt, 48U, 0U), "rsa_decrypt bad padding: fails, length 0, buffer zeroed");
        }
        /* hand-built key with an absurd exponent is refused before exponentiation */
        {
            uint8_t *e_saved = key.e;
            uint32_t e_len_saved = key.e_len;
            uint8_t e_huge[128];
            (void)memset(e_huge, 0xFF, sizeof(e_huge));
            key.e = e_huge;
            key.e_len = 128U;
            ct_len = sizeof(ct);
            (void)check(noxtls_rsa_encrypt(&key, msg, 10U, ct, &ct_len) == NOXTLS_RETURN_INVALID_PARAM, "rsa_encrypt: 1024-bit e refused");
            key.e = e_saved;
            key.e_len = e_len_saved;
        }
    }
    (void)noxtls_rsa_key_free(&key);
}
#endif /* NOXTLS_FEATURE_RSA */

#if NOXTLS_FEATURE_ECDSA
static void ecdsa_round_trip(const char *name, ecc_curve_t id, uint32_t size)
{
    ecc_key_t key;
    ecdsa_signature_t sig;
    uint8_t msg[32];
    char what[96];
    int i;
    int ok = 1;

    if(!check(noxtls_ecc_key_generate(&key, id) == NOXTLS_RETURN_SUCCESS, "ecc_key_generate")) {
        return;
    }
    for(i = 0; i < 6; i += 1) {
        rnd_fill(msg, sizeof(msg));
        (void)noxtls_ecdsa_signature_init(&sig, size);
        if((noxtls_ecdsa_sign(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS) ||
           (noxtls_ecdsa_verify(&key, msg, sizeof(msg), &sig, NOXTLS_HASH_SHA_256) != NOXTLS_RETURN_SUCCESS)) {
            ok = 0;
        }
    }
    (void)snprintf(what, sizeof(what), "ECDSA %s sign/verify round trips", name);
    (void)check(ok, what);
    (void)noxtls_ecc_key_free(&key);
}
#endif

int main(void)
{
    test_bn_mod_ct();
    test_mod_inv_prime_ct();
#if NOXTLS_FEATURE_DSA
    test_dsa();
#endif
#if NOXTLS_FEATURE_RSA
    test_rsa_public_validation();
    test_rsa_keygen_and_unpad();
#endif
#if NOXTLS_FEATURE_ECDSA
#if NOXTLS_ECC_ENABLE_SECP384R1
    ecdsa_round_trip("P-384", NOXTLS_ECC_SECP384R1, 48U);
#endif
#if NOXTLS_ECC_ENABLE_SECP521R1
    ecdsa_round_trip("P-521", NOXTLS_ECC_SECP521R1, 66U);
#endif
#endif
    (void)printf("bignum_ct_audit_test: %d checks, %d failures\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
