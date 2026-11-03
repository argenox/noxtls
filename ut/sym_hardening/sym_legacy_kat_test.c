/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    sym_legacy_kat_test.c
* Summary: Known answers for DES/3DES (branch-free bit handling and
*          table-scan S-boxes) and RC4 (table or constant-time state access,
*          NOXTLS_LEGACY_CIPHER_CONSTANT_TIME), plus the built-in self tests.
*****************************************************************************/
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#if NOXTLS_FEATURE_DES
#include "encryption/des/noxtls_des.h"
#endif
#if NOXTLS_FEATURE_RC4
#include "encryption/rc4/noxtls_rc4.h"
#endif

#include "crypto_sym_test_util.h"

#if NOXTLS_FEATURE_DES
static void test_des(void)
{
    static const struct { const char *key; const char *pt; const char *ct; } v[] = {
        { "133457799bbcdff1", "0123456789abcdef", "85e813540f0ab405" },
        { "0e329232ea6d0d73", "8787878787878787", "0000000000000000" },
    };
    uint32_t i;
    cs_section("DES known answers");
    for (i = 0U; i < 2U; i += 1U) {
        uint8_t key[8];
        uint8_t pt[8];
        uint8_t out[8];
        (void)cs_hex(v[i].key, key, sizeof(key));
        (void)cs_hex(v[i].pt, pt, sizeof(pt));
        CHECK_RC(noxtls_des_encrypt_block(key, pt, out), NOXTLS_RETURN_SUCCESS);
        EXPECT_HEX("des encrypt", out, 8U, v[i].ct);
        CHECK_RC(noxtls_des_decrypt_block(key, out, out), NOXTLS_RETURN_SUCCESS);
        EXPECT_MEM("des decrypt", out, pt, 8U);
    }
    CHECK_RC(noxtls_des_self_test(), NOXTLS_RETURN_SUCCESS);

    cs_section("3DES: K1=K2=K3 equals DES, random keys round-trip");
    {
        uint8_t k3[24];
        uint8_t pt[8];
        uint8_t a[8];
        uint8_t b[8];
        uint32_t n;
        (void)cs_hex("133457799bbcdff1133457799bbcdff1133457799bbcdff1", k3, sizeof(k3));
        (void)cs_hex("0123456789abcdef", pt, sizeof(pt));
        CHECK_RC(noxtls_des3_encrypt_block(k3, 24U, pt, a), NOXTLS_RETURN_SUCCESS);
        EXPECT_HEX("3des degenerate", a, 8U, "85e813540f0ab405");
        for (n = 0U; n < 200U; n += 1U) {
            cs_fill(k3, sizeof(k3), 0x3DE5U + n);
            cs_fill(pt, sizeof(pt), 0x9000U + n);
            CHECK_RC(noxtls_des3_encrypt_block(k3, 24U, pt, a), NOXTLS_RETURN_SUCCESS);
            CHECK_RC(noxtls_des3_decrypt_block(k3, 24U, a, b), NOXTLS_RETURN_SUCCESS);
            if (!EXPECT_MEM("3des round trip", b, pt, 8U)) {
                break;
            }
        }
    }
}
#endif

#if NOXTLS_FEATURE_RC4
static void test_rc4(void)
{
    static const struct { const char *key; const char *pt; const char *ct; } v[] = {
        { "Key", "Plaintext", "bbf316e8d940af0ad3" },
        { "Wiki", "pedia", "1021bf0420" },
        { "Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5" },
    };
    uint32_t i;
    cs_section("RC4 known answers");
    for (i = 0U; i < 3U; i += 1U) {
        uint8_t out[32];
        uint32_t len = (uint32_t)strlen(v[i].pt);
        CHECK_RC(noxtls_rc4_encrypt((const uint8_t *)v[i].key, (uint32_t)strlen(v[i].key),
                                    (const uint8_t *)v[i].pt, len, out), NOXTLS_RETURN_SUCCESS);
        EXPECT_HEX("rc4", out, len, v[i].ct);
    }
    CHECK_RC(noxtls_rc4_self_test(), NOXTLS_RETURN_SUCCESS);
}
#endif

int main(void)
{
#if NOXTLS_FEATURE_DES
    test_des();
#endif
#if NOXTLS_FEATURE_RC4
    test_rc4();
#endif
    (void)printf("sym_legacy_kat_test: %u checks, %u failures\n", (unsigned)g_cs_checks, (unsigned)g_cs_failures);
    return (g_cs_failures == 0U) ? 0 : 1;
}
