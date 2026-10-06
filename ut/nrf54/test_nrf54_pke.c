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
* File:    test_nrf54_pke.c
* Summary: Tests of the BA414EP backend and the NoxTLS ECC / ECDSA / Ed25519 ports
*
*****************************************************************************/

/**
 * @file test_nrf54_pke.c
 * @brief ECDSA P-256 (RFC 6979 §A.2.5) and Ed25519 (RFC 8032 §7.1) verification
 *        through the NoxTLS API on the mocked BA414EP: operand layout, COMMAND
 *        words, rejection, software fallback on engine errors, microcode
 *        handling per chip, operand-memory wipe, interrupt handling and the
 *        P-256 point-multiply port with its double check.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"
#include "ut_nrf54_vectors.h"
#include "noxtls_ecc.h"
#include "noxtls_ecdsa.h"
#include "noxtls_ecdsa_accel_port.h"
#include "ed25519/noxtls_ed25519.h"
#include "drbg/noxtls_drbg.h"

/** Point-multiply port (declared by noxtls_ecc.c, implemented by the nRF54 port). */
noxtls_return_t noxtls_ecc_point_multiply_accel_port(ecc_point_t *result, const uint8_t *scalar, const ecc_point_t *point,
                                                      const ecc_curve_params_t *curve);

/** COMMAND of an ECDSA P-256 verification. */
#define UT_CMD_ECDSA  (NOXTLS_NRF54_PK_OP_ECDSA_VERIFY | NOXTLS_NRF54_PK_FLAG_BIG_ENDIAN | NOXTLS_NRF54_PK_CURVE_P256 | \
                       (31U << NOXTLS_NRF54_PK_OPSZ_POS))

/** P-256 test key and signature. */
static ecc_key_t s_key;
static ecdsa_signature_t s_sig;
static uint8_t s_pub[64];

/**
 * @brief Load the RFC 6979 key and the "sample" signature.
 */
static void ut_ecdsa_load(void)
{
    if (s_key.curve == NULL) {
        (void)noxtls_ecc_key_init(&s_key, NOXTLS_ECC_SECP256R1);
    }
    (void)ut_hex(UT_P256_PUB, s_pub, sizeof(s_pub));
    (void)memcpy(s_key.Q.x, s_pub, 32U);
    (void)memcpy(s_key.Q.y, &s_pub[32], 32U);
    s_key.Q.size = 32U;
    (void)memset(&s_sig, 0, sizeof(s_sig));
    (void)ut_hex(UT_P256_SIG_SAMPLE, s_sig.r, 32U);
    (void)ut_hex(&UT_P256_SIG_SAMPLE[64], s_sig.s, 32U);
    s_sig.size = 32U;
}

/**
 * @brief Verify "sample" through NoxTLS.
 *
 * @return NoxTLS result.
 */
static noxtls_return_t ut_ecdsa_verify(void)
{
    return noxtls_ecdsa_verify(&s_key, (const uint8_t *)"sample", 6U, &s_sig, NOXTLS_HASH_SHA_256);
}

REGISTER_TEST(test_pke_ecdsa_layout_and_results)
{
    uint8_t h[32];
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        uint32_t rejects;
        uint32_t errors;

        ut_setup(chip);
        rejects = noxtls_nrf54_pke_stats()->rejects;
        errors = noxtls_nrf54_pke_stats()->errors;
        ut_ecdsa_load();
        UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.pk_cmd, UT_CMD_ECDSA);
        UTNOX_EQUALS(memcmp(ut_pk_be(NOXTLS_NRF54_PK_SLOT_ECDSA_QX), s_pub, 32U), 0);
        UTNOX_EQUALS(memcmp(ut_pk_be(NOXTLS_NRF54_PK_SLOT_ECDSA_QY), &s_pub[32], 32U), 0);
        UTNOX_EQUALS(memcmp(ut_pk_be(NOXTLS_NRF54_PK_SLOT_ECDSA_R), s_sig.r, 32U), 0);
        UTNOX_EQUALS(memcmp(ut_pk_be(NOXTLS_NRF54_PK_SLOT_ECDSA_S), s_sig.s, 32U), 0);
        (void)ut_hex(UT_P256_H_SAMPLE, h, sizeof(h));
        UTNOX_EQUALS(memcmp(ut_pk_be(NOXTLS_NRF54_PK_SLOT_ECDSA_H), h, 32U), 0);
        UTNOX_EQUALS(ut_pk_wiped(), 1U);
        UTNOX_EQUALS(g_ut.pk_clears, (chip == 0U) ? 1U : 0U);
        /* Engine rejection is final. */
        g_ut.pk_status_bits = NOXTLS_NRF54_PK_ST_BAD_SIGNATURE;
        UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(noxtls_nrf54_pke_stats()->rejects - rejects, 1U);
        /* Engine error: NoxTLS verifies in software (valid signature, then a corrupted one). */
        g_ut.pk_status_bits = NOXTLS_NRF54_PK_ST_NOT_IMPL;
        UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
        s_sig.s[31] ^= 0x01U;
        UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_FAILED);
        UTNOX_EQUALS(noxtls_nrf54_pke_stats()->errors - errors, 2U);
        g_ut.pk_status_bits = 0U;
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    /* Port arguments. */
    ut_ecdsa_load();
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(NULL, h, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, NULL, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, h, 32U, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, h, 48U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&s_key, h, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    s_key.curve->size = 48U;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&s_key, h, 32U, &s_sig), NOXTLS_RETURN_NOT_SUPPORTED);
    s_key.curve->size = 32U;
    UTNOX_EQUALS(noxtls_nrf54_pke_ecdsa_p256_verify(NULL, h, h, h, h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_ecdsa_p256_verify(h, NULL, h, h, h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_ecdsa_p256_verify(h, h, NULL, h, h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_ecdsa_p256_verify(h, h, h, NULL, h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_ecdsa_p256_verify(h, h, h, h, NULL), NOXTLS_RETURN_NULL);
    return 0;
}

REGISTER_TEST(test_pke_ed25519_layout_and_results)
{
    uint8_t pub[32];
    uint8_t msg[4];
    uint8_t sig[64];
    uint8_t ra[128];
    uint8_t k[64];
    uint8_t y[32];
    uint32_t mlen;
    uint32_t i;
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        if (chip == 0U) {
            ut_port_irq();
        }
        for (i = 0U; i < UT_ED25519_VECS; i++) {
            uint32_t flags = 0U;

            (void)ut_hex(s_ut_ed25519_vecs[i].pub, pub, sizeof(pub));
            mlen = ut_hex(s_ut_ed25519_vecs[i].msg, msg, sizeof(msg));
            (void)ut_hex(s_ut_ed25519_vecs[i].sig, sig, sizeof(sig));
            UTNOX_EQUALS(noxtls_ed25519_verify(pub, msg, mlen, sig), NOXTLS_RETURN_SUCCESS);
            /* k = SHA-512(R || A || M), RFC 8032 §5.1.7 step 2. */
            (void)memcpy(ra, sig, 32U);
            (void)memcpy(&ra[32], pub, 32U);
            (void)memcpy(&ra[64], msg, mlen);
            ut_sha(512U, ra, 64U + mlen, k);
            UTNOX_EQUALS(memcmp(ut_pk_le(NOXTLS_NRF54_PK_SLOT_ED_K), k, 32U), 0);
            UTNOX_EQUALS(memcmp(ut_pk_le(NOXTLS_NRF54_PK_SLOT_ED_K + 1U), &k[32], 32U), 0);
            (void)memcpy(y, pub, 32U);
            y[31] &= 0x7FU;
            UTNOX_EQUALS(memcmp(ut_pk_le(NOXTLS_NRF54_PK_SLOT_ED_AY), y, 32U), 0);
            (void)memcpy(y, sig, 32U);
            y[31] &= 0x7FU;
            UTNOX_EQUALS(memcmp(ut_pk_le(NOXTLS_NRF54_PK_SLOT_ED_RY), y, 32U), 0);
            UTNOX_EQUALS(memcmp(ut_pk_le(NOXTLS_NRF54_PK_SLOT_ED_S), &sig[32], 32U), 0);
            if ((pub[31] & 0x80U) != 0U) {
                flags |= NOXTLS_NRF54_PK_FLAG_ED_AX_ODD;
            }
            if ((sig[31] & 0x80U) != 0U) {
                flags |= NOXTLS_NRF54_PK_FLAG_ED_RX_ODD;
            }
            UTNOX_EQUALS(g_ut.pk_cmd, NOXTLS_NRF54_PK_OP_EDDSA_VERIFY | NOXTLS_NRF54_PK_CURVE_ED25519 |
                         (31U << NOXTLS_NRF54_PK_OPSZ_POS) | flags);
            UTNOX_EQUALS(ut_pk_wiped(), 1U);
        }
        /* Rejection; then an engine error with a valid and a bit-flipped signature (software decides). */
        g_ut.pk_status_bits = NOXTLS_NRF54_PK_ST_BAD_SIGNATURE;
        UTNOX_EQUALS(noxtls_ed25519_verify(pub, msg, mlen, sig), NOXTLS_RETURN_FAILED);
        g_ut.pk_status_bits = NOXTLS_NRF54_PK_ST_BAD_CURVE;
        UTNOX_EQUALS(noxtls_ed25519_verify(pub, msg, mlen, sig), NOXTLS_RETURN_SUCCESS);
        sig[5] ^= 0x10U;
        UTNOX_EQUALS(noxtls_ed25519_verify(pub, msg, mlen, sig), NOXTLS_RETURN_FAILED);
        g_ut.pk_status_bits = 0U;
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    /* Stream / split API (the runtime verifier) uses the same hook. */
    ut_setup(0U);
    (void)ut_hex(s_ut_ed25519_vecs[2].pub, pub, sizeof(pub));
    (void)ut_hex(s_ut_ed25519_vecs[2].sig, sig, sizeof(sig));
    (void)ut_hex(s_ut_ed25519_vecs[2].msg, msg, sizeof(msg));
    UTNOX_EQUALS(noxtls_ed25519_verify_split(pub, msg, 1U, &msg[1], 1U, sig), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_starts, 2U);
    /* Non-canonical R: rejected without the engine. Non-canonical A: software decides. */
    (void)memset(ra, 0xFF, 32U);
    ra[0] = 0xEDU;
    ra[31] = 0x7FU;
    (void)memcpy(&ra[32], &sig[32], 32U);
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(pub, ra, k), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(ra, sig, k), NOXTLS_RETURN_NOT_SUPPORTED);
    ra[0] = 0xECU;
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(ra, sig, k), NOXTLS_RETURN_SUCCESS);
    ra[31] = 0x7EU;
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(ra, sig, k), NOXTLS_RETURN_SUCCESS);
    ra[31] = 0x7FU;
    ra[5] = 0x00U;
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(ra, sig, k), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(NULL, sig, k), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(pub, NULL, k), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ed25519_verify_accel_port(pub, sig, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Odd x of A: flag bit 29 (the mock does not check the math). */
    pub[31] |= 0x80U;
    UTNOX_EQUALS(noxtls_nrf54_pke_ed25519_verify(pub, sig, k), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_cmd & NOXTLS_NRF54_PK_FLAG_ED_AX_ODD, NOXTLS_NRF54_PK_FLAG_ED_AX_ODD);
    UTNOX_EQUALS(noxtls_nrf54_pke_ed25519_verify(NULL, sig, k), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_ed25519_verify(pub, NULL, k), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_ed25519_verify(pub, sig, NULL), NOXTLS_RETURN_NULL);
    return 0;
}

REGISTER_TEST(test_pke_microcode_and_engine_states)
{
    uint32_t i;
    uint32_t u0;

    /* nRF54L15: microcode loaded once and read back. */
    ut_setup(1U);
    u0 = noxtls_nrf54_pke_stats()->ucode_loads;
    ut_ecdsa_load();
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->ucode_loads - u0, 1U);
    for (i = 0U; i < NOXTLS_NRF54_BA414EP_UCODE_WORDS; i += 97U) {
        UTNOX_EQUALS(g_ut.core[UT_IDX(NOXTLS_NRF54_PK_CODE) + i], noxtls_nrf54_ba414ep_ucode[i]);
    }
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->ucode_loads - u0, 1U);
    /* Code RAM lost (power event): the engine reports it, software verifies, next command reloads. */
    g_ut.core[UT_IDX(NOXTLS_NRF54_PK_CODE)] ^= 1U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->last_status, NOXTLS_NRF54_PK_ST_BAD_UCODE);
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->ucode_loads - u0, 2U);
    /* Microcode read-back mismatch: no command, software verifies. */
    ut_setup(0U);
    u0 = noxtls_nrf54_pke_stats()->ucode_loads;
    {
        noxtls_nrf54_hw_t hw = *noxtls_nrf54_cracen_hw();

        hw.variant = (uint8_t)NOXTLS_NRF54_VARIANT_BASE;
        UTNOX_EQUALS(noxtls_nrf54_cracen_set_hw(&hw), NOXTLS_RETURN_SUCCESS);
    }
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_starts, 0U);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->ucode_loads - u0, 1U);
    g_ut.err[0] = '\0';
    /* nRF54LM20: never writes the code memory (the mock fails such writes), clears with the command. */
    ut_setup(0U);
    u0 = noxtls_nrf54_pke_stats()->ucode_loads;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->ucode_loads - u0, 0U);
    UTNOX_EQUALS(g_ut.pk_clears, 1U);
    UTNOX_EQUALS(g_ut.err[0], 0);
    /* Clear-memory command that never completes: bounded. */
    g_ut.pk_clear_hang = 1U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    g_ut.pk_clear_hang = 0U;
    /* Stale completion latched at power-up, interrupt-driven wait: exactly one interrupt. */
    ut_setup(0U);
    ut_port_irq();
    g_ut.pk_irq_at_power = 1U;
    g_ut.pk_delay = 5U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_cracen_stats()->irq_pke, 1U);
    UTNOX_EQUALS(g_ut.pk_starts, 2U);
    /* IKG busy for a while, then ready; never ready: software. */
    ut_setup(0U);
    g_ut.ikg_busy_reads = 3U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_starts, 2U);
    g_ut.ikg_never_ready = 1U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_starts, 2U);
    g_ut.ikg_never_ready = 0U;
    /* Engine without built-in P-256 / without a PKE / timeout: software. */
    g_ut.core[UT_IDX(NOXTLS_NRF54_PK_HWCONFIG)] &= ~NOXTLS_NRF54_PK_HW_P256;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_starts, 2U);
    ut_setup(0U);
    g_ut.core[UT_IDX(NOXTLS_NRF54_HW_INCLIPS)] &= ~NOXTLS_NRF54_INCLIPS_BA414EP;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(g_ut.pk_starts, 0U);
    ut_setup(1U);
    u0 = noxtls_nrf54_pke_stats()->ucode_loads;
    g_ut.pk_hang = 1U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    g_ut.pk_hang = 0U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_nrf54_pke_stats()->ucode_loads - u0, 2U);
    /* 8192-bit engine: 0x400-byte slots. */
    ut_setup(0U);
    g_ut.core[UT_IDX(NOXTLS_NRF54_PK_HWCONFIG)] = (g_ut.core[UT_IDX(NOXTLS_NRF54_PK_HWCONFIG)] & ~0xFFFU) | 0x400U;
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(&g_ut.pk_snap[(NOXTLS_NRF54_PK_SLOT_ECDSA_QX * 0x400U) + 0x400U - 32U], s_pub, 32U), 0);
    /* Busy CRACEN: software. */
    ut_setup(0U);
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(ut_ecdsa_verify(), NOXTLS_RETURN_SUCCESS);
    noxtls_nordic_crypto_release();
    UTNOX_EQUALS(g_ut.pk_starts, 0U);
    return 0;
}

REGISTER_TEST(test_pke_point_multiply_port)
{
    ecc_curve_params_t curve;
    ecc_point_t r;
    ecc_point_t p;
    uint8_t k[32];
    uint8_t blind[8] = { 0U };
    uint32_t i;
    uint8_t chip;

    (void)memset(&curve, 0, sizeof(curve));
    UTNOX_EQUALS(noxtls_ecc_curve_init(&curve, NOXTLS_ECC_SECP256R1), NOXTLS_RETURN_SUCCESS);
    p = curve.G;
    for (i = 0U; i < 32U; i++) {
        k[i] = (uint8_t)(i + 1U);
    }
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        (void)memset(&r, 0, sizeof(r));
        UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_SUCCESS);
        for (i = 0U; i < 32U; i++) {
            UTNOX_EQUALS(r.x[i], (uint8_t)(p.x[i] ^ k[i]));
            UTNOX_EQUALS(r.y[i], (uint8_t)(p.y[i] ^ k[i]));
        }
        UTNOX_EQUALS(r.size, 32U);
        UTNOX_EQUALS(g_ut.pk_ptmul_runs, 2U);
        UTNOX_EQUALS(g_ut.pk_cmd & 0xFFU, NOXTLS_NRF54_PK_OP_ECC_PTMUL);
        UTNOX_EQUALS(g_ut.pk_ptrs, NOXTLS_NRF54_PK_SLOT_PTMUL_PX | (NOXTLS_NRF54_PK_SLOT_PTMUL_K << 8) |
                     (NOXTLS_NRF54_PK_SLOT_PTMUL_RX << 16));
        /* Blinding factor: odd, bits 63..62 clear, bit 61 set. */
        UTNOX_EQUALS(ut_pk_be(NOXTLS_NRF54_PK_SLOT_BLIND)[24] & 0xE0U, 0x20U);
        UTNOX_EQUALS(ut_pk_be(NOXTLS_NRF54_PK_SLOT_BLIND)[31] & 0x01U, 1U);
        UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 1);
        UTNOX_EQUALS(noxtls_ecc_accel_last_stage(), 4U);
        UTNOX_EQUALS(ut_pk_wiped(), 1U);
        /* The two blinded runs disagree: not accepted. */
        g_ut.pk_ptmul_corrupt = UINT32_C(1) << 3;
        UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
        UTNOX_EQUALS(r.x[0], 0U);
        g_ut.pk_ptmul_corrupt = 0U;
        /* Engine error on the first run. */
        g_ut.pk_status_bits = NOXTLS_NRF54_PK_ST_NOT_ON_CURVE;
        UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
        UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), (int32_t)NOXTLS_RETURN_NOT_SUPPORTED);
        UTNOX_EQUALS(noxtls_ecc_accel_last_status(), NOXTLS_NRF54_PK_ST_NOT_ON_CURVE);
        g_ut.pk_status_bits = 0U;
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    /* Through the NoxTLS point multiplication: the accelerated result is used. */
    ut_setup(0U);
    UTNOX_EQUALS(noxtls_ecc_point_multiply(&r, k, &p, &curve), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(r.x[5], (uint8_t)(p.x[5] ^ k[5]));
    UTNOX_GREATER_THAN(noxtls_ecc_accel_operation_count(), 0U);
    /* No entropy for the blinding factor: software. */
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
    noxtls_drbg_set_entropy_callback(NULL);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_accel_last_stage(), 1U);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_AUTO);
    /* Not for this engine. */
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(NULL, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, NULL, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, NULL, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    p.size = 48U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    p.size = 32U;
    curve.p[0] ^= 1U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    curve.p[0] ^= 1U;
    noxtls_nrf54_cracen_set_enabled(0U);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&r, k, &p, &curve), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_nrf54_cracen_set_enabled(1U);
    UTNOX_EQUALS(noxtls_nrf54_pke_p256_mul(NULL, k, k, blind, r.x, r.y), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_p256_mul(k, NULL, k, blind, r.x, r.y), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_p256_mul(k, k, NULL, blind, r.x, r.y), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_p256_mul(k, k, k, NULL, r.x, r.y), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_p256_mul(k, k, k, blind, NULL, r.y), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_pke_p256_mul(k, k, k, blind, r.x, NULL), NOXTLS_RETURN_NULL);
    /* Telemetry. */
    noxtls_ecc_accel_note_fallback();
    UTNOX_GREATER_THAN(noxtls_ecc_accel_fallback_count(), 0U);
    UTNOX_EQUALS(noxtls_ecc_accel_input_echo_ok(), 1);
    (void)noxtls_ecc_curve_free(&curve);
    return 0;
}
