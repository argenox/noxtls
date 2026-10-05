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
* File:    test_nrf54_aead.c
* Summary: Tests of the BA411 AES-GCM / AES-CCM backend and the NoxTLS AEAD ports
*
*****************************************************************************/

/**
 * @file test_nrf54_aead.c
 * @brief GCM (McGrew-Viega test cases) and CCM (SP 800-38C Appendix C, RFC 3610)
 *        vectors through the NoxTLS API on the mocked CRACEN, tag rejection with
 *        output wipe, bounce, the long-AAD encoding, counter limits and errors.
 * @ingroup noxtls_nrf54_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_mock.h"
#include "ut_nrf54_ref.h"
#include "ut_nrf54_vectors.h"
#include "noxtls_aes.h"
#include "noxtls_aes_gcm.h"
#include "noxtls_aes_ccm.h"
#include "noxtls_aes_accel.h"

/** Decoded vector. */
typedef struct {
    uint8_t key[32];
    uint8_t nonce[16];
    uint8_t aad[32];
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t tag[16];
    uint32_t key_len;
    uint32_t nonce_len;
    uint32_t aad_len;
    uint32_t len;
    uint32_t tag_len;
} ut_vec_t;

/**
 * @brief Decode a vector.
 *
 * @param[in]  v Vector.
 * @param[out] d Decoded vector.
 */
static void ut_decode(const ut_aead_vec_t *v, ut_vec_t *d)
{
    (void)memset(d, 0, sizeof(*d));
    d->key_len = ut_hex(v->key, d->key, sizeof(d->key));
    d->nonce_len = ut_hex(v->nonce, d->nonce, sizeof(d->nonce));
    d->aad_len = ut_hex(v->aad, d->aad, sizeof(d->aad));
    d->len = ut_hex(v->pt, d->pt, sizeof(d->pt));
    (void)ut_hex(v->ct, d->ct, sizeof(d->ct));
    d->tag_len = ut_hex(v->tag, d->tag, sizeof(d->tag));
}

/**
 * @brief AES key size selector of a key length.
 *
 * @param[in] key_len Bytes.
 *
 * @return Selector.
 */
static noxtls_aes_type_t ut_type(uint32_t key_len)
{
    return (key_len == 16U) ? NOXTLS_AES_128_BIT : ((key_len == 24U) ? NOXTLS_AES_192_BIT : NOXTLS_AES_256_BIT);
}

/**
 * @brief Run one vector through the NoxTLS API (buffers in the DMA window), both directions and a tamper.
 *
 * @param[in] v Vector.
 *
 * @return Failures.
 */
static uint32_t ut_run_vec(const ut_aead_vec_t *v)
{
    ut_vec_t d;
    uint8_t tag[16];
    uint32_t fails = 0U;
    noxtls_return_t rc;

    ut_decode(v, &d);
    (void)memcpy(g_ut_ram.in, d.pt, d.len);
    (void)memset(g_ut_ram.out, 0xEE, 64U);
    if (v->alg == 0U) {
        rc = noxtls_aes_gcm_encrypt(d.key, ut_type(d.key_len), d.nonce, d.aad, d.aad_len, g_ut_ram.in, d.len,
                                    g_ut_ram.out, tag);
        fails |= ((rc != NOXTLS_RETURN_SUCCESS) || (memcmp(g_ut_ram.out, d.ct, d.len) != 0) ||
                  (memcmp(tag, d.tag, d.tag_len) != 0)) ? (UINT32_C(1) << 1) : 0U;
        (void)memcpy(g_ut_ram.in, d.ct, d.len);
        rc = noxtls_aes_gcm_decrypt(d.key, ut_type(d.key_len), d.nonce, d.aad, d.aad_len, g_ut_ram.in, d.len, tag,
                                    g_ut_ram.out);
        fails |= ((rc != NOXTLS_RETURN_SUCCESS) || (memcmp(g_ut_ram.out, d.pt, d.len) != 0)) ? (UINT32_C(1) << 2) : 0U;
        tag[0] ^= 0x01U;
        (void)memset(g_ut_ram.out, 0xEE, 64U);
        rc = noxtls_aes_gcm_decrypt(d.key, ut_type(d.key_len), d.nonce, d.aad, d.aad_len, g_ut_ram.in, d.len, tag,
                                    g_ut_ram.out);
        fails |= (rc != NOXTLS_RETURN_BAD_DATA) ? (UINT32_C(1) << 3) : 0U;
    } else {
        rc = noxtls_aes_ccm_encrypt(d.key, ut_type(d.key_len), d.nonce, d.nonce_len, d.aad, d.aad_len, g_ut_ram.in,
                                    d.len, g_ut_ram.out, tag, d.tag_len);
        fails |= ((rc != NOXTLS_RETURN_SUCCESS) || (memcmp(g_ut_ram.out, d.ct, d.len) != 0) ||
                  (memcmp(tag, d.tag, d.tag_len) != 0)) ? (UINT32_C(1) << 4) : 0U;
        (void)memcpy(g_ut_ram.in, d.ct, d.len);
        rc = noxtls_aes_ccm_decrypt(d.key, ut_type(d.key_len), d.nonce, d.nonce_len, d.aad, d.aad_len, g_ut_ram.in,
                                    d.len, tag, d.tag_len, g_ut_ram.out);
        fails |= ((rc != NOXTLS_RETURN_SUCCESS) || (memcmp(g_ut_ram.out, d.pt, d.len) != 0)) ? (UINT32_C(1) << 5) : 0U;
        tag[d.tag_len - 1U] ^= 0x80U;
        (void)memset(g_ut_ram.out, 0xEE, 64U);
        rc = noxtls_aes_ccm_decrypt(d.key, ut_type(d.key_len), d.nonce, d.nonce_len, d.aad, d.aad_len, g_ut_ram.in,
                                    d.len, tag, d.tag_len, g_ut_ram.out);
        fails |= (rc != NOXTLS_RETURN_BAD_DATA) ? (UINT32_C(1) << 6) : 0U;
    }
    /* Unauthenticated plaintext is never released: wiped (hardware) or untouched (software). */
    {
        uint32_t i;

        for (i = 0U; i < d.len; i++) {
            fails |= ((g_ut_ram.out[i] != 0U) && (g_ut_ram.out[i] != 0xEEU)) ? (UINT32_C(1) << 7) : 0U;
        }
    }
    return fails;
}

REGISTER_TEST(test_aead_vectors)
{
    uint8_t chip;
    uint32_t i;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        if (chip != 0U) {
            ut_port_irq();
        }
        for (i = 0U; i < UT_AEAD_VECS; i++) {
            if ((s_ut_aead_vecs[i].alg != 0U) || (strlen(s_ut_aead_vecs[i].tag) == 32U)) {
                UTNOX_EQUALS(ut_run_vec(&s_ut_aead_vecs[i]) | (i << 16) | ((uint32_t)chip << 24), (i << 16) | ((uint32_t)chip << 24));
            }
        }
        UTNOX_GREATER_THAN(noxtls_nrf54_cracen_stats()->cm_jobs, 20U);
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_aead_ccm_long_aad_and_bounce)
{
    uint8_t key[16];
    uint8_t nonce[13];
    uint8_t ct[32];
    uint8_t tag[16];
    uint8_t out[32];
    uint8_t far_pt[40];
    uint8_t far_ct[40];
    uint8_t far_tag[16];
    uint8_t sw_ct[40];
    uint8_t sw_tag[16];
    uint32_t i;
    uint8_t chip;

    for (chip = 0U; chip < 2U; chip++) {
        ut_setup(chip);
        (void)ut_hex(UT_CCM_LONG_KEY, key, sizeof(key));
        (void)ut_hex(UT_CCM_LONG_NONCE, nonce, sizeof(nonce));
        for (i = 0U; i < UT_CCM_LONG_AAD_LEN; i++) {
            g_ut_ram.aad[i] = (uint8_t)i;
        }
        for (i = 0U; i < UT_CCM_LONG_PT_LEN; i++) {
            g_ut_ram.in[i] = (uint8_t)(0x20U + i);
        }
        /* 0xFF00 bytes of AAD: 6-byte length encoding, header split over two descriptors. */
        UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 13U, g_ut_ram.aad, UT_CCM_LONG_AAD_LEN,
                                            g_ut_ram.in, UT_CCM_LONG_PT_LEN, g_ut_ram.out, tag, 16U), NOXTLS_RETURN_SUCCESS);
        (void)ut_hex(UT_CCM_LONG_CT, ct, sizeof(ct));
        UTNOX_EQUALS(memcmp(g_ut_ram.out, ct, 32U), 0);
        (void)ut_hex(UT_CCM_LONG_TAG, out, sizeof(out));
        UTNOX_EQUALS(memcmp(tag, out, 16U), 0);
        UTNOX_EQUALS(g_ut.last_aad_len, 16U + 6U + UT_CCM_LONG_AAD_LEN);
        /* Stack buffers (outside the DMA window) are bounced; compare with software. */
        for (i = 0U; i < sizeof(far_pt); i++) {
            far_pt[i] = (uint8_t)(i ^ 0x5AU);
        }
        UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 12U, far_pt, 20U, far_pt, 40U, far_ct,
                                            far_tag, 8U), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(0U);
        UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 12U, far_pt, 20U, far_pt, 40U, sw_ct,
                                            sw_tag, 8U), NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(1U);
        UTNOX_EQUALS(memcmp(far_ct, sw_ct, 40U), 0);
        UTNOX_EQUALS(memcmp(far_tag, sw_tag, 8U), 0);
        UTNOX_EQUALS(noxtls_aes_gcm_encrypt(key, NOXTLS_AES_128_BIT, nonce, far_pt, 20U, far_pt, 40U, far_ct, far_tag),
                     NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(0U);
        UTNOX_EQUALS(noxtls_aes_gcm_encrypt(key, NOXTLS_AES_128_BIT, nonce, far_pt, 20U, far_pt, 40U, sw_ct, sw_tag),
                     NOXTLS_RETURN_SUCCESS);
        noxtls_nrf54_cracen_set_enabled(1U);
        UTNOX_EQUALS(memcmp(far_ct, sw_ct, 40U), 0);
        UTNOX_EQUALS(memcmp(far_tag, sw_tag, 16U), 0);
        UTNOX_EQUALS(noxtls_aes_gcm_decrypt(key, NOXTLS_AES_128_BIT, nonce, far_pt, 20U, far_ct, 40U, far_tag, sw_ct),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(sw_ct, far_pt, 40U), 0);
        UTNOX_EQUALS(g_ut.err[0], 0);
    }
    return 0;
}

REGISTER_TEST(test_aead_backend_limits_and_errors)
{
    uint8_t key[32] = { 0U };
    uint8_t iv[13] = { 0U };
    uint8_t tag[16] = { 0U };
    static uint8_t big[300];

    ut_setup(0U);
    /* Arguments. */
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, NULL, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, NULL, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 4U, g_ut_ram.in, g_ut_ram.out, 16U, tag), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, NULL, g_ut_ram.out, 16U, tag), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, NULL, 16U, tag), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 17U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, NULL, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, NULL, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, NULL, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 3U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, NULL, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, NULL, 16U, tag, 16U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 15U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_INVALID_KEY_SIZE);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 6U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 14U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 2U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 18U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 5U),
                 NOXTLS_RETURN_INVALID_PARAM);
    /* n = 13: q = 2, the payload must be < 2^16. */
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 13U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 0x10000U, tag, 16U),
                 NOXTLS_RETURN_INVALID_PARAM);
    /* CRACEN Lite: payload above 2^16 - 2 blocks would wrap the engine counter. */
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 0x100000U, tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* No AES-192 on CRACEN Lite. */
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 24U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Unreachable buffers too long for the bounce buffers. */
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, big, sizeof(big), g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, big, g_ut_ram.out, sizeof(big), tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, big, sizeof(big), tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 12U, big, sizeof(big), g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Engine without CCM. */
    ut_setup(0U);
    g_ut.core[UT_IDX(NOXTLS_NRF54_HW_BA411_CFG1)] &= ~(UINT32_C(1) << NOXTLS_NRF54_AES_MODE_CCM);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Busy. */
    ut_setup(1U);
    UTNOX_EQUALS(noxtls_nordic_crypto_try_acquire(), 1);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 12U, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_nordic_crypto_release();
    /* AES-192 on the nRF54L15 engine. */
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 24U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_SUCCESS);
    /* Job failure: output wiped, error reported (CCM through the NoxTLS API returns FAILED). */
    (void)memset(g_ut_ram.out, 0x77, 16U);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(g_ut_ram.out[0], 0U);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 0U, tag),
                 NOXTLS_RETURN_FAILED);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, iv, 12U, NULL, 0U, g_ut_ram.in, 16U, g_ut_ram.out,
                                        tag, 16U), NOXTLS_RETURN_FAILED);
    /* GCM decrypt hardware failure: the port falls back to software (still verifies). */
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt(key, NOXTLS_AES_128_BIT, iv, NULL, 0U, g_ut_ram.in, 16U, g_ut_ram.out, tag),
                 NOXTLS_RETURN_SUCCESS);
    (void)memcpy(&g_ut_ram.in[64], g_ut_ram.out, 16U);
    g_ut.inject_error = 1U;
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt(key, NOXTLS_AES_128_BIT, iv, NULL, 0U, &g_ut_ram.in[64], 16U, tag, g_ut_ram.out),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(memcmp(g_ut_ram.out, g_ut_ram.in, 16U), 0);
    /* Segments longer than one DMA descriptor (16 MiB): software. */
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 0x1000000U, tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, g_ut_ram.aad, 0x1000000U, g_ut_ram.in, g_ut_ram.out, 16U, tag),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* Long AAD in the window but the payload is not reachable: software. */
    UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 12U, g_ut_ram.aad, 100U, big, g_ut_ram.out, sizeof(big), tag, 16U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    /* GCM decryption with a bounced output; empty payload with NULL buffers. */
    {
        uint8_t far_out[32];

        UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, g_ut_ram.in, g_ut_ram.out, 32U, tag),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_nrf54_aead_gcm(1U, key, 16U, iv, NULL, 0U, g_ut_ram.out, far_out, 32U, tag),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(memcmp(far_out, g_ut_ram.in, 32U), 0);
        UTNOX_EQUALS(noxtls_nrf54_aead_gcm(0U, key, 16U, iv, NULL, 0U, NULL, NULL, 0U, tag), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_nrf54_aead_ccm(0U, key, 16U, iv, 12U, g_ut_ram.aad, 4U, NULL, NULL, 0U, tag, 8U),
                     NOXTLS_RETURN_SUCCESS);
    }
    /* Port argument checks. */
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(key, NOXTLS_AES_128_BIT, iv, NULL, 0U, g_ut_ram.in, 16U, NULL,
                                                   g_ut_ram.out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(key, NOXTLS_AES_128_BIT, iv, 12U, NULL, 0U, g_ut_ram.in, 16U, NULL,
                                                   16U, g_ut_ram.out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(key, NOXTLS_AES_128_BIT, iv, 12U, NULL, 0U, g_ut_ram.in, 16U, tag,
                                                   17U, g_ut_ram.out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(key, (noxtls_aes_type_t)9, iv, NULL, 0U, g_ut_ram.in, 16U,
                                                   g_ut_ram.out, tag), NOXTLS_RETURN_NOT_SUPPORTED);
    return 0;
}
