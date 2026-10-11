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
* File:    ecjpake_ut.c
* Summary: EC-JPAKE primitive tests: vectors, exchange, negatives, limits
*
*
*****************************************************************************/

/**
 * @file ecjpake_ut.c
 * @brief EC-JPAKE tests: draft example, reference vectors, both roles, malformed input.
 * @ingroup noxtls_ecjpake
 */

#include <stdint.h>
#include <string.h>

#include "pake/noxtls_ecjpake.h"
#include "pake/noxtls_ecjpake_internal.h"
#include "drbg/noxtls_drbg.h"
#include "runner.h"
#include "test_assert.h"
#include "ecjpake_test_vectors.h"

/** @brief Scalar size shorthand. */
#define UT_SC NOXTLS_ECJPAKE_SCALAR_SIZE
/** @brief Point size shorthand. */
#define UT_PT NOXTLS_ECJPAKE_POINT_SIZE
/** @brief Number of injected scalars in k_ecj_scalars. */
#define UT_SCALAR_COUNT (10U)
/** @brief Index of x1 in k_ecj_scalars. */
#define UT_IDX_X1 (0U)
/** @brief Index of x3 in k_ecj_scalars. */
#define UT_IDX_X3 (4U)
/** @brief Index of x4 in k_ecj_scalars. */
#define UT_IDX_X4 (6U)
/** @brief Offset of the r length octet in an ECJPAKEKeyKP. */
#define UT_KP_R_LEN_OFFSET (2U * (1U + UT_PT))
/** @brief Offset of the V point (after its length octet) in an ECJPAKEKeyKP. */
#define UT_KP_V_OFFSET (1U + UT_PT + 1U)
/** @brief Maximum queued scalars for the injected random source. */
#define UT_QUEUE_MAX (16U)

/** @brief P-256 order n, big-endian. */
static const uint8_t s_order[UT_SC] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

/** @brief Client context (kept off the test stack). */
static noxtls_ecjpake_ctx_t s_client;
/** @brief Server context. */
static noxtls_ecjpake_ctx_t s_server;

/** @brief Injected scalar queue (32-octet entries). */
static uint8_t s_queue[UT_QUEUE_MAX][UT_SC];
/** @brief Number of queued scalars. */
static uint32_t s_queue_len;
/** @brief Next queue entry. */
static uint32_t s_queue_pos;
/** @brief When non-zero the injected source fails with this code. */
static noxtls_return_t s_queue_fail_rc;

/**
 * @brief Injected random source: returns 8 zero octets then the next queued scalar.
 * @internal
 *
 * @param[in] user Unused.
 * @param[out] out Destination.
 * @param[in] len Requested length (NOXTLS_ECJPAKE_RANDOM_SEED_SIZE).
 *
 * @return NOXTLS_RETURN_SUCCESS or the configured failure.
 */
static noxtls_return_t ut_queue_random(void *user, uint8_t *out, uint32_t len)
{
    (void)user;
    if (s_queue_fail_rc != NOXTLS_RETURN_SUCCESS) {
        return s_queue_fail_rc;
    }

    memset(out, 0, len);
    if (s_queue_pos < s_queue_len) {
        memcpy(&out[len - UT_SC], s_queue[s_queue_pos], UT_SC);
        ++s_queue_pos;
    }

    return NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Load the reference scalars into the injected queue and enable it.
 * @internal
 */
static void ut_queue_reference(void)
{
    uint32_t index;

    for (index = 0U; index < UT_SCALAR_COUNT; ++index) {
        memcpy(s_queue[index], &k_ecj_scalars[index * UT_SC], UT_SC);
    }

    s_queue_len = UT_SCALAR_COUNT;
    s_queue_pos = 0U;
    s_queue_fail_rc = NOXTLS_RETURN_SUCCESS;
    noxtls_ecjpake_set_random_source(ut_queue_random, NULL);
}

/**
 * @brief Restore the DRBG random source.
 * @internal
 */
static void ut_queue_off(void)
{
    noxtls_ecjpake_set_random_source(NULL, NULL);
    s_queue_len = 0U;
    s_queue_pos = 0U;
    s_queue_fail_rc = NOXTLS_RETURN_SUCCESS;
}

/**
 * @brief Return 1 when every octet is zero.
 * @internal
 *
 * @param[in] buf Buffer.
 * @param[in] len Length.
 *
 * @return 1 when all zero.
 */
static int ut_all_zero(const void *buf, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)buf;
    size_t index;

    for (index = 0U; index < len; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief Run a full exchange; optionally compare every message with the reference vectors.
 * @internal
 *
 * @param[in] client_pw Client password.
 * @param[in] client_len Client password length.
 * @param[in] server_pw Server password.
 * @param[in] server_len Server password length.
 * @param[in] check_vectors Non-zero to compare with ecjpake_test_vectors.h.
 * @param[out] pms_client Client premaster.
 * @param[out] pms_server Server premaster.
 *
 * @return 0 on success, non-zero on the first failing step.
 */
static int ut_exchange(const uint8_t *client_pw, uint32_t client_len,
                       const uint8_t *server_pw, uint32_t server_len,
                       int check_vectors,
                       uint8_t pms_client[NOXTLS_ECJPAKE_PREMASTER_SIZE],
                       uint8_t pms_server[NOXTLS_ECJPAKE_PREMASTER_SIZE])
{
    static uint8_t c_r1[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE];
    static uint8_t s_r1[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE];
    static uint8_t s_r2[NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE];
    static uint8_t c_r2[NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE];
    uint32_t c_r1_len = 0U;
    uint32_t s_r1_len = 0U;
    uint32_t s_r2_len = 0U;
    uint32_t c_r2_len = 0U;
    uint32_t len = 0U;

    if (noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, client_pw, client_len) != NOXTLS_RETURN_SUCCESS) {
        return 1;
    }

    if (noxtls_ecjpake_init(&s_server, NOXTLS_ECJPAKE_ROLE_SERVER, server_pw, server_len) != NOXTLS_RETURN_SUCCESS) {
        return 2;
    }

    if (noxtls_ecjpake_write_round_one(&s_client, c_r1, sizeof(c_r1), &c_r1_len) != NOXTLS_RETURN_SUCCESS) {
        return 3;
    }

    if (noxtls_ecjpake_read_round_one(&s_server, c_r1, c_r1_len) != NOXTLS_RETURN_SUCCESS) {
        return 4;
    }

    if (noxtls_ecjpake_write_round_one(&s_server, s_r1, sizeof(s_r1), &s_r1_len) != NOXTLS_RETURN_SUCCESS) {
        return 5;
    }

    if (noxtls_ecjpake_read_round_one(&s_client, s_r1, s_r1_len) != NOXTLS_RETURN_SUCCESS) {
        return 6;
    }

    if (noxtls_ecjpake_write_round_two(&s_server, s_r2, sizeof(s_r2), &s_r2_len) != NOXTLS_RETURN_SUCCESS) {
        return 7;
    }

    if (noxtls_ecjpake_read_round_two(&s_client, s_r2, s_r2_len) != NOXTLS_RETURN_SUCCESS) {
        return 8;
    }

    if (noxtls_ecjpake_write_round_two(&s_client, c_r2, sizeof(c_r2), &c_r2_len) != NOXTLS_RETURN_SUCCESS) {
        return 9;
    }

    if (noxtls_ecjpake_read_round_two(&s_server, c_r2, c_r2_len) != NOXTLS_RETURN_SUCCESS) {
        return 10;
    }

    if ((noxtls_ecjpake_derive_premaster(&s_client, pms_client, NOXTLS_ECJPAKE_PREMASTER_SIZE, &len) !=
         NOXTLS_RETURN_SUCCESS) || (len != NOXTLS_ECJPAKE_PREMASTER_SIZE)) {
        return 11;
    }

    if ((noxtls_ecjpake_derive_premaster(&s_server, pms_server, NOXTLS_ECJPAKE_PREMASTER_SIZE, &len) !=
         NOXTLS_RETURN_SUCCESS) || (len != NOXTLS_ECJPAKE_PREMASTER_SIZE)) {
        return 12;
    }

    if (check_vectors != 0) {
        if ((c_r1_len != sizeof(k_ecj_client_r1)) || (memcmp(c_r1, k_ecj_client_r1, c_r1_len) != 0)) {
            return 13;
        }

        if ((s_r1_len != sizeof(k_ecj_server_r1)) || (memcmp(s_r1, k_ecj_server_r1, s_r1_len) != 0)) {
            return 14;
        }

        if ((s_r2_len != sizeof(k_ecj_server_r2)) || (memcmp(s_r2, k_ecj_server_r2, s_r2_len) != 0)) {
            return 15;
        }

        if ((c_r2_len != sizeof(k_ecj_client_r2)) || (memcmp(c_r2, k_ecj_client_r2, c_r2_len) != 0)) {
            return 16;
        }

        if (memcmp(pms_client, k_ecj_pms, NOXTLS_ECJPAKE_PREMASTER_SIZE) != 0) {
            return 17;
        }
    }

    return 0;
}

/**
 * @brief draft-cragie-tls-ecjpake-01 section 8.3.1: "d45yj8e" maps to s = 0x643435796a3865.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_password_mapping_draft_example)
{
    static const uint8_t password[] = { 'd', '4', '5', 'y', 'j', '8', 'e' };
    uint8_t expected[UT_SC];

    memset(expected, 0, sizeof(expected));
    expected[25] = 0x64U;
    expected[26] = 0x34U;
    expected[27] = 0x35U;
    expected[28] = 0x79U;
    expected[29] = 0x6AU;
    expected[30] = 0x38U;
    expected[31] = 0x65U;
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, password, sizeof(password)),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(s_client.s, expected, UT_SC);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_ACTIVE);
    noxtls_ecjpake_free(&s_client);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_EMPTY);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(NULL), NOXTLS_ECJPAKE_STATE_EMPTY);
    noxtls_ecjpake_free(NULL);
    return 0;
}

/**
 * @brief Both roles reproduce every octet of the independent Python model.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_reference_vectors)
{
    uint8_t pms_c[NOXTLS_ECJPAKE_PREMASTER_SIZE];
    uint8_t pms_s[NOXTLS_ECJPAKE_PREMASTER_SIZE];

    ut_queue_reference();
    UTNOX_EQUALS(ut_exchange(k_ecj_password, sizeof(k_ecj_password), k_ecj_password, sizeof(k_ecj_password),
                             1, pms_c, pms_s), 0);
    ut_queue_off();
    UTNOX_MEM_EQUAL(pms_c, pms_s, sizeof(pms_c));
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_DONE);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_server), NOXTLS_ECJPAKE_STATE_DONE);
    UTNOX_IS_TRUE(ut_all_zero(s_client.s, UT_SC) && ut_all_zero(s_client.xm1, UT_SC) &&
                  ut_all_zero(s_client.xm2, UT_SC));
    UTNOX_IS_TRUE(ut_all_zero(s_server.s, UT_SC) && ut_all_zero(s_server.xm2, UT_SC));
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief DRBG-driven exchanges: same password agrees, wrong password disagrees, MIN/MAX lengths.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_random_exchange_and_wrong_password)
{
    static const uint8_t pskc[16] = {
        0xC3, 0xF5, 0x93, 0x68, 0x44, 0x5A, 0x1B, 0x61, 0x06, 0xBE, 0x42, 0x0A, 0x70, 0x6D, 0x4C, 0xC9 };
    static const uint8_t pskd[] = { 'J', '0', '1', 'N', 'M', 'E' };
    static const uint8_t wrong[] = { 'J', '0', '1', 'N', 'M', 'F' };
    static const uint8_t one[1] = { 0x01 };
    uint8_t max_pw[NOXTLS_ECJPAKE_PASSWORD_MAX_LEN];
    uint8_t pms_c[NOXTLS_ECJPAKE_PREMASTER_SIZE];
    uint8_t pms_s[NOXTLS_ECJPAKE_PREMASTER_SIZE];

    ut_queue_off();
    UTNOX_EQUALS(ut_exchange(pskc, sizeof(pskc), pskc, sizeof(pskc), 0, pms_c, pms_s), 0);
    UTNOX_MEM_EQUAL(pms_c, pms_s, sizeof(pms_c));
    UTNOX_EQUALS(ut_exchange(pskd, sizeof(pskd), pskd, sizeof(pskd), 0, pms_c, pms_s), 0);
    UTNOX_MEM_EQUAL(pms_c, pms_s, sizeof(pms_c));

    /* Wrong password: every ZKP still verifies; only the premasters differ (the
     * TLS Finished check turns this into a handshake failure). */
    UTNOX_EQUALS(ut_exchange(pskd, sizeof(pskd), wrong, sizeof(wrong), 0, pms_c, pms_s), 0);
    UTNOX_NOT_EQUALS(memcmp(pms_c, pms_s, sizeof(pms_c)), 0);

    /* MIN and MAX password lengths. */
    UTNOX_EQUALS(ut_exchange(one, sizeof(one), one, sizeof(one), 0, pms_c, pms_s), 0);
    UTNOX_MEM_EQUAL(pms_c, pms_s, sizeof(pms_c));
    memset(max_pw, 0xA5, sizeof(max_pw));
    UTNOX_EQUALS(ut_exchange(max_pw, sizeof(max_pw), max_pw, sizeof(max_pw), 0, pms_c, pms_s), 0);
    UTNOX_MEM_EQUAL(pms_c, pms_s, sizeof(pms_c));
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief init argument checks: NULL, role, length bounds, s = 0 mod n.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_init_arguments)
{
    static const uint8_t zero[4] = { 0, 0, 0, 0 };
    uint8_t too_long[NOXTLS_ECJPAKE_PASSWORD_MAX_LEN + 1U];
    uint8_t n_multiple[UT_SC + 1U];

    memset(too_long, 0x31, sizeof(too_long));
    UTNOX_EQUALS(noxtls_ecjpake_init(NULL, NOXTLS_ECJPAKE_ROLE_CLIENT, zero, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, (noxtls_ecjpake_role_t)2, too_long, 1U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, too_long, 0U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_SERVER, too_long, sizeof(too_long)),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_SERVER, too_long, sizeof(too_long) - 1U),
                 NOXTLS_RETURN_SUCCESS);

    /* s = 0: all-zero password and a multiple of n (n with a leading zero octet). */
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, zero, sizeof(zero)),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_EMPTY);
    n_multiple[0] = 0U;
    memcpy(&n_multiple[1], s_order, UT_SC);
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, n_multiple, sizeof(n_multiple)),
                 NOXTLS_RETURN_INVALID_PARAM);
    noxtls_ecjpake_free(&s_client);
    return 0;
}


/** @brief Client round one captured by ut_setup_round_one(). */
static uint8_t s_c_r1[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE];
/** @brief Length of s_c_r1. */
static uint32_t s_c_r1_len;
/** @brief Server round one captured by ut_setup_round_one(). */
static uint8_t s_s_r1[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE];
/** @brief Length of s_s_r1. */
static uint32_t s_s_r1_len;
/** @brief Scratch message buffer for mutations. */
static uint8_t s_msg[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE + 8U];

/**
 * @brief Bring both contexts through round one with the reference scalars.
 * @internal
 *
 * @return 0 on success.
 */
static int ut_setup_round_one(void)
{
    ut_queue_reference();
    if ((noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, k_ecj_password, sizeof(k_ecj_password)) !=
         NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_init(&s_server, NOXTLS_ECJPAKE_ROLE_SERVER, k_ecj_password, sizeof(k_ecj_password)) !=
         NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_write_round_one(&s_client, s_c_r1, sizeof(s_c_r1), &s_c_r1_len) != NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_read_round_one(&s_server, s_c_r1, s_c_r1_len) != NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_write_round_one(&s_server, s_s_r1, sizeof(s_s_r1), &s_s_r1_len) != NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_read_round_one(&s_client, s_s_r1, s_s_r1_len) != NOXTLS_RETURN_SUCCESS)) {
        return 1;
    }

    return 0;
}

/**
 * @brief Feed a mutated client round one to a fresh server and return its result.
 * @internal
 *
 * @param[in] msg Message.
 * @param[in] len Length.
 *
 * @return Result of noxtls_ecjpake_read_round_one(), or NOXTLS_RETURN_FAILED when a
 *         failure did not erase the context.
 */
static noxtls_return_t ut_server_reads(const uint8_t *msg, uint32_t len)
{
    noxtls_return_t rc;

    (void)noxtls_ecjpake_init(&s_server, NOXTLS_ECJPAKE_ROLE_SERVER, k_ecj_password, sizeof(k_ecj_password));
    rc = noxtls_ecjpake_read_round_one(&s_server, msg, len);
    if ((rc != NOXTLS_RETURN_SUCCESS) &&
        ((noxtls_ecjpake_get_state(&s_server) != NOXTLS_ECJPAKE_STATE_FAILED) ||
         (ut_all_zero(s_server.s, UT_SC) == 0))) {
        return NOXTLS_RETURN_FAILED;
    }

    return rc;
}

/**
 * @brief Malformed and invalid round-one messages are rejected with the right alert class.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_round_one_malformed)
{
    noxtls_ecjpake_key_kp_t kp;
    uint32_t used = 0U;
    uint32_t len = 0U;

    UTNOX_EQUALS(ut_setup_round_one(), 0);
    ut_queue_off();
    UTNOX_EQUALS(ut_server_reads(s_c_r1, s_c_r1_len), NOXTLS_RETURN_SUCCESS);

    /* Length errors. */
    UTNOX_EQUALS(ut_server_reads(s_c_r1, 0U), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(ut_server_reads(s_c_r1, s_c_r1_len - 1U), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(ut_server_reads(s_c_r1, UT_KP_R_LEN_OFFSET), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[s_c_r1_len] = 0U;
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len + 1U), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[0] = (uint8_t)(UT_PT - 1U);
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[1U + UT_PT] = (uint8_t)(UT_PT + 1U);
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[UT_KP_R_LEN_OFFSET] = 0U;
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[UT_KP_R_LEN_OFFSET] = (uint8_t)(UT_SC + 1U);
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);

    /* Invalid points: compressed prefix, off curve, x >= p, identity, bad V. */
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[1] = 0x02U;
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[UT_PT] ^= 0x01U;
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    memset(&s_msg[2], 0xFF, UT_SC);
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    memset(&s_msg[2], 0, UT_PT - 1U);
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[UT_KP_V_OFFSET + UT_PT - 1U] ^= 0x01U;
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);

    /* Wrong ZKP: flip the last octet of r in the second key. */
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    s_msg[s_c_r1_len - 1U] ^= 0x01U;
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);

    /* V of key 1 copied into key 2: valid points, wrong proof. */
    memcpy(s_msg, s_c_r1, s_c_r1_len);
    UTNOX_EQUALS(noxtls_ecjpake_kp_read(s_c_r1, s_c_r1_len, &kp, &used), NOXTLS_RETURN_SUCCESS);
    memcpy(&s_msg[used + UT_KP_V_OFFSET], &s_c_r1[UT_KP_V_OFFSET], UT_PT);
    UTNOX_EQUALS(ut_server_reads(s_msg, s_c_r1_len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);

    /* r = n (not reduced): rejected before the group equation. */
    memcpy(kp.r, s_order, UT_SC);
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(&kp, s_msg, sizeof(s_msg), &len), NOXTLS_RETURN_SUCCESS);
    memcpy(&s_msg[len], &s_c_r1[used], s_c_r1_len - used);
    UTNOX_EQUALS(ut_server_reads(s_msg, len + s_c_r1_len - used), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);

    /* Reflection: the client's own round one carries the "client" identity, so the
     * client must reject it as a server round one. */
    (void)noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, k_ecj_password, sizeof(k_ecj_password));
    UTNOX_EQUALS(noxtls_ecjpake_read_round_one(&s_client, s_c_r1, s_c_r1_len),
                 NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_FAILED);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_one(&s_client, s_s_r1, s_s_r1_len), NOXTLS_RETURN_NOT_INITIALIZED);
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief Malformed and invalid round-two messages, both directions.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_round_two_malformed)
{
    uint32_t len = sizeof(k_ecj_server_r2);

    /* Client reading ServerECJPAKEParams. */
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, k_ecj_server_r2, NOXTLS_ECJPAKE_EC_PARAMETERS_SIZE - 1U),
                 NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    memcpy(s_msg, k_ecj_server_r2, len);
    s_msg[0] = 1U;
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, s_msg, len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    memcpy(s_msg, k_ecj_server_r2, len);
    s_msg[2] = (uint8_t)(NOXTLS_ECJPAKE_NAMED_CURVE_SECP256R1 + 1U);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, s_msg, len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    memcpy(s_msg, k_ecj_server_r2, len);
    s_msg[1] = 1U;
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, s_msg, len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, k_ecj_server_r2, len - 1U),
                 NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    memcpy(s_msg, k_ecj_server_r2, len);
    s_msg[len] = 0U;
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, s_msg, len + 1U), NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    memcpy(s_msg, k_ecj_server_r2, len);
    s_msg[len - 1U] ^= 0x01U;
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, s_msg, len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_FAILED);

    /* Server reading ClientECJPAKEParams. */
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    len = sizeof(k_ecj_client_r2);
    memcpy(s_msg, k_ecj_client_r2, len);
    s_msg[len - 1U] ^= 0x01U;
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_server, s_msg, len), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_server, k_ecj_server_r2, sizeof(k_ecj_server_r2)),
                 NOXTLS_RETURN_TLS_ALERT_DECODE_ERROR);
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_server, k_ecj_client_r2, len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_server, k_ecj_client_r2, len), NOXTLS_RETURN_NOT_INITIALIZED);
    ut_queue_off();
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief Call order, NULL arguments and output-size limits for every API.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_state_and_arguments)
{
    uint8_t out[NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE];
    uint8_t again[NOXTLS_ECJPAKE_ROUND_ONE_MAX_SIZE];
    uint8_t pms[NOXTLS_ECJPAKE_PREMASTER_SIZE];
    uint32_t len = 0U;
    uint32_t len2 = 0U;

    /* NULL arguments. */
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(NULL, out, sizeof(out), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, NULL, sizeof(out), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, out, sizeof(out), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_one(NULL, out, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_one(&s_client, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(NULL, out, sizeof(out), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, NULL, sizeof(out), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, out, sizeof(out), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(NULL, out, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(NULL, pms, sizeof(pms), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, NULL, sizeof(pms), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, pms, sizeof(pms), NULL), NOXTLS_RETURN_NULL);

    /* EMPTY context. */
    noxtls_ecjpake_free(&s_client);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, out, sizeof(out), &len), NOXTLS_RETURN_NOT_INITIALIZED);

    /* Out of order before round one completes. */
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, k_ecj_password, sizeof(k_ecj_password)),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, out, sizeof(out), &len), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, out, sizeof(out)), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, pms, sizeof(pms), &len), NOXTLS_RETURN_NOT_INITIALIZED);

    /* Round one output too small: context stays usable and repeats the same octets. */
    ut_queue_reference();
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, again, sizeof(k_ecj_client_r1) - 1U, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_ACTIVE);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, again, sizeof(again), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, s_msg, sizeof(s_msg), &len2), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, len2);
    UTNOX_MEM_EQUAL(again, s_msg, len);
    UTNOX_MEM_EQUAL(again, k_ecj_client_r1, len);

    /* Round two / premaster output too small, and repeated reads or writes. */
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_one(&s_client, s_s_r1, s_s_r1_len), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_server, out, NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE - 1U, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, out, NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE - 1U, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_server, out, sizeof(out), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_server, out, sizeof(out), &len2), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_server, pms, sizeof(pms), &len2), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, out, len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, out, NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE, &len),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, pms, sizeof(pms) - 1U, &len2),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, pms, sizeof(pms), &len2), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, pms, sizeof(pms), &len2), NOXTLS_RETURN_NOT_INITIALIZED);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, out, sizeof(out), &len2), NOXTLS_RETURN_NOT_INITIALIZED);
    ut_queue_off();
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief Queue the scalars for the server round one and both round-two nonces.
 * @internal
 *
 * @param[in] x3 Server first key.
 * @param[in] x4 Server second key.
 */
static void ut_queue_server_keys(const uint8_t x3[UT_SC], const uint8_t x4[UT_SC])
{
    memcpy(s_queue[0], x3, UT_SC);
    memcpy(s_queue[1], &k_ecj_scalars[5U * UT_SC], UT_SC);
    memcpy(s_queue[2], x4, UT_SC);
    memcpy(s_queue[3], &k_ecj_scalars[7U * UT_SC], UT_SC);
    memcpy(s_queue[4], &k_ecj_scalars[8U * UT_SC], UT_SC);
    memcpy(s_queue[5], &k_ecj_scalars[9U * UT_SC], UT_SC);
    s_queue_len = 6U;
    s_queue_pos = 0U;
}

/**
 * @brief Drive a client (reference x1, x2) and a server with chosen x3, x4 through round one.
 * @internal
 *
 * @param[in] x3 Server first key.
 * @param[in] x4 Server second key.
 *
 * @return 0 on success.
 */
static int ut_round_one_with_server_keys(const uint8_t x3[UT_SC], const uint8_t x4[UT_SC])
{
    uint32_t len = 0U;

    ut_queue_reference();
    if ((noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, k_ecj_password, sizeof(k_ecj_password)) !=
         NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_init(&s_server, NOXTLS_ECJPAKE_ROLE_SERVER, k_ecj_password, sizeof(k_ecj_password)) !=
         NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_write_round_one(&s_client, s_c_r1, sizeof(s_c_r1), &s_c_r1_len) != NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_read_round_one(&s_server, s_c_r1, s_c_r1_len) != NOXTLS_RETURN_SUCCESS)) {
        return 1;
    }

    ut_queue_server_keys(x3, x4);
    if ((noxtls_ecjpake_write_round_one(&s_server, s_s_r1, sizeof(s_s_r1), &len) != NOXTLS_RETURN_SUCCESS) ||
        (noxtls_ecjpake_read_round_one(&s_client, s_s_r1, len) != NOXTLS_RETURN_SUCCESS)) {
        return 2;
    }

    return 0;
}

/**
 * @brief Degenerate keys: identity round-two generator (RFC 8236 section 3.2) and identity K.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_identity_generator_and_key)
{
    static const uint8_t zero[UT_SC] = { 0 };
    uint8_t neg_x1[UT_SC];
    uint8_t x4[UT_SC];
    uint8_t out[NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE];
    uint8_t pms[NOXTLS_ECJPAKE_PREMASTER_SIZE];
    uint32_t len = 0U;

    /* x4 = -(x1 + x3): client GA = X1 + X3 + X4 is the identity. */
    noxtls_ecjpake_scalar_sub(zero, &k_ecj_scalars[UT_IDX_X1 * UT_SC], neg_x1);
    noxtls_ecjpake_scalar_sub(neg_x1, &k_ecj_scalars[UT_IDX_X3 * UT_SC], x4);
    UTNOX_EQUALS(ut_round_one_with_server_keys(&k_ecj_scalars[UT_IDX_X3 * UT_SC], x4), 0);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, out, sizeof(out), &len),
                 NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_FAILED);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_server, k_ecj_client_r2, sizeof(k_ecj_client_r2)),
                 NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);

    /* x3 = -x1: every generator is fine but K = G*(x1 + x3)*x2*x4*s is the identity. */
    UTNOX_EQUALS(ut_round_one_with_server_keys(neg_x1, &k_ecj_scalars[UT_IDX_X4 * UT_SC]), 0);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_server, out, sizeof(out), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_client, out, len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_client, out, sizeof(out), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_read_round_two(&s_server, out, len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_client, pms, sizeof(pms), &len),
                 NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_IS_TRUE(ut_all_zero(pms, sizeof(pms)));
    UTNOX_EQUALS(noxtls_ecjpake_derive_premaster(&s_server, pms, sizeof(pms), &len),
                 NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    ut_queue_off();
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief Failing entropy callback for the custom DRBG source.
 * @internal
 *
 * @param[out] out Destination (unused).
 * @param[in] len Length (unused).
 *
 * @return NOXTLS_RETURN_FAILED always.
 */
static noxtls_return_t ut_entropy_fail(uint8_t *out, uint32_t len)
{
    (void)out;
    (void)len;
    return NOXTLS_RETURN_FAILED;
}

/**
 * @brief Random-source failures: callback error, all-zero draws, DRBG entropy failure.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_random_failures)
{
    uint8_t out[NOXTLS_ECJPAKE_ROUND_TWO_MAX_SIZE];
    uint8_t scalar[UT_SC];
    noxtls_entropy_source_t saved_source = noxtls_drbg_get_entropy_source();
    noxtls_entropy_cb_t saved_cb = noxtls_drbg_get_entropy_callback();
    uint32_t len = 0U;

    UTNOX_EQUALS(noxtls_ecjpake_random_scalar(NULL), NOXTLS_RETURN_NULL);

    /* Callback error during round one. */
    ut_queue_reference();
    s_queue_fail_rc = NOXTLS_RETURN_NOT_ENOUGH_ENTROPY;
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, k_ecj_password, sizeof(k_ecj_password)),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, out, sizeof(out), &len),
                 NOXTLS_RETURN_NOT_ENOUGH_ENTROPY);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_client), NOXTLS_ECJPAKE_STATE_FAILED);

    /* Only zero draws: retries are exhausted. */
    s_queue_fail_rc = NOXTLS_RETURN_SUCCESS;
    s_queue_len = 0U;
    s_queue_pos = 0U;
    UTNOX_EQUALS(noxtls_ecjpake_random_scalar(scalar), NOXTLS_RETURN_FAILED);
    UTNOX_IS_TRUE(ut_all_zero(scalar, sizeof(scalar)));

    /* Second key fails after the first succeeded. */
    ut_queue_reference();
    s_queue_len = 2U;
    UTNOX_EQUALS(noxtls_ecjpake_init(&s_client, NOXTLS_ECJPAKE_ROLE_CLIENT, k_ecj_password, sizeof(k_ecj_password)),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_write_round_one(&s_client, out, sizeof(out), &len), NOXTLS_RETURN_FAILED);

    /* Round two nonce failure. */
    UTNOX_EQUALS(ut_setup_round_one(), 0);
    s_queue_fail_rc = NOXTLS_RETURN_FAILED;
    UTNOX_EQUALS(noxtls_ecjpake_write_round_two(&s_server, out, sizeof(out), &len), NOXTLS_RETURN_FAILED);
    UTNOX_EQUALS(noxtls_ecjpake_get_state(&s_server), NOXTLS_ECJPAKE_STATE_FAILED);

    /* DRBG path with a failing entropy source, then recovery. */
    ut_queue_off();
    noxtls_drbg_set_entropy_callback(ut_entropy_fail);
    noxtls_drbg_set_entropy_source(NOXTLS_ENTROPY_SOURCE_CUSTOM);
    UTNOX_NOT_EQUALS(noxtls_ecjpake_random_scalar(scalar), NOXTLS_RETURN_SUCCESS);
    noxtls_drbg_set_entropy_source(saved_source);
    noxtls_drbg_set_entropy_callback(saved_cb);
    UTNOX_EQUALS(noxtls_ecjpake_random_scalar(scalar), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_valid(scalar), 1U);
    noxtls_ecjpake_free(&s_client);
    noxtls_ecjpake_free(&s_server);
    return 0;
}

/**
 * @brief Scalar arithmetic edge cases (0, 1, n-1, n, wide inputs).
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_scalar_arithmetic)
{
    static const uint8_t zero[UT_SC] = { 0 };
    uint8_t one[UT_SC];
    uint8_t n_minus_1[UT_SC];
    uint8_t out[UT_SC];
    uint8_t wide[UT_SC + 1U];

    memset(one, 0, sizeof(one));
    one[UT_SC - 1U] = 1U;
    memcpy(n_minus_1, s_order, UT_SC);
    n_minus_1[UT_SC - 1U] = (uint8_t)(n_minus_1[UT_SC - 1U] - 1U);

    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_valid(zero), 0U);
    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_valid(one), 1U);
    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_valid(n_minus_1), 1U);
    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_valid(s_order), 0U);
    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_below_order(zero), 1U);
    UTNOX_EQUALS(noxtls_ecjpake_scalar_is_below_order(s_order), 0U);

    noxtls_ecjpake_scalar_reduce(NULL, 0U, out);
    UTNOX_MEM_EQUAL(out, zero, UT_SC);
    noxtls_ecjpake_scalar_reduce(s_order, UT_SC, out);
    UTNOX_MEM_EQUAL(out, zero, UT_SC);
    noxtls_ecjpake_scalar_reduce(n_minus_1, UT_SC, out);
    UTNOX_MEM_EQUAL(out, n_minus_1, UT_SC);
    /* 256*n + 1 reduces to 1. */
    memcpy(wide, s_order, UT_SC);
    wide[UT_SC] = 1U;
    noxtls_ecjpake_scalar_reduce(wide, sizeof(wide), out);
    UTNOX_MEM_EQUAL(out, one, UT_SC);

    /* (n-1)^2 = 1 and a*1 = a. */
    noxtls_ecjpake_scalar_mul(n_minus_1, n_minus_1, out);
    UTNOX_MEM_EQUAL(out, one, UT_SC);
    noxtls_ecjpake_scalar_mul(n_minus_1, one, out);
    UTNOX_MEM_EQUAL(out, n_minus_1, UT_SC);

    /* 0 - 1 = n - 1; (n-1) - (n-1) = 0. */
    noxtls_ecjpake_scalar_sub(zero, one, out);
    UTNOX_MEM_EQUAL(out, n_minus_1, UT_SC);
    noxtls_ecjpake_scalar_sub(n_minus_1, n_minus_1, out);
    UTNOX_MEM_EQUAL(out, zero, UT_SC);
    return 0;
}

/**
 * @brief Point, ZKP and codec helper arguments and edge cases.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_ecjpake_internal_helpers)
{
    static const uint8_t zero[UT_SC] = { 0 };
    static const uint8_t id[NOXTLS_ECJPAKE_ID_LEN] = { 'c', 'l', 'i', 'e', 'n', 't' };
    noxtls_ecjpake_key_kp_t kp;
    noxtls_ecjpake_key_kp_t parsed;
    uint8_t one[UT_SC];
    uint8_t g[UT_PT];
    uint8_t p[UT_PT];
    uint8_t ident[UT_PT];
    uint8_t h[UT_SC];
    uint8_t buf[NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE];
    uint32_t len = 0U;
    uint32_t used = 0U;

    memset(one, 0, sizeof(one));
    one[UT_SC - 1U] = 1U;
    UTNOX_EQUALS(noxtls_ecjpake_point_mul(one, NULL, g), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_point_validate(g), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_point_validate(NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_point_mul(NULL, NULL, p), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_point_mul(one, NULL, NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_point_mul(zero, g, ident), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_point_is_identity(ident), 1U);
    UTNOX_EQUALS(noxtls_ecjpake_point_is_identity(g), 0U);

    /* G - G = O; O + G = G; G - O = G. */
    UTNOX_EQUALS(noxtls_ecjpake_point_add(g, g, 1U, p), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_point_is_identity(p), 1U);
    UTNOX_EQUALS(noxtls_ecjpake_point_add(ident, g, 0U, p), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(p, g, UT_PT);
    UTNOX_EQUALS(noxtls_ecjpake_point_add(g, ident, 1U, p), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(p, g, UT_PT);
    UTNOX_EQUALS(noxtls_ecjpake_point_add(NULL, g, 0U, p), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_point_add(g, NULL, 0U, p), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_point_add(g, g, 0U, NULL), NOXTLS_RETURN_NULL);

    /* ZKP hash arguments; an empty identity is allowed. */
    UTNOX_EQUALS(noxtls_ecjpake_zkp_hash(NULL, g, g, id, sizeof(id), h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_hash(g, NULL, g, id, sizeof(id), h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_hash(g, g, NULL, id, sizeof(id), h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_hash(g, g, g, NULL, 1U, h), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_hash(g, g, g, id, sizeof(id), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_hash(g, g, g, NULL, 0U, h), NOXTLS_RETURN_SUCCESS);

    /* Prove x = 1 over G (X = G), verify, then change the identity. */
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(NULL, one, g, one, id, sizeof(id), &kp), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(g, NULL, g, one, id, sizeof(id), &kp), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(g, one, NULL, one, id, sizeof(id), &kp), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(g, one, g, NULL, id, sizeof(id), &kp), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(g, one, g, one, id, sizeof(id), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(g, one, g, one, NULL, 1U, &kp), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_prove(g, one, g, one, id, sizeof(id), &kp), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_verify(g, &kp, id, sizeof(id)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_verify(g, &kp, id, sizeof(id) - 1U), NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_verify(g, &kp, NULL, 1U), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_verify(NULL, &kp, id, sizeof(id)), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_zkp_verify(g, NULL, id, sizeof(id)), NOXTLS_RETURN_NULL);

    /* r = 0 is written as one octet (MIN length) and parses back. */
    memset(kp.r, 0, sizeof(kp.r));
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(&kp, buf, sizeof(buf), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, NOXTLS_ECJPAKE_KEY_KP_MIN_SIZE);
    UTNOX_EQUALS(noxtls_ecjpake_kp_read(buf, len, &parsed, &used), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(used, len);
    UTNOX_MEM_EQUAL(parsed.r, zero, UT_SC);
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(&kp, buf, NOXTLS_ECJPAKE_KEY_KP_MIN_SIZE - 1U, &len),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(NULL, buf, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(&kp, NULL, sizeof(buf), &len), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(&kp, buf, sizeof(buf), NULL), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_kp_read(NULL, len, &parsed, &used), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_kp_read(buf, len, NULL, &used), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_ecjpake_kp_read(buf, len, &parsed, NULL), NOXTLS_RETURN_NULL);

    /* MAX r length (32 octets) round-trips. */
    memset(kp.r, 0x7F, sizeof(kp.r));
    UTNOX_EQUALS(noxtls_ecjpake_kp_write(&kp, buf, sizeof(buf), &len), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(len, NOXTLS_ECJPAKE_KEY_KP_MAX_SIZE);
    UTNOX_EQUALS(noxtls_ecjpake_kp_read(buf, len, &parsed, &used), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(parsed.r, kp.r, UT_SC);
    return 0;
}

#if defined(_MSC_VER) && !defined(__cplusplus)
/**
 * @brief Register the tests when REGISTER_TEST cannot use constructors (MSVC-ABI C builds).
 */
void utnox_register_tests(void)
{
    register_test(__reg_test_ecjpake_password_mapping_draft_example.name,
                  __reg_test_ecjpake_password_mapping_draft_example.func);
    register_test(__reg_test_ecjpake_reference_vectors.name, __reg_test_ecjpake_reference_vectors.func);
    register_test(__reg_test_ecjpake_random_exchange_and_wrong_password.name,
                  __reg_test_ecjpake_random_exchange_and_wrong_password.func);
    register_test(__reg_test_ecjpake_init_arguments.name, __reg_test_ecjpake_init_arguments.func);
    register_test(__reg_test_ecjpake_round_one_malformed.name, __reg_test_ecjpake_round_one_malformed.func);
    register_test(__reg_test_ecjpake_round_two_malformed.name, __reg_test_ecjpake_round_two_malformed.func);
    register_test(__reg_test_ecjpake_state_and_arguments.name, __reg_test_ecjpake_state_and_arguments.func);
    register_test(__reg_test_ecjpake_identity_generator_and_key.name,
                  __reg_test_ecjpake_identity_generator_and_key.func);
    register_test(__reg_test_ecjpake_random_failures.name, __reg_test_ecjpake_random_failures.func);
    register_test(__reg_test_ecjpake_scalar_arithmetic.name, __reg_test_ecjpake_scalar_arithmetic.func);
    register_test(__reg_test_ecjpake_internal_helpers.name, __reg_test_ecjpake_internal_helpers.func);
}
#endif
