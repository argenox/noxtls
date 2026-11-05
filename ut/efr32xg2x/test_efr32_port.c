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
* File:    test_efr32_port.c
* Summary: Tests of the NoxTLS accelerator ports through the public NoxTLS APIs
*
*****************************************************************************/

/**
 * @file test_efr32_port.c
 * @brief AES (block, ECB / CBC / CTR, GCM via the block hook, CCM), SHA-2, DRBG entropy,
 *        point multiplication, ECDH and ECDSA called through the NoxTLS APIs: hardware
 *        results equal the software results and the published vectors, and every
 *        failure, busy engine or unsupported request ends in the software path.
 * @ingroup noxtls_efr32_ut
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_efr32_mock.h"
#include "common/noxtls_accel_port.h"
#include "drbg/noxtls_drbg.h"
#include "noxtls_aes.h"
#include "noxtls_aes_ccm.h"
#include "noxtls_aes_gcm.h"
#include "noxtls_ecdh.h"
#include "noxtls_ecdsa.h"
#include "noxtls_sha.h"

REGISTER_TEST(test_port_switches_follow_the_backend)
{
    UTNOX_EQUALS(NOXTLS_FEATURE_EFR32XG2X_HW_ACCEL, 1);
    UTNOX_EQUALS(NOXTLS_PORT_AES_MODE_ACCEL, 1);
    UTNOX_EQUALS(NOXTLS_PORT_AES_CCM_ACCEL, 1);
    UTNOX_EQUALS(NOXTLS_PORT_SHA256_ACCEL, 1);
    UTNOX_EQUALS(NOXTLS_PORT_SHA512_ACCEL, 1);
    UTNOX_EQUALS(NOXTLS_PORT_ENTROPY_ACCEL, 1);
    /* Ed25519 verification keeps its software path: the SE hashes the message itself. */
    UTNOX_EQUALS(NOXTLS_PORT_ED25519_ACCEL, 0);
    return 0;
}

REGISTER_TEST(test_port_aes_modes_via_noxtls_api)
{
    uint8_t ct[32];

    ut_setup();
    (void)ut_hex("2b7e151628aed2a6abf7158809cf4f3c", g_ut_ram.aux);
    (void)ut_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", g_ut_ram.in);
    (void)ut_hex("000102030405060708090a0b0c0d0e0f", g_ut_ram.aux2);
    UTNOX_EQUALS(noxtls_aes_encrypt_cbc(g_ut_ram.aux, g_ut_ram.in, 32U, g_ut_ram.aux2, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    (void)ut_hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2", ct);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 32U);
    UTNOX_EQUALS(g_ut.aes_jobs, 1U);
    UTNOX_EQUALS(noxtls_aes_decrypt_cbc(g_ut_ram.aux, g_ut_ram.out, 32U, g_ut_ram.aux2, &g_ut_ram.out[64], NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(&g_ut_ram.out[64], g_ut_ram.in, 32U);
    UTNOX_EQUALS(g_ut.aes_jobs, 2U);
    (void)ut_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", g_ut_ram.aux2);
    UTNOX_EQUALS(noxtls_aes_encrypt_ctr(g_ut_ram.aux, g_ut_ram.in, 32U, g_ut_ram.aux2, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    (void)ut_hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff", ct);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 32U);
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(g_ut_ram.aux, g_ut_ram.in, 32U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_decrypt_ecb(g_ut_ram.aux, g_ut_ram.out, 32U, NULL, &g_ut_ram.out[64], NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(&g_ut_ram.out[64], g_ut_ram.in, 32U);
    UTNOX_EQUALS(g_ut.aes_jobs, 5U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_aes_busy_engine_is_served_by_software)
{
    uint8_t ct[16];

    ut_setup();
    (void)ut_hex("000102030405060708090a0b0c0d0e0f", g_ut_ram.aux);
    (void)ut_hex("00112233445566778899aabbccddeeff", g_ut_ram.in);
    (void)ut_hex("69c4e0d86a7b0430d8cdb78070b4c55a", ct);
    /* The link layer owns RADIOAES: noxtls does not wait, the result is the same. */
    UTNOX_EQUALS(noxtls_efr32_aes_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(g_ut_ram.aux, g_ut_ram.in, 16U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 16U);
    UTNOX_EQUALS(g_ut.aes_jobs, 0U);
    noxtls_efr32_aes_release();
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(g_ut_ram.aux, g_ut_ram.in, 16U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 16U);
    UTNOX_EQUALS(g_ut.aes_jobs, 1U);
    /* A faulty engine fails the hardware request but never corrupts a later software one. */
    g_ut.aes_bus_error = 1U;
    UTNOX_NOT_EQUALS(noxtls_aes_encrypt_ecb(g_ut_ram.aux, g_ut_ram.in, 16U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    g_ut.aes_bus_error = 0U;
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_AES, 0U);
    UTNOX_EQUALS(noxtls_aes_encrypt_ecb(g_ut_ram.aux, g_ut_ram.in, 16U, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 16U);
    return 0;
}

REGISTER_TEST(test_port_aes_single_block_hooks)
{
    uint8_t ct[16];
    uint8_t pt[16];

    ut_setup();
    (void)ut_hex("000102030405060708090a0b0c0d0e0f", g_ut_ram.aux);
    (void)ut_hex("00112233445566778899aabbccddeeff", pt);
    (void)ut_hex("69c4e0d86a7b0430d8cdb78070b4c55a", ct);
    (void)memcpy(g_ut_ram.in, pt, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_port_decrypt_block(g_ut_ram.aux, g_ut_ram.out, g_ut_ram.in, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 16U);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(NULL, g_ut_ram.in, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(g_ut_ram.aux, NULL, g_ut_ram.out, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(g_ut_ram.aux, g_ut_ram.in, NULL, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, (noxtls_aes_type_t)99), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_block(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, NOXTLS_AES_192_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Multi-block hook. */
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(NULL, g_ut_ram.in, g_ut_ram.out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(g_ut_ram.aux, NULL, g_ut_ram.out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(g_ut_ram.aux, g_ut_ram.in, NULL, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, 0x10000000U, NOXTLS_AES_128_BIT),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, 3U, NOXTLS_AES_192_BIT), NOXTLS_RETURN_NOT_SUPPORTED);
    /* A hardware error after output was written is FAILED (not retried in software). */
    g_ut.aes_bus_error = 1U;
    UTNOX_EQUALS(noxtls_aes_accel_port_encrypt_blocks(g_ut_ram.aux, g_ut_ram.in, g_ut_ram.out, 3U, NOXTLS_AES_128_BIT), NOXTLS_RETURN_FAILED);
    g_ut.aes_bus_error = 0U;
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_aes_mode_hook_arguments)
{
    ut_setup();
    (void)ut_hex("000102030405060708090a0b0c0d0e0f", g_ut_ram.aux);
    ut_hex("00112233445566778899aabbccddeeff", g_ut_ram.in);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, g_ut_ram.aux2, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_SUCCESS);
    /* CBC with a NULL IV is a zero IV for the hook. */
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CBC, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_CTR, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, NULL, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, NULL, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, NULL),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 0U, g_ut_ram.out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port((noxtls_aes_accel_mode_t)9, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 15U, g_ut_ram.out),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.aes_hang = 1U;
    UTNOX_EQUALS(noxtls_aes_mode_accel_port(NOXTLS_AES_ACCEL_MODE_ECB, 0U, g_ut_ram.aux, NOXTLS_AES_128_BIT, NULL, g_ut_ram.in, 16U, g_ut_ram.out),
                 NOXTLS_RETURN_FAILED);
    g_ut.aes_hang = 0U;
    return 0;
}

REGISTER_TEST(test_port_gcm_runs_in_software_through_the_block_hook)
{
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t aad[20];
    uint8_t pt[60];
    uint8_t ct[60];
    uint8_t tag[16];
    uint8_t out[60];
    uint8_t tg[16];

    ut_setup();
    (void)ut_hex("feffe9928665731c6d6a8f9467308308", key);
    (void)ut_hex("cafebabefacedbaddecaf888", iv);
    (void)ut_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
    (void)ut_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", pt);
    (void)ut_hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", ct);
    (void)ut_hex("5bc94fbc3221a5db94fae95ae7121a47", tag);
    (void)memcpy(g_ut_ram.aux, key, 16U);
    (void)memcpy(g_ut_ram.in, pt, 60U);
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, iv, aad, 20U, g_ut_ram.in, 60U, g_ut_ram.out, tg), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, ct, 60U);
    UTNOX_MEM_EQUAL(tg, tag, 16U);
    /* H, the keystream blocks and the tag mask go through the block hook: 1 + 4 + 1 jobs. */
    UTNOX_EQUALS(g_ut.aes_jobs, 6U);
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, iv, aad, 20U, ct, 60U, tag, out), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(out, pt, 60U);
    tg[0] ^= 1U;
    UTNOX_NOT_EQUALS(noxtls_aes_gcm_decrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, iv, aad, 20U, ct, 60U, tg, out), NOXTLS_RETURN_SUCCESS);
    /* The port hooks themselves decline. */
    UTNOX_EQUALS(noxtls_aes_gcm_encrypt_accel_port(key, NOXTLS_AES_128_BIT, iv, aad, 20U, pt, 60U, out, tg), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_gcm_decrypt_accel_port(key, NOXTLS_AES_128_BIT, iv, aad, 20U, ct, 60U, tag, out), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_ccm_via_noxtls_api)
{
    uint8_t key[16];
    uint8_t nonce[7];
    uint8_t aad[8];
    uint8_t pt[4];
    uint8_t expect[8];
    uint8_t tag[16];
    uint8_t out[16];

    ut_setup();
    (void)ut_hex("404142434445464748494a4b4c4d4e4f", key);
    (void)ut_hex("10111213141516", nonce);
    (void)ut_hex("0001020304050607", aad);
    (void)ut_hex("20212223", pt);
    (void)ut_hex("7162015b4dac255d", expect);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(key, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, pt, 4U, out, tag, 4U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(out, expect, 4U);
    UTNOX_MEM_EQUAL(tag, &expect[4], 4U);
    /* Key, AAD and payload on the stack: the key is copied and the small buffers are bounced, so the engine still runs. */
    UTNOX_EQUALS(g_ut.aes_jobs, 1U);
    (void)memcpy(g_ut_ram.aux, key, 16U);
    (void)memcpy(g_ut_ram.in, pt, 4U);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, g_ut_ram.in, 4U, g_ut_ram.out, tag, 4U),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.out, expect, 4U);
    UTNOX_MEM_EQUAL(tag, &expect[4], 4U);
    UTNOX_EQUALS(g_ut.aes_jobs, 2U);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, g_ut_ram.out, 4U, tag, 4U, g_ut_ram.in),
                 NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(g_ut_ram.in, pt, 4U);
    tag[0] ^= 1U;
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt(g_ut_ram.aux, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, g_ut_ram.out, 4U, tag, 4U, g_ut_ram.in),
                 NOXTLS_RETURN_BAD_DATA);
    /* Port hook arguments. */
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(g_ut_ram.aux, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, g_ut_ram.out, 4U, NULL, 4U, g_ut_ram.in),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_ccm_decrypt_accel_port(g_ut_ram.aux, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, g_ut_ram.out, 4U, tag, 17U, g_ut_ram.in),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(g_ut_ram.aux, NOXTLS_AES_192_BIT, nonce, 7U, aad, 8U, g_ut_ram.in, 4U, g_ut_ram.out, tag, 4U),
                 NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.aes_bus_error = 1U;
    UTNOX_EQUALS(noxtls_aes_ccm_encrypt_accel_port(g_ut_ram.aux, NOXTLS_AES_128_BIT, nonce, 7U, aad, 8U, g_ut_ram.in, 4U, g_ut_ram.out, tag, 4U),
                 NOXTLS_RETURN_FAILED);
    g_ut.aes_bus_error = 0U;
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

/**
 * @brief Digest of a message through the SHA API, hardware path or forced software.
 * @internal
 *
 * @param[in]  algo Algorithm.
 * @param[in]  msg  Message.
 * @param[in]  len  Bytes.
 * @param[in]  sw   Non-zero to force software.
 * @param[out] out  Digest.
 */
static void ut_digest(noxtls_hash_algos_t algo, const uint8_t *msg, uint32_t len, uint8_t sw, uint8_t *out)
{
    noxtls_sha_ctx_t ctx;

    if (sw != 0U) {
        ut_sw_begin();
    }
    (void)noxtls_sha_init(&ctx, algo);
    (void)noxtls_sha_update(&ctx, msg, len);
    (void)noxtls_sha_finish(&ctx, out);
    if (sw != 0U) {
        ut_sw_end();
    }
}

REGISTER_TEST(test_port_sha2_hardware_equals_software)
{
    static uint8_t msg[5000];
    static const noxtls_hash_algos_t algos[] = { NOXTLS_HASH_SHA_224, NOXTLS_HASH_SHA_256, NOXTLS_HASH_SHA_384, NOXTLS_HASH_SHA_512 };
    static const uint32_t lens[] = { 0U, 1U, 55U, 56U, 63U, 64U, 65U, 127U, 128U, 129U, 200U, 1000U, 5000U };
    uint8_t a[64];
    uint8_t b[64];
    uint32_t i;
    uint32_t j;

    ut_setup();
    for (i = 0U; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 31U);
    }
    for (i = 0U; i < (sizeof(algos) / sizeof(algos[0])); i++) {
        for (j = 0U; j < (sizeof(lens) / sizeof(lens[0])); j++) {
            ut_digest(algos[i], msg, lens[j], 0U, a);
            ut_digest(algos[i], msg, lens[j], 1U, b);
            UTNOX_MEM_EQUAL(a, b, (algos[i] == NOXTLS_HASH_SHA_224) ? 28U : ((algos[i] == NOXTLS_HASH_SHA_256) ? 32U :
                                                                          ((algos[i] == NOXTLS_HASH_SHA_384) ? 48U : 64U)));
        }
    }
    UTNOX_IS_TRUE(g_ut.se_hash_blocks > 100U);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_sha2_small_calls_stay_in_software)
{
    static uint8_t msg[128];
    uint8_t d[32];

    ut_setup();
    (void)memset(msg, 0x61, sizeof(msg));
    /* One block per hook call is below NOXTLS_EFR32_CONFIG_SE_HASH_MIN_BLOCKS. */
    ut_digest(NOXTLS_HASH_SHA_256, msg, 64U, 0U, d);
    UTNOX_EQUALS(g_ut.se_cmds, 0U);
    ut_digest(NOXTLS_HASH_SHA_256, msg, 128U, 0U, d);
    UTNOX_EQUALS(g_ut.se_cmds, 1U);
    return 0;
}

REGISTER_TEST(test_port_sha2_fallbacks)
{
    static uint8_t msg[512];
    uint8_t a[32];
    uint8_t b[32];
    uint8_t stack_msg[256];

    ut_setup();
    (void)memset(msg, 0x5C, sizeof(msg));
    (void)memset(stack_msg, 0x5C, sizeof(stack_msg));
    ut_digest(NOXTLS_HASH_SHA_256, msg, sizeof(msg), 1U, b);
    /* SE busy (BlueNox owns it), SE error, SE unit disabled, operation disabled, unreachable data. */
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    ut_digest(NOXTLS_HASH_SHA_256, msg, sizeof(msg), 0U, a);
    UTNOX_MEM_EQUAL(a, b, 32U);
    noxtls_efr32_se_release();
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    ut_digest(NOXTLS_HASH_SHA_256, msg, sizeof(msg), 0U, a);
    UTNOX_MEM_EQUAL(a, b, 32U);
    g_ut.se_force = 0U;
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_SE, 0U);
    ut_digest(NOXTLS_HASH_SHA_256, msg, sizeof(msg), 0U, a);
    UTNOX_MEM_EQUAL(a, b, 32U);
    noxtls_efr32_set_enabled(NOXTLS_EFR32_UNIT_SE, 1U);
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_SHA256);
    ut_digest(NOXTLS_HASH_SHA_256, msg, sizeof(msg), 0U, a);
    UTNOX_MEM_EQUAL(a, b, 32U);
    noxtls_efr32_set_ops_disabled(0U);
    g_ut.se_cmds = 0U;
    ut_digest(NOXTLS_HASH_SHA_256, stack_msg, sizeof(stack_msg), 0U, a);
    ut_digest(NOXTLS_HASH_SHA_256, stack_msg, sizeof(stack_msg), 1U, b);
    UTNOX_MEM_EQUAL(a, b, 32U);
    UTNOX_EQUALS(g_ut.se_cmds, 0U);
    return 0;
}

REGISTER_TEST(test_port_sha_hook_arguments)
{
    static uint8_t msg[256];
    noxtls_sha_ctx_t ctx;
    noxtls_sha512_ctx_t c5;

    ut_setup();
    (void)noxtls_sha_init(&ctx, NOXTLS_HASH_SHA_256);
    (void)noxtls_sha512_init(&c5, NOXTLS_HASH_SHA_512);
    UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(NULL, msg, 4U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(&ctx, NULL, 4U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(&ctx, msg, 0U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha256_round_accel_port(&ctx, msg), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha256_blocks_accel_port(&ctx, msg, 4U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(NULL, msg, 2U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(&c5, NULL, 2U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(&c5, msg, 0U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(&c5, msg, 1U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_sha512_blocks_accel_port(&c5, msg, 2U), NOXTLS_RETURN_SUCCESS);
    return 0;
}

REGISTER_TEST(test_port_drbg_entropy)
{
    uint8_t a[48];
    uint8_t b[48];

    ut_setup();
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(a, sizeof(a)), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(b, sizeof(b)), NOXTLS_RETURN_SUCCESS);
    UTNOX_IS_TRUE(memcmp(a, b, sizeof(a)) != 0);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(NULL, 16U), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(a, sizeof(a)), NOXTLS_RETURN_NOT_SUPPORTED);
    noxtls_efr32_se_release();
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    UTNOX_EQUALS(noxtls_drbg_entropy_accel_port(a, sizeof(a)), NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.se_force = 0U;
    return 0;
}

REGISTER_TEST(test_port_ecc_keygen_matches_rfc6979_public_key)
{
    uint8_t d[32];
    uint8_t qx[32];
    uint8_t qy[32];
    ecc_key_t key;

    ut_setup();
    (void)ut_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", d);
    (void)ut_hex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6", qx);
    (void)ut_hex("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", qy);
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(key.Q.x, qx, 32U);
    UTNOX_MEM_EQUAL(key.Q.y, qy, 32U);
    /* Point multiplication ran twice in the SE (double check). */
    UTNOX_EQUALS(g_ut.se_cmds, 2U);
    UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_DH);
    UTNOX_EQUALS(noxtls_ecc_accel_is_ready(), 1);
    UTNOX_IS_TRUE(noxtls_ecc_accel_operation_count() >= 1U);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), (int32_t)NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_accel_last_stage(), 4U);
    UTNOX_EQUALS(noxtls_ecc_accel_input_echo_ok(), 1);
    UTNOX_EQUALS(noxtls_ecc_accel_last_status(), noxtls_efr32_stats()->se_errors);
    (void)noxtls_ecc_key_free(&key);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_ecc_fallbacks_still_give_the_right_point)
{
    uint8_t d[32];
    uint8_t qx[32];
    ecc_key_t key;
    uint32_t fb;

    ut_setup();
    (void)ut_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", d);
    (void)ut_hex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6", qx);
    /* Double-check mismatch (a transient fault): the port declines and software recomputes. */
    g_ut.se_wrong_mul = 1U;
    fb = noxtls_ecc_accel_fallback_count();
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(key.Q.x, qx, 32U);
    UTNOX_IS_TRUE(noxtls_ecc_accel_fallback_count() > fb);
    UTNOX_EQUALS(noxtls_ecc_accel_last_rc(), (int32_t)NOXTLS_RETURN_NOT_SUPPORTED);
    (void)noxtls_ecc_key_free(&key);
    g_ut.se_wrong_mul = 0U;
    /* Busy mailbox, SE error, operation disabled. */
    UTNOX_EQUALS(noxtls_efr32_se_acquire(), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(key.Q.x, qx, 32U);
    (void)noxtls_ecc_key_free(&key);
    noxtls_efr32_se_release();
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_CRYPTO_ERROR;
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(key.Q.x, qx, 32U);
    (void)noxtls_ecc_key_free(&key);
    g_ut.se_force = 0U;
    noxtls_efr32_set_ops_disabled(NOXTLS_EFR32_OP_ECC_MUL);
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_MEM_EQUAL(key.Q.x, qx, 32U);
    (void)noxtls_ecc_key_free(&key);
    noxtls_efr32_set_ops_disabled(0U);
    return 0;
}

REGISTER_TEST(test_port_ecc_point_multiply_hook_arguments)
{
    ecc_point_t pt;
    ecc_point_t res;
    uint8_t k[32] = { 0U };
    const ecc_curve_params_t *p256;
    const ecc_curve_params_t *k1;
    ecc_curve_params_t caller;

    ut_setup();
    p256 = noxtls_ecc_curve_get(NOXTLS_ECC_SECP256R1);
    k1 = noxtls_ecc_curve_get(NOXTLS_ECC_SECP256K1);
    UTNOX_IS_TRUE(p256 != NULL);
    UTNOX_IS_TRUE(k1 != NULL);
    k[31] = 2U;
    pt = p256->G;
    (void)memset(&res, 0, sizeof(res));
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, &pt, p256), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(res.size, 32U);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(NULL, k, &pt, p256), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, NULL, &pt, p256), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, NULL, p256), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, &pt, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    /* Not an NIST curve of the SE: secp256k1 has the same size but another prime. */
    pt = k1->G;
    g_ut.se_cmds = 0U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, &pt, k1), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(g_ut.se_cmds, 0U);
    /* A caller-built curve without a prime, and a point of the wrong size. */
    caller = *p256;
    caller.p = NULL;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, &p256->G, &caller), NOXTLS_RETURN_NOT_SUPPORTED);
    pt = p256->G;
    pt.size = 24U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, &pt, p256), NOXTLS_RETURN_NOT_SUPPORTED);
    /* A curve whose size is a SE size but whose prime is not (P-384 size with the P-256 prime pointer). */
    caller = *p256;
    caller.size = 48U;
    UTNOX_EQUALS(noxtls_ecc_point_multiply_accel_port(&res, k, &p256->G, &caller), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_ecdh_p256_p384_agree_and_match_software)
{
    ecc_key_t a;
    ecc_key_t b;
    uint8_t s1[48];
    uint8_t s2[48];
    uint8_t s3[48];
    uint32_t l1;
    uint32_t l2;
    uint32_t l3;
    uint32_t c;

    ut_setup();
    for (c = 0U; c < 2U; c++) {
        ecc_curve_t id = (c == 0U) ? NOXTLS_ECC_SECP256R1 : NOXTLS_ECC_SECP384R1;
        uint32_t sz = (c == 0U) ? 32U : 48U;
        uint8_t da[48];
        uint8_t db[48];

        (void)memset(da, 0x21, sizeof(da));
        (void)memset(db, 0x37, sizeof(db));
        da[0] = 0x01U;
        db[0] = 0x02U;
        UTNOX_EQUALS(noxtls_ecc_key_import_private(&a, id, da, sz), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(noxtls_ecc_key_import_private(&b, id, db, sz), NOXTLS_RETURN_SUCCESS);
        l1 = sizeof(s1);
        l2 = sizeof(s2);
        l3 = sizeof(s3);
        g_ut.se_cmds = 0U;
        UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret(&a, &b.Q, s1, &l1), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.se_cmds, 1U);
        UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret(&b, &a.Q, s2, &l2), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(l1, sz);
        UTNOX_EQUALS(l2, sz);
        UTNOX_MEM_EQUAL(s1, s2, sz);
        ut_sw_begin();
        UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret(&a, &b.Q, s3, &l3), NOXTLS_RETURN_SUCCESS);
        ut_sw_end();
        UTNOX_MEM_EQUAL(s1, s3, sz);
        /* The point at infinity from the SE is never published: software decides. */
        g_ut.se_infinity = 1U;
        l1 = sizeof(s1);
        (void)memset(s1, 0, sizeof(s1));
        UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret(&a, &b.Q, s1, &l1), NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(s1, s3, sz);
        g_ut.se_infinity = 0U;
        (void)noxtls_ecc_key_free(&a);
        (void)noxtls_ecc_key_free(&b);
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_ecdh_hook_arguments)
{
    ecc_key_t a;
    uint8_t d[32];
    uint8_t s[32];
    uint32_t l = sizeof(s);

    ut_setup();
    (void)memset(d, 0x21, sizeof(d));
    d[0] = 0x01U;
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&a, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(NULL, &a.Q, s, &l), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(&a, NULL, s, &l), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(&a, &a.Q, NULL, &l), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(&a, &a.Q, s, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    l = 16U;
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(&a, &a.Q, s, &l), NOXTLS_RETURN_NOT_SUPPORTED);
    l = sizeof(s);
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(&a, &a.Q, s, &l), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(l, 32U);
    g_ut.se_force = 1U;
    g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
    l = sizeof(s);
    UTNOX_EQUALS(noxtls_ecdh_compute_shared_secret_accel_port(&a, &a.Q, s, &l), NOXTLS_RETURN_NOT_SUPPORTED);
    g_ut.se_force = 0U;
    (void)noxtls_ecc_key_free(&a);
    return 0;
}

REGISTER_TEST(test_port_ecdsa_sign_verify_via_noxtls_api)
{
    uint8_t d[48];
    uint8_t h[48];
    ecc_key_t key;
    ecdsa_signature_t sig;
    uint32_t c;

    ut_setup();
    for (c = 0U; c < 2U; c++) {
        ecc_curve_t id = (c == 0U) ? NOXTLS_ECC_SECP256R1 : NOXTLS_ECC_SECP384R1;
        uint32_t sz = (c == 0U) ? 32U : 48U;

        (void)memset(d, 0x19, sizeof(d));
        d[0] = 0x01U;
        (void)memset(h, 0x6D, sizeof(h));
        UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, id, d, sz), NOXTLS_RETURN_SUCCESS);
        (void)memset(&sig, 0, sizeof(sig));
        g_ut.se_cmds = 0U;
        UTNOX_EQUALS(noxtls_ecdsa_sign_digest(&key, h, sz, &sig), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.se_cmds, 1U);
        UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_SIGN);
        UTNOX_EQUALS(sig.size, sz);
        UTNOX_EQUALS(noxtls_ecdsa_verify_digest(&key, h, sz, &sig), NOXTLS_RETURN_SUCCESS);
        UTNOX_EQUALS(g_ut.se_cmds, 2U);
        UTNOX_EQUALS(g_ut.se_last_cmd, NOXTLS_EFR32_SE_CMD_VERIFY);
        ut_sw_begin();
        UTNOX_EQUALS(noxtls_ecdsa_verify_digest(&key, h, sz, &sig), NOXTLS_RETURN_SUCCESS);
        ut_sw_end();
        /* Tampered signature: the SE verdict is final. */
        sig.s[sz - 1U] ^= 1U;
        UTNOX_EQUALS(noxtls_ecdsa_verify_digest(&key, h, sz, &sig), NOXTLS_RETURN_FAILED);
        sig.s[sz - 1U] ^= 1U;
        /* Verify error responses other than "invalid signature" fall back to software, which accepts it. */
        g_ut.se_force = 1U;
        g_ut.se_force_resp = NOXTLS_EFR32_SE_RESP_INTERNAL;
        UTNOX_EQUALS(noxtls_ecdsa_verify_digest(&key, h, sz, &sig), NOXTLS_RETURN_SUCCESS);
        /* Sign falls back to software on an SE error and the signature is still valid. */
        (void)memset(&sig, 0, sizeof(sig));
        UTNOX_EQUALS(noxtls_ecdsa_sign_digest(&key, h, sz, &sig), NOXTLS_RETURN_SUCCESS);
        g_ut.se_force = 0U;
        UTNOX_EQUALS(noxtls_ecdsa_verify_digest(&key, h, sz, &sig), NOXTLS_RETURN_SUCCESS);
        (void)noxtls_ecc_key_free(&key);
    }
    UTNOX_IS_TRUE(ut_clean() != 0U);
    return 0;
}

REGISTER_TEST(test_port_ecdsa_hook_arguments)
{
    uint8_t d[32];
    uint8_t h[32];
    ecc_key_t key;
    ecc_key_t k1;
    ecdsa_signature_t sig;

    ut_setup();
    (void)memset(d, 0x19, sizeof(d));
    d[0] = 0x01U;
    (void)memset(h, 0x6D, sizeof(h));
    (void)memset(&sig, 0, sizeof(sig));
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&key, NOXTLS_ECC_SECP256R1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecc_key_import_private(&k1, NOXTLS_ECC_SECP256K1, d, 32U), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(NULL, h, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, NULL, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, h, 32U, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, h, 31U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&k1, h, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_sign_accel_port(&key, h, 32U, &sig), NOXTLS_RETURN_SUCCESS);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(NULL, h, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, NULL, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, h, 32U, NULL), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, h, 20U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&k1, h, 32U, &sig), NOXTLS_RETURN_NOT_SUPPORTED);
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, h, 32U, &sig), NOXTLS_RETURN_SUCCESS);
    sig.r[0] ^= 0x01U;
    UTNOX_EQUALS(noxtls_ecdsa_verify_accel_port(&key, h, 32U, &sig), NOXTLS_RETURN_FAILED);
    (void)noxtls_ecc_key_free(&key);
    (void)noxtls_ecc_key_free(&k1);
    return 0;
}
