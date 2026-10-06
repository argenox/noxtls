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
* File:    test_ut_ref.c
* Summary: Checks of the mock oracle against FIPS 197 / FIPS 180-4 examples
*
*****************************************************************************/


/**
 * @file test_ut_ref.c
 * @brief Checks the mock's oracle against FIPS 197 Appendix C and FIPS 180-4 examples.
 * @ingroup noxtls_nrf54_ut
 *
 * Vectors: FIPS 197 (Nov 2001, upd. 2023) Appendix C.1-C.3; NIST CSRC "Example
 * Algorithms" for FIPS 180-4 (SHA224/256/384/512.pdf): "abc", the 448-bit and
 * 896-bit two-block messages and the empty message.
 */

#include <stdint.h>
#include <string.h>

#include "runner.h"
#include "test_assert.h"

#include "ut_nrf54_ref.h"

/** FIPS 197 C plaintext. */
static const char * const s_c_pt = "00112233445566778899aabbccddeeff";
/** FIPS 197 C keys (prefixes of 000102..1f). */
static const char * const s_c_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/**
 * @brief Check one FIPS 197 Appendix C vector in both directions.
 * @internal
 *
 * @param[in] key_len Key bytes.
 * @param[in] ct_hex  Expected ciphertext.
 *
 * @return 0 when both directions match.
 */
static int ut_check_c(uint32_t key_len, const char * ct_hex)
{
    ut_aes_key_t k;
    uint8_t key[32];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t out[16];

    (void)ut_hex(s_c_key, key, sizeof(key));
    (void)ut_hex(s_c_pt, pt, sizeof(pt));
    (void)ut_hex(ct_hex, ct, sizeof(ct));
    if (ut_aes_setkey(&k, key, key_len) != 0) {
        return 1;
    }
    ut_aes_encrypt(&k, pt, out);
    if (memcmp(out, ct, 16U) != 0) {
        return 2;
    }
    ut_aes_decrypt(&k, ct, out);
    return (memcmp(out, pt, 16U) == 0) ? 0 : 3;
}

REGISTER_TEST(test_ref_aes_fips197)
{
    ut_aes_key_t k;
    uint8_t key[16] = { 0 };

    UTNOX_EQUALS(ut_check_c(16U, "69c4e0d86a7b0430d8cdb78070b4c55a"), 0);
    UTNOX_EQUALS(ut_check_c(24U, "dda97ca4864cdfe06eaf70a0ec0d7191"), 0);
    UTNOX_EQUALS(ut_check_c(32U, "8ea2b7ca516745bfeafc49904b496089"), 0);
    UTNOX_EQUALS(ut_aes_setkey(&k, key, 15U), -1);
    return 0;
}

/**
 * @brief Check a SHA-2 digest of a text message.
 * @internal
 *
 * @param[in] bits Digest bits.
 * @param[in] msg  Message text.
 * @param[in] hex  Expected digest.
 *
 * @return 0 when it matches.
 */
static int ut_check_sha(uint32_t bits, const char * msg, const char * hex)
{
    uint8_t exp[64];
    uint8_t got[64];

    (void)ut_hex(hex, exp, sizeof(exp));
    ut_sha(bits, (const uint8_t *)msg, (uint32_t)strlen(msg), got);
    return memcmp(exp, got, bits / 8U);
}

/** FIPS 180-4 448-bit example message. */
const char * const g_ut_msg448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
/** FIPS 180-4 896-bit example message. */
const char * const g_ut_msg896 =
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

REGISTER_TEST(test_ref_sha2_examples)
{
    uint8_t state[64];

    UTNOX_EQUALS(ut_check_sha(256U, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), 0);
    UTNOX_EQUALS(ut_check_sha(256U, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), 0);
    UTNOX_EQUALS(ut_check_sha(256U, g_ut_msg448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), 0);
    UTNOX_EQUALS(ut_check_sha(224U, "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"), 0);
    UTNOX_EQUALS(ut_check_sha(224U, g_ut_msg448, "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"), 0);
    UTNOX_EQUALS(ut_check_sha(384U, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                                           "8086072ba1e7cc2358baeca134c825a7"), 0);
    UTNOX_EQUALS(ut_check_sha(384U, g_ut_msg896, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
                                                  "fcc7c71a557e2db966c3e9fa91746039"), 0);
    UTNOX_EQUALS(ut_check_sha(512U, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"), 0);
    UTNOX_EQUALS(ut_check_sha(512U, g_ut_msg896, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                                                  "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"), 0);
    UTNOX_EQUALS(ut_check_sha(512U, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                                        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"), 0);
    UTNOX_EQUALS(ut_sha_iv(1U, state), 0U);
    UTNOX_EQUALS(ut_hex("zz 0", state, 4U), 0U);
    UTNOX_EQUALS(ut_hex("AbCd", state, 1U), 1U);
    UTNOX_EQUALS(state[0], 0xABU);
    return 0;
}
