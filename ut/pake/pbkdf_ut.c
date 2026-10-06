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
* File:    pbkdf_ut.c
* Summary: PBKDF2 (RFC 8018) known-answer and negative tests
*
*
*****************************************************************************/

/**
 * @file pbkdf_ut.c
 * @brief PBKDF2-HMAC known answers (RFC 7914 section 11, RFC 6070) and argument checks.
 * @ingroup noxtls_kdf
 */

#include <stdint.h>
#include <string.h>

#include "kdf/noxtls_pbkdf.h"
#include "runner.h"
#include "test_assert.h"

/** @brief Largest derived key used by these vectors. */
#define PBKDF_UT_MAX_DK (64U)

/** @brief One PBKDF2 known-answer vector. */
typedef struct
{
    noxtls_hash_algos_t hash;  /**< HMAC hash. */
    const char *password;      /**< Password (ASCII). */
    uint32_t password_len;     /**< Password length (allows embedded NUL). */
    const char *salt;          /**< Salt (ASCII). */
    uint32_t salt_len;         /**< Salt length (allows embedded NUL). */
    uint32_t iterations;       /**< Iteration count. */
    const char *dk_hex;        /**< Expected derived key, hex. */
} pbkdf_ut_vector_t;

/**
 * @brief Decode a hex string.
 * @internal
 *
 * @param[in] hex Lower-case hex string.
 * @param[out] out Output buffer.
 * @param[in] cap Output capacity.
 *
 * @return Number of bytes decoded.
 */
static uint32_t pbkdf_ut_hex(const char *hex, uint8_t *out, uint32_t cap)
{
    uint32_t len = 0U;

    while ((hex[0] != '\0') && (hex[1] != '\0') && (len < cap)) {
        uint32_t hi = (uint32_t)((hex[0] <= '9') ? (hex[0] - '0') : (hex[0] - 'a' + 10));
        uint32_t lo = (uint32_t)((hex[1] <= '9') ? (hex[1] - '0') : (hex[1] - 'a' + 10));
        out[len] = (uint8_t)((hi << 4) | lo);
        ++len;
        hex += 2;
    }

    return len;
}

/** @brief RFC 7914 section 11, RFC 6070, and widely published PBKDF2 vectors (cross-checked with Python hashlib). */
static const pbkdf_ut_vector_t s_vectors[] = {
    /* RFC 7914 section 11, PBKDF2-HMAC-SHA256. */
    {NOXTLS_HASH_SHA_256, "passwd", 6U, "salt", 4U, 1U,
     "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
    {NOXTLS_HASH_SHA_256, "Password", 8U, "NaCl", 4U, 80000U,
     "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
     "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
    /* Common PBKDF2-HMAC-SHA256 vectors (RFC 6070 inputs with SHA-256). */
    {NOXTLS_HASH_SHA_256, "password", 8U, "salt", 4U, 1U,
     "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
    {NOXTLS_HASH_SHA_256, "password", 8U, "salt", 4U, 2U,
     "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
    {NOXTLS_HASH_SHA_256, "password", 8U, "salt", 4U, 4096U,
     "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
    {NOXTLS_HASH_SHA_256, "passwordPASSWORDpassword", 24U,
     "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36U, 4096U,
     "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
    {NOXTLS_HASH_SHA_256, "pass\0word", 9U, "sa\0lt", 5U, 4096U,
     "89b69d0516f829893c696226650a8687"},
    /* Empty password and salt. */
    {NOXTLS_HASH_SHA_256, "", 0U, "", 0U, 1U,
     "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"},
    /* Password longer than the HMAC block (hashed key), truncated second block. */
    {NOXTLS_HASH_SHA_256,
     "pppppppppppppppppppppppppppppppppppppppppppppppppp"
     "pppppppppppppppppppppppppppppppppppppppppppppppppp", 100U, "salt", 4U, 3U,
     "f598272d35e2ca276ac07694cf01636c4d643ad3075956477cfdd83eda46d9f6ff"},
    /* RFC 6070, PBKDF2-HMAC-SHA1. */
    {NOXTLS_HASH_SHA1, "password", 8U, "salt", 4U, 1U, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
    {NOXTLS_HASH_SHA1, "password", 8U, "salt", 4U, 2U, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
    {NOXTLS_HASH_SHA1, "password", 8U, "salt", 4U, 4096U, "4b007901b765489abead49d926f721d065a429c1"},
    /* SHA-384 and SHA-512. */
    {NOXTLS_HASH_SHA_384, "password", 8U, "salt", 4U, 2U,
     "54f775c6d790f21930459162fc535dbf04a939185127016a04176a0730c6f1f4"
     "fb48832ad1261baadd2cedd50814b1c8"},
    {NOXTLS_HASH_SHA_512, "password", 8U, "salt", 4U, 2U,
     "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
     "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"},
};

/**
 * @brief Every known-answer vector matches byte for byte.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_pbkdf2_known_answers)
{
    uint32_t index;

    for (index = 0U; index < (uint32_t)(sizeof(s_vectors) / sizeof(s_vectors[0])); ++index) {
        uint8_t expected[PBKDF_UT_MAX_DK];
        uint8_t dk[PBKDF_UT_MAX_DK];
        uint32_t dk_len = pbkdf_ut_hex(s_vectors[index].dk_hex, expected, PBKDF_UT_MAX_DK);

        memset(dk, 0xA5, sizeof(dk));
        UTNOX_EQUALS(noxtls_pbkdf2_hmac(s_vectors[index].hash,
                                        (const uint8_t *)s_vectors[index].password,
                                        s_vectors[index].password_len,
                                        (const uint8_t *)s_vectors[index].salt,
                                        s_vectors[index].salt_len,
                                        s_vectors[index].iterations, dk, dk_len),
                     NOXTLS_RETURN_SUCCESS);
        UTNOX_MEM_EQUAL(dk, expected, dk_len);
        /* Bytes past dk_len are untouched. */
        if (dk_len < PBKDF_UT_MAX_DK) {
            UTNOX_EQUALS(dk[dk_len], 0xA5U);
        }
    }

    return 0;
}

/**
 * @brief NULL pointers, bad algorithm, zero iterations and zero length are rejected.
 *
 * @return 0 on success.
 */
REGISTER_TEST(test_pbkdf2_invalid_arguments)
{
    uint8_t dk[32];
    const uint8_t pw[4] = {1U, 2U, 3U, 4U};

    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, pw, 4U, pw, 4U, 1U, NULL, 32U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, NULL, 4U, pw, 4U, 1U, dk, 32U),
                 NOXTLS_RETURN_NULL);
    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, pw, 4U, NULL, 4U, 1U, dk, 32U),
                 NOXTLS_RETURN_NULL);

    memset(dk, 0xA5, sizeof(dk));
    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_MD5, pw, 4U, pw, 4U, 1U, dk, 32U),
                 NOXTLS_RETURN_INVALID_ALGORITHM);
    UTNOX_MEM_VALUE(dk, 0U, sizeof(dk));

    memset(dk, 0xA5, sizeof(dk));
    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, pw, 4U, pw, 4U, 0U, dk, 32U),
                 NOXTLS_RETURN_INVALID_PARAM);
    UTNOX_MEM_VALUE(dk, 0U, sizeof(dk));

    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, pw, 4U, pw, 4U, 1U, dk, 0U),
                 NOXTLS_RETURN_INVALID_PARAM);

    /* NULL password / salt with zero length are valid empty inputs. */
    UTNOX_EQUALS(noxtls_pbkdf2_hmac(NOXTLS_HASH_SHA_256, NULL, 0U, NULL, 0U, 1U, dk, 32U),
                 NOXTLS_RETURN_SUCCESS);
    return 0;
}
