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
* File:    ut_nrf54_vectors.h
* Summary: Known-answer vectors of the CRACEN backend tests
*
*****************************************************************************/


/**
 * @file ut_nrf54_vectors.h
 * @brief Known-answer vectors for the CRACEN PKE and AEAD drivers (host tests
 *        and the on-target hardware test plan).
 * @ingroup noxtls_nrf54_ut
 *
 * Every vector was re-checked with the Python "cryptography" package (46.0.5)
 * before being recorded here:
 * - AES-GCM: "The Galois/Counter Mode of Operation" (McGrew, Viega; NIST
 *   modes submission) test cases 1, 2, 4, 10 and 16;
 * - AES-CCM: NIST SP 800-38C Appendix C Examples 1-3, RFC 3610 §8 Packet
 *   Vector #1, plus generated edge cases (no AAD, no payload, AES-256, 4/8-byte
 *   GCM tags and a 0xFF00-byte AAD with the 6-byte AAD length encoding);
 * - ECDSA P-256 / SHA-256: RFC 6979 §A.2.5 (messages "sample" and "test");
 * - Ed25519: RFC 8032 §7.1 TEST 1, 2 and 3.
 * Hex strings are parsed with ut_hex().
 */

#ifndef UT_NRF54_VECTORS_H
#define UT_NRF54_VECTORS_H

#include <stdint.h>

#if defined(__GNUC__)
/** @brief Tables are included by several test files; not every file uses all of them. */
#define UT_VEC_MAYBE_UNUSED __attribute__((unused))
#else
#define UT_VEC_MAYBE_UNUSED
#endif

/** One AEAD known-answer vector. */
typedef struct {
    uint32_t alg;          /**< 0 = GCM, 1 = CCM. */
    const char * key;      /**< Key (hex). */
    const char * nonce;    /**< IV / nonce (hex). */
    const char * aad;      /**< AAD (hex, "" for none). */
    const char * pt;       /**< Plaintext (hex). */
    const char * ct;       /**< Ciphertext (hex). */
    const char * tag;      /**< Tag (hex, its length is the tag length). */
} ut_aead_vec_t;

/** Plaintext of GCM test cases 4, 10 and 16. */
#define UT_GCM_P4 "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
/** AAD of GCM test cases 4, 10 and 16. */
#define UT_GCM_A4 "feedfacedeadbeeffeedfacedeadbeefabaddad2"

/** AEAD vectors (alg 0 = GCM, 1 = CCM). */
static const ut_aead_vec_t s_ut_aead_vecs[] UT_VEC_MAYBE_UNUSED = {
    /* GCM TC1: empty plaintext, empty AAD. */
    { 0U, "00000000000000000000000000000000", "000000000000000000000000", "", "", "",
      "58e2fccefa7e3061367f1d57a4e7455a" },
    /* GCM TC2. */
    { 0U, "00000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000",
      "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf" },
    /* GCM TC4: AES-128, 60-byte plaintext, 20-byte AAD. */
    { 0U, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", UT_GCM_A4, UT_GCM_P4,
      "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
      "5bc94fbc3221a5db94fae95ae7121a47" },
    /* GCM TC10: AES-192 (nRF54L15 only; CRACEN Lite has no AES-192). */
    { 0U, "feffe9928665731c6d6a8f9467308308feffe9928665731c", "cafebabefacedbaddecaf888", UT_GCM_A4, UT_GCM_P4,
      "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
      "2519498e80f1478f37ba55bd6d27618c" },
    /* GCM TC16: AES-256. */
    { 0U, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", UT_GCM_A4,
      UT_GCM_P4,
      "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
      "76fc6ece0f4e1768cddf8853bb2d551b" },
    /* CCM SP 800-38C Example 1: n = 7, a = 8, p = 4, t = 4. */
    { 1U, "404142434445464748494a4b4c4d4e4f", "10111213141516", "0001020304050607", "20212223", "7162015b",
      "4dac255d" },
    /* CCM SP 800-38C Example 2: n = 8, a = 16, p = 16, t = 6. */
    { 1U, "404142434445464748494a4b4c4d4e4f", "1011121314151617", "000102030405060708090a0b0c0d0e0f",
      "202122232425262728292a2b2c2d2e2f", "d2a1f0e051ea5f62081a7792073d593d", "1fc64fbfaccd" },
    /* CCM SP 800-38C Example 3: n = 12, a = 20, p = 24, t = 8. */
    { 1U, "404142434445464748494a4b4c4d4e4f", "101112131415161718191a1b", "000102030405060708090a0b0c0d0e0f10111213",
      "202122232425262728292a2b2c2d2e2f3031323334353637", "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
      "484392fbc1b09951" },
    /* CCM RFC 3610 Packet Vector #1: n = 13, a = 8, p = 23, t = 8. */
    { 1U, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "00000003020100a0a1a2a3a4a5", "0001020304050607",
      "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
      "17e8d12cfdf926e0" },
    /* Generated (cryptography 46.0.5): GCM with 4- and 8-byte tags (truncated TC4-key tag). */
    { 0U, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "", "d9313225", "42831ec2", "7c781b027294b5d3" },
    { 0U, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "", "d9313225", "42831ec2", "7c781b02" },
    /* Generated: CCM without AAD (B0 only header), n = 7, p = 18, t = 8. */
    { 1U, "404142434445464748494a4b4c4d4e4f", "10111213141516", "", "202122232425262728292a2b2c2d2e2f3031",
      "7162015bc051951e5918aeaf3c11f3d4ac36", "cda8b6cbca4ff028" },
    /* Generated: CCM without payload, n = 7, a = 8, t = 4. */
    { 1U, "404142434445464748494a4b4c4d4e4f", "10111213141516", "0001020304050607", "", "", "7d3869c0" },
    /* Generated: CCM AES-256, n = 12, a = 4, p = 16, t = 16. */
    { 1U, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedface",
      "d9313225f88406e5a55909c5aff5269a", "c5cccc57f32343875b5b95f98869ae19", "6f8843e53ac043e4d3d7c368740aea8c" },
};

/** Number of AEAD vectors. */
#define UT_AEAD_VECS (sizeof(s_ut_aead_vecs) / sizeof(s_ut_aead_vecs[0]))

/**
 * @name CCM with 0xFF00 bytes of AAD (AAD byte i = i & 0xFF; payload byte i = 0x20 + i;
 *       key 404142..4f, nonce 101112..1c, t = 16). Generated with cryptography 46.0.5.
 * @{
 */
#define UT_CCM_LONG_AAD_LEN   0xFF00U
#define UT_CCM_LONG_PT_LEN    32U
#define UT_CCM_LONG_KEY       "404142434445464748494a4b4c4d4e4f"
#define UT_CCM_LONG_NONCE     "101112131415161718191a1b1c"
#define UT_CCM_LONG_CT        "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72"
#define UT_CCM_LONG_TAG       "6ec44a5ff0a0031dacb6fb0019e09dfe"
/** @} */

/**
 * @name ECDSA P-256 / SHA-256, RFC 6979 §A.2.5 (public key U = xG)
 * @{
 */
#define UT_P256_PUB  "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" \
                     "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
#define UT_P256_H_SAMPLE "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
#define UT_P256_SIG_SAMPLE "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" \
                           "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
#define UT_P256_H_TEST "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
#define UT_P256_SIG_TEST "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" \
                         "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
/** @} */

/** One Ed25519 vector (RFC 8032 §7.1). */
typedef struct {
    const char * pub; /**< Public key A (hex). */
    const char * msg; /**< Message (hex). */
    const char * sig; /**< Signature R || S (hex). */
} ut_ed25519_vec_t;

/** RFC 8032 §7.1 TEST 1-3. */
static const ut_ed25519_vec_t s_ut_ed25519_vecs[] UT_VEC_MAYBE_UNUSED = {
    { "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
    { "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
    { "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
};

/** Number of Ed25519 vectors. */
#define UT_ED25519_VECS (sizeof(s_ut_ed25519_vecs) / sizeof(s_ut_ed25519_vecs[0]))

#endif /* UT_NRF54_VECTORS_H */
