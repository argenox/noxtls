/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    crypto_sym_aria_camellia_test.c
* Summary: ARIA and Camellia regression tests (public API only).
*
*  - RFC 5794 appendix A (ARIA-128/192/256) and RFC 3713 appendix A
*    (Camellia-128/192/256) single-block vectors, encrypt and decrypt;
*  - every mode of both modules (ECB, CBC, CTR, CFB128, OFB) for all key sizes
*    through the one-shot encrypt/decrypt functions, the *_encrypt_data /
*    *_decrypt_data dispatchers and the streaming init/update/final API with
*    irregular chunks; 64-byte messages for ECB/CBC, 61 bytes for the stream
*    modes. Expected values: OpenSSL (`openssl enc -aria-*`) for ARIA and the
*    Python `cryptography` Camellia (plus an ECB-based CTR model cross-checked
*    with `openssl enc -camellia-*-ctr`);
*  - in place (output == input) for every mode, one-shot and streaming (16-byte
*    multiple chunks for ECB/CBC, any chunks for the stream modes);
*  - the modules' built-in self tests.
* Built twice: CRYPTO_SYM_PART=0 -> crypto_sym_aria_camellia_test (vectors,
*   modes, streaming, self tests), CRYPTO_SYM_PART=1 ->
*   crypto_sym_aria_camellia_inplace_test (in-place only).
* Expected values: crypto_sym_aria_camellia_vectors.h.
*****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "noxtls_common.h"
#if NOXTLS_FEATURE_ARIA
#include "encryption/aria/noxtls_aria.h"
#endif
#if NOXTLS_FEATURE_CAMELLIA
#include "encryption/camellia/noxtls_camellia.h"
#endif

#include "crypto_sym_test_util.h"
#include "crypto_sym_aria_camellia_vectors.h"

#ifndef CRYPTO_SYM_PART
#define CRYPTO_SYM_PART 0 /* 0: crypto_sym_aria_camellia_test, 1: crypto_sym_aria_camellia_inplace_test */
#endif

#define CS_MODES (5U) /* ECB, CBC, CTR, CFB, OFB: identical numbering in both modules */

typedef noxtls_return_t (*cs_fn_t)(const uint8_t *key, const uint8_t *data, uint32_t len, const uint8_t *iv,
                                   uint8_t *out, uint32_t type);
typedef noxtls_return_t (*cs_data_fn_t)(const uint8_t *key, const uint8_t *data, uint32_t len, const uint8_t *iv,
                                        uint8_t *out, uint32_t type, uint32_t mode);

typedef struct {
    const char *name;
    cs_fn_t enc[CS_MODES];
    cs_fn_t dec[CS_MODES];
    cs_data_fn_t enc_data;
    cs_data_fn_t dec_data;
    noxtls_return_t (*s_init)(const uint8_t *key, const uint8_t *iv, uint32_t type, uint32_t mode, uint32_t op);
    noxtls_return_t (*s_update)(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *olen);
    noxtls_return_t (*s_final)(uint8_t *out, uint32_t *olen);
    noxtls_return_t (*self_test)(void);
    const char *block_key;     /* NULL: 00 01 02 ... (RFC 5794) */
    const char *block_pt;
    const char *block_ct[3];
    const char *mode_ct[3][CS_MODES];
} cs_cipher_t;

static const char *const k_mode_names[CS_MODES] = { "ECB", "CBC", "CTR", "CFB", "OFB" };

#if NOXTLS_FEATURE_ARIA
static noxtls_aria_context_t g_aria_ctx;
static noxtls_return_t aria_s_init(const uint8_t *key, const uint8_t *iv, uint32_t type, uint32_t mode, uint32_t op)
{
    return noxtls_aria_init(&g_aria_ctx, key, iv, type, mode, op);
}
static noxtls_return_t aria_s_update(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *olen)
{
    return noxtls_aria_update(&g_aria_ctx, in, len, out, olen);
}
static noxtls_return_t aria_s_final(uint8_t *out, uint32_t *olen)
{
    return noxtls_aria_final(&g_aria_ctx, out, olen);
}
static const cs_cipher_t k_aria = {
    "ARIA",
    { noxtls_aria_encrypt_ecb, noxtls_aria_encrypt_cbc, noxtls_aria_encrypt_ctr, noxtls_aria_encrypt_cfb, noxtls_aria_encrypt_ofb },
    { noxtls_aria_decrypt_ecb, noxtls_aria_decrypt_cbc, noxtls_aria_decrypt_ctr, noxtls_aria_decrypt_cfb, noxtls_aria_decrypt_ofb },
    noxtls_aria_encrypt_data, noxtls_aria_decrypt_data,
    aria_s_init, aria_s_update, aria_s_final, noxtls_aria_self_test,
    NULL, k_aria_block_pt, { k_aria128_block_ct, k_aria192_block_ct, k_aria256_block_ct },
    { { k_aria128_ecb, k_aria128_cbc, k_aria128_ctr, k_aria128_cfb, k_aria128_ofb },
      { k_aria192_ecb, k_aria192_cbc, k_aria192_ctr, k_aria192_cfb, k_aria192_ofb },
      { k_aria256_ecb, k_aria256_cbc, k_aria256_ctr, k_aria256_cfb, k_aria256_ofb } }
};
#endif

#if NOXTLS_FEATURE_CAMELLIA
static noxtls_camellia_context_t g_cam_ctx;
static noxtls_return_t cam_s_init(const uint8_t *key, const uint8_t *iv, uint32_t type, uint32_t mode, uint32_t op)
{
    return noxtls_camellia_init(&g_cam_ctx, key, iv, type, mode, op);
}
static noxtls_return_t cam_s_update(const uint8_t *in, uint32_t len, uint8_t *out, uint32_t *olen)
{
    return noxtls_camellia_update(&g_cam_ctx, in, len, out, olen);
}
static noxtls_return_t cam_s_final(uint8_t *out, uint32_t *olen)
{
    return noxtls_camellia_final(&g_cam_ctx, out, olen);
}
static const cs_cipher_t k_camellia = {
    "Camellia",
    { noxtls_camellia_encrypt_ecb, noxtls_camellia_encrypt_cbc, noxtls_camellia_encrypt_ctr, noxtls_camellia_encrypt_cfb,
      noxtls_camellia_encrypt_ofb },
    { noxtls_camellia_decrypt_ecb, noxtls_camellia_decrypt_cbc, noxtls_camellia_decrypt_ctr, noxtls_camellia_decrypt_cfb,
      noxtls_camellia_decrypt_ofb },
    noxtls_camellia_encrypt_data, noxtls_camellia_decrypt_data,
    cam_s_init, cam_s_update, cam_s_final, noxtls_camellia_self_test,
    k_cam_block_key, k_cam_block_pt, { k_cam128_block_ct, k_cam192_block_ct, k_cam256_block_ct },
    { { k_cam128_ecb, k_cam128_cbc, k_cam128_ctr, k_cam128_cfb, k_cam128_ofb },
      { k_cam192_ecb, k_cam192_cbc, k_cam192_ctr, k_cam192_cfb, k_cam192_ofb },
      { k_cam256_ecb, k_cam256_cbc, k_cam256_ctr, k_cam256_cfb, k_cam256_ofb } }
};
#endif

static uint8_t g_pt[128];
static uint8_t g_ct[128];
static uint8_t g_out[128];
static uint8_t g_buf[128];

/* Streaming over in[0..len); aligned != 0 uses 16-byte multiple chunks. Returns bytes produced or 0xFFFFFFFF. */
static uint32_t stream(const cs_cipher_t *c, const uint8_t *key, const uint8_t *iv, uint32_t type, uint32_t mode,
                       uint32_t op, const uint8_t *in, uint8_t *out, uint32_t len, int aligned, uint32_t start)
{
    uint32_t off = 0U;
    uint32_t produced = 0U;
    uint32_t idx = start;
    uint32_t olen = 0U;

    if (c->s_init(key, iv, type, mode, op) != NOXTLS_RETURN_SUCCESS) {
        return 0xFFFFFFFFU;
    }
    while (off < len) {
        uint32_t n = cs_chunk(idx) % 23U; /* short messages: keep chunks small */
        idx += 1U;
        if (aligned != 0) {
            n = 16U * ((n % 3U) + 1U);
        }
        if (n > (len - off)) {
            n = len - off;
        }
        if (c->s_update(&in[off], n, &out[produced], &olen) != NOXTLS_RETURN_SUCCESS) {
            return 0xFFFFFFFFU;
        }
        off += n;
        produced += olen;
    }
    if (c->s_final(&out[produced], &olen) != NOXTLS_RETURN_SUCCESS) {
        return 0xFFFFFFFFU;
    }
    return produced + olen;
}

static int key_size_enabled(uint32_t k)
{
    (void)k;
    return 1; /* ARIA / Camellia key sizes are not individually configurable */
}

static void test_cipher(const cs_cipher_t *c, uint32_t part)
{
    static const uint32_t k_kl[3] = { 16U, 24U, 32U };
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t blk[16];
    uint8_t out[16];
    char what[112];
    uint32_t k;
    uint32_t m;
    uint32_t start;

    for (k = 0U; k < 3U; k += 1U) {
        if (key_size_enabled(k) == 0) {
            continue;
        }
        /* Single-block RFC vectors. */
        if (part == 0U) {
            (void)snprintf(what, sizeof(what), "%s-%u block vector", c->name, (unsigned)(k_kl[k] * 8U));
            cs_section(what);
            if (c->block_key == NULL) {
                uint32_t i;
                for (i = 0U; i < 32U; i += 1U) {
                    key[i] = (uint8_t)i;
                }
            } else {
                (void)cs_hex(c->block_key, key, sizeof(key));
            }
            (void)cs_hex(c->block_pt, blk, sizeof(blk));
            CHECK_RC(c->enc[0](key, blk, 16U, NULL, out, k), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_HEX(what, out, 16U, c->block_ct[k]);
            CHECK_RC(c->dec[0](key, out, 16U, NULL, out, k), NOXTLS_RETURN_SUCCESS);
            (void)EXPECT_MEM("block decrypt (in place)", out, blk, 16U);
        }

        cs_fill(key, 32U, CS_AC_KEY_SEED);
        cs_fill(iv, 16U, CS_AC_IV_SEED);
        for (m = 0U; m < CS_MODES; m += 1U) {
            uint32_t len = (m < 2U) ? 64U : 61U;
            const uint8_t *ivp = (m == 0U) ? NULL : iv;
            const char *ct_hex = c->mode_ct[k][m];
            int aligned = (m < 2U) ? 1 : 0;
            cs_fill(g_pt, len, CS_AC_MSG_SEED);
            (void)cs_hex(ct_hex, g_ct, sizeof(g_ct));
            if (part == 0U) {
                (void)snprintf(what, sizeof(what), "%s-%u-%s one-shot", c->name, (unsigned)(k_kl[k] * 8U), k_mode_names[m]);
                cs_section(what);
                (void)memset(g_out, 0xEE, sizeof(g_out));
                CHECK_RC(c->enc[m](key, g_pt, len, ivp, g_out, k), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM("encrypt", g_out, g_ct, len);
                CHECK(g_out[len] == 0xEEU);
                (void)memset(g_out, 0xEE, sizeof(g_out));
                CHECK_RC(c->dec[m](key, g_ct, len, ivp, g_out, k), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM("decrypt", g_out, g_pt, len);
                CHECK_RC(c->enc_data(key, g_pt, len, ivp, g_out, k, m), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM("encrypt_data", g_out, g_ct, len);
                CHECK_RC(c->dec_data(key, g_ct, len, ivp, g_out, k, m), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM("decrypt_data", g_out, g_pt, len);

                for (start = 0U; start < 4U; start += 1U) {
                    (void)snprintf(what, sizeof(what), "%s-%u-%s streaming (schedule %u)", c->name, (unsigned)(k_kl[k] * 8U),
                                   k_mode_names[m], (unsigned)start);
                    cs_section(what);
                    (void)memset(g_out, 0xEE, sizeof(g_out));
                    CHECK(stream(c, key, ivp, k, m, 0U, g_pt, g_out, len, 0, start) == len);
                    (void)EXPECT_MEM("streaming encrypt", g_out, g_ct, len);
                    (void)memset(g_out, 0xEE, sizeof(g_out));
                    CHECK(stream(c, key, ivp, k, m, 1U, g_ct, g_out, len, 0, start) == len);
                    (void)EXPECT_MEM("streaming decrypt", g_out, g_pt, len);
                }
            } else {
                (void)snprintf(what, sizeof(what), "%s-%u-%s in-place one-shot encrypt", c->name, (unsigned)(k_kl[k] * 8U),
                               k_mode_names[m]);
                cs_section(what);
                (void)memcpy(g_buf, g_pt, len);
                CHECK_RC(c->enc[m](key, g_buf, len, ivp, g_buf, k), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM(what, g_buf, g_ct, len);
                (void)snprintf(what, sizeof(what), "%s-%u-%s in-place one-shot decrypt", c->name, (unsigned)(k_kl[k] * 8U),
                               k_mode_names[m]);
                cs_section(what);
                (void)memcpy(g_buf, g_ct, len);
                CHECK_RC(c->dec[m](key, g_buf, len, ivp, g_buf, k), NOXTLS_RETURN_SUCCESS);
                (void)EXPECT_MEM(what, g_buf, g_pt, len);
                (void)snprintf(what, sizeof(what), "%s-%u-%s in-place streaming encrypt", c->name, (unsigned)(k_kl[k] * 8U),
                               k_mode_names[m]);
                cs_section(what);
                (void)memcpy(g_buf, g_pt, len);
                CHECK(stream(c, key, ivp, k, m, 0U, g_buf, g_buf, len, aligned, 1U) == len);
                (void)EXPECT_MEM(what, g_buf, g_ct, len);
                (void)snprintf(what, sizeof(what), "%s-%u-%s in-place streaming decrypt", c->name, (unsigned)(k_kl[k] * 8U),
                               k_mode_names[m]);
                cs_section(what);
                (void)memcpy(g_buf, g_ct, len);
                CHECK(stream(c, key, ivp, k, m, 1U, g_buf, g_buf, len, aligned, 2U) == len);
                (void)EXPECT_MEM(what, g_buf, g_pt, len);
            }
        }
    }
    if (part == 0U) {
        (void)snprintf(what, sizeof(what), "%s self test", c->name);
        cs_section(what);
        CHECK_RC(c->self_test(), NOXTLS_RETURN_SUCCESS);
    }
}

int main(void)
{
#if NOXTLS_FEATURE_ARIA
    test_cipher(&k_aria, (uint32_t)CRYPTO_SYM_PART);
#else
    (void)printf("SKIP ARIA: NOXTLS_FEATURE_ARIA is off\n");
#endif
#if NOXTLS_FEATURE_CAMELLIA
    test_cipher(&k_camellia, (uint32_t)CRYPTO_SYM_PART);
#else
    (void)printf("SKIP Camellia: NOXTLS_FEATURE_CAMELLIA is off\n");
#endif
    return cs_finish((CRYPTO_SYM_PART == 0) ? "crypto_sym_aria_camellia_test" : "crypto_sym_aria_camellia_inplace_test");
}
