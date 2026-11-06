/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    ut_wb_mock.c
* Summary: Register-level model of STM32WB55 AES1, PKA, RNG and HSEM for the host tests
*****************************************************************************/

/**
 * @file ut_wb_mock.c
 * @brief Functional register model replacing noxtls_stm32wb_bus.c in the host tests.
 * @ingroup noxtls_stm32wb_ut
 */

#include "ut_wb_mock.h"

#include <string.h>

#include "ut_wb_ref.h"
#include "noxtls_stm32wb_bus.h"
#include "noxtls_stm32wb_config.h"

/* AES CR / SR bits, taken from the ST CMSIS header (independent of the driver's regs header). */
#define M_AES_EN        0x00000001U
#define M_AES_CCFC      0x00000080U
#define M_AES_ERRC      0x00000100U
#define M_AES_KEYSIZE   0x00040000U

ut_wb_t g_wb;

/** Number of words of the AES register block. */
#define M_AES_SPAN      0x40U

/* ------------------------------------------------------------------------- */
/* helpers                                                                    */
/* ------------------------------------------------------------------------- */

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void proto(void)
{
    g_wb.proto_err++;
}

void ut_wb_reset(void)
{
    memset(&g_wb, 0, sizeof(g_wb));
    g_wb.aes_dout_pos = 4U;
    g_wb.mul_tab = k_ut_wb_mul;
    g_wb.mul_n = k_ut_wb_mul_count;
    g_wb.sign_tab = k_ut_wb_sign;
    g_wb.sign_n = k_ut_wb_sign_count;
    g_wb.verify_tab = k_ut_wb_verify;
    g_wb.verify_n = k_ut_wb_verify_count;
}

void ut_wb_cpu2_take(uint32_t id)
{
    g_wb.sem_owner[id] = 8U;
}

void ut_wb_rng_script(const uint32_t *words, uint32_t n)
{
    memcpy(g_wb.rng_words, words, n * sizeof(uint32_t));
    g_wb.rng_n = n;
    g_wb.rng_pos = 0U;
}

void ut_wb_rng_script_counter(uint32_t n)
{
    uint32_t i;

    for (i = 0U; i < n; i++) {
        g_wb.rng_words[i] = 0x01020304U + (i * 0x11111111U);
    }
    g_wb.rng_n = n;
    g_wb.rng_pos = 0U;
}

/* ------------------------------------------------------------------------- */
/* AES1                                                                       */
/* ------------------------------------------------------------------------- */

static uint32_t aes_chmod(void)
{
    return ((g_wb.aes_cr >> 5) & 3U) | (((g_wb.aes_cr >> 16) & 1U) << 2);
}

static uint32_t aes_mode(void)
{
    return (g_wb.aes_cr >> 3) & 3U;
}

static uint32_t aes_phase(void)
{
    return (g_wb.aes_cr >> 13) & 3U;
}

static void aes_get_key(uint8_t *kb, uint32_t *len)
{
    uint32_t n = ((g_wb.aes_cr & M_AES_KEYSIZE) != 0U) ? 8U : 4U;
    uint32_t i;

    for (i = 0U; i < n; i++) {
        put32(&kb[i * 4U], g_wb.aes_key[n - 1U - i]);
    }
    *len = n * 4U;
}

static void aes_get_iv(uint8_t *iv)
{
    uint32_t i;

    for (i = 0U; i < 4U; i++) {
        put32(&iv[i * 4U], g_wb.aes_iv[3U - i]);
    }
}

static void aes_set_iv(const uint8_t *iv)
{
    uint32_t i;

    for (i = 0U; i < 4U; i++) {
        g_wb.aes_iv[3U - i] = be32(&iv[i * 4U]);
    }
}

static void aes_expand(ut_ref_aes_t *ctx)
{
    uint8_t kb[32];
    uint32_t len;

    aes_get_key(kb, &len);
    ut_ref_aes_set_key(ctx, kb, len);
}

/** Complete one engine operation: CCF, or an injected fault. */
static void aes_finish(void)
{
    g_wb.aes_computations++;
    if (g_wb.aes_fault_at == g_wb.aes_computations) {
        if (g_wb.aes_fault_kind == 1U) {
            g_wb.aes_rderr = 1U;
        } else if (g_wb.aes_fault_kind == 2U) {
            g_wb.aes_wrerr = 1U;
        } else {
            /* Never completes. */
        }
        return;
    }
    g_wb.aes_ccf = 1U;
    g_wb.aes_dout_pos = 0U;
}

static void xor16(uint8_t *a, const uint8_t *b)
{
    uint32_t i;

    for (i = 0U; i < 16U; i++) {
        a[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void ctr32_inc(uint8_t *blk)
{
    put32(&blk[12], be32(&blk[12]) + 1U);
}

/** Zero the last NPBLB bytes of a block (the padding the hardware must not authenticate). */
static void mask_tail(uint8_t *blk)
{
    uint32_t npblb = (g_wb.aes_cr >> 20) & 0xFU;
    uint32_t i;

    g_wb.aes_last_npblb = npblb;
    for (i = 16U - npblb; i < 16U; i++) {
        blk[i] = 0U;
    }
}

static void aes_init_phase(void)
{
    ut_ref_aes_t ctx;
    uint8_t iv[16];
    uint8_t zero[16] = { 0 };

    aes_expand(&ctx);
    aes_get_iv(iv);
    if (aes_chmod() == 3U) {
        ut_ref_aes_enc(&ctx, zero, g_wb.gcm_h);
        memset(g_wb.gcm_s, 0, 16U);
        memcpy(g_wb.gcm_icb, iv, 16U);
        /* J0 = nonce || 1: the init block carries nonce || 2. */
        put32(&iv[12], be32(&iv[12]) - 1U);
        ut_ref_aes_enc(&ctx, iv, g_wb.gcm_ekj0);
    } else {
        uint32_t l = (uint32_t)(iv[0] & 7U) + 1U;
        uint32_t i;

        ut_ref_aes_enc(&ctx, iv, g_wb.ccm_y);
        memset(g_wb.ccm_ctr, 0, 16U);
        g_wb.ccm_ctr[0] = (uint8_t)(l - 1U);
        memcpy(&g_wb.ccm_ctr[1], &iv[1], 15U - l);
        memcpy(g_wb.ccm_a0, g_wb.ccm_ctr, 16U);
        for (i = 0U; i < l; i++) {
            g_wb.ccm_ctr[15U - i] = (i == 0U) ? 1U : 0U;
        }
    }
    g_wb.aes_active = 1U;
    aes_finish();
    /* The init phase ends with EN cleared by hardware. */
    g_wb.aes_cr &= ~M_AES_EN;
}

static void aes_ccm_final(void)
{
    ut_ref_aes_t ctx;
    uint8_t ek[16];
    uint8_t tag[16];
    uint32_t i;

    aes_expand(&ctx);
    ut_ref_aes_enc(&ctx, g_wb.ccm_a0, ek);
    memcpy(tag, g_wb.ccm_y, 16U);
    xor16(tag, ek);
    for (i = 0U; i < 4U; i++) {
        g_wb.aes_dout[i] = be32(&tag[i * 4U]);
    }
    aes_finish();
}

static void aes_block(void)
{
    ut_ref_aes_t ctx;
    uint8_t in[16];
    uint8_t out[16];
    uint8_t iv[16];
    uint8_t ks[16];
    uint32_t i;
    uint32_t chmod = aes_chmod();
    uint32_t dec = (aes_mode() >= 2U) ? 1U : 0U;

    for (i = 0U; i < 4U; i++) {
        put32(&in[i * 4U], g_wb.aes_din[i]);
    }
    aes_expand(&ctx);
    if (aes_mode() == 1U) {
        proto();
    }
    if (chmod == 0U) {
        if (dec != 0U) {
            ut_ref_aes_dec(&ctx, in, out);
        } else {
            ut_ref_aes_enc(&ctx, in, out);
        }
    } else if (chmod == 1U) {
        aes_get_iv(iv);
        if (dec != 0U) {
            ut_ref_aes_dec(&ctx, in, out);
            xor16(out, iv);
            aes_set_iv(in);
        } else {
            memcpy(out, in, 16U);
            xor16(out, iv);
            ut_ref_aes_enc(&ctx, out, out);
            aes_set_iv(out);
        }
    } else if (chmod == 2U) {
        /* CTR: the hardware increments only the low 32 bits of the counter block. */
        aes_get_iv(iv);
        ut_ref_aes_enc(&ctx, iv, ks);
        memcpy(out, in, 16U);
        xor16(out, ks);
        ctr32_inc(iv);
        aes_set_iv(iv);
    } else if ((chmod == 3U) || (chmod == 4U)) {
        uint32_t ph = aes_phase();
        uint8_t c[16];

        if (g_wb.aes_active == 0U) {
            proto();
        }
        memset(out, 0, 16U);
        if (ph == 1U) {
            if (chmod == 3U) {
                memcpy(c, in, 16U);
                xor16(g_wb.gcm_s, c);
                ut_ref_gf_mul(g_wb.gcm_s, g_wb.gcm_h);
            } else {
                xor16(g_wb.ccm_y, in);
                ut_ref_aes_enc(&ctx, g_wb.ccm_y, g_wb.ccm_y);
            }
        } else if (ph == 2U) {
            if (chmod == 3U) {
                ut_ref_aes_enc(&ctx, g_wb.gcm_icb, ks);
                ctr32_inc(g_wb.gcm_icb);
                memcpy(out, in, 16U);
                xor16(out, ks);
                memcpy(c, (dec != 0U) ? in : out, 16U);
                if (dec == 0U) {
                    mask_tail(c);
                }
                xor16(g_wb.gcm_s, c);
                ut_ref_gf_mul(g_wb.gcm_s, g_wb.gcm_h);
            } else {
                ut_ref_aes_enc(&ctx, g_wb.ccm_ctr, ks);
                /* CCM counter: increment the L-byte counter field. */
                {
                    uint32_t l = (uint32_t)g_wb.ccm_a0[0] + 1U;
                    int32_t k;

                    for (k = 15; k >= (int32_t)(16U - l); k--) {
                        g_wb.ccm_ctr[k] = (uint8_t)(g_wb.ccm_ctr[k] + 1U);
                        if (g_wb.ccm_ctr[k] != 0U) {
                            break;
                        }
                    }
                }
                memcpy(out, in, 16U);
                xor16(out, ks);
                memcpy(c, (dec != 0U) ? out : in, 16U);
                if (dec != 0U) {
                    mask_tail(c);
                }
                xor16(g_wb.ccm_y, c);
                ut_ref_aes_enc(&ctx, g_wb.ccm_y, g_wb.ccm_y);
            }
        } else if (ph == 3U) {
            if (chmod == 3U) {
                uint8_t tag[16];

                if (aes_mode() != 0U) {
                    g_wb.aes_final_mode_bad++;
                } else {
                    g_wb.aes_final_mode_ok++;
                }
                xor16(g_wb.gcm_s, in);
                ut_ref_gf_mul(g_wb.gcm_s, g_wb.gcm_h);
                memcpy(tag, g_wb.gcm_s, 16U);
                xor16(tag, g_wb.gcm_ekj0);
                memcpy(out, tag, 16U);
            } else {
                proto();
            }
        } else {
            proto();
        }
    } else {
        proto();
        memset(out, 0, 16U);
    }
    for (i = 0U; i < 4U; i++) {
        g_wb.aes_dout[i] = be32(&out[i * 4U]);
    }
    aes_finish();
}

static uint32_t aes_read(uint32_t off)
{
    uint32_t v = 0U;

    if (off == 0x00U) {
        v = g_wb.aes_cr;
    } else if (off == 0x04U) {
        v = g_wb.aes_ccf | (g_wb.aes_rderr << 1) | (g_wb.aes_wrerr << 2) | (g_wb.aes_busy << 3);
    } else if (off == 0x0CU) {
        if (g_wb.aes_dout_pos >= 4U) {
            proto();
        } else {
            v = g_wb.aes_dout[g_wb.aes_dout_pos];
            g_wb.aes_dout_pos++;
        }
    } else if ((off >= 0x10U) && (off < 0x20U)) {
        v = g_wb.aes_key[(off - 0x10U) / 4U];
    } else if ((off >= 0x20U) && (off < 0x30U)) {
        v = g_wb.aes_iv[(off - 0x20U) / 4U];
    } else if ((off >= 0x30U) && (off < 0x40U)) {
        v = g_wb.aes_key[4U + ((off - 0x30U) / 4U)];
    } else {
        proto();
    }
    return v;
}

static void aes_write(uint32_t off, uint32_t value)
{
    if (off == 0x00U) {
        uint32_t old = g_wb.aes_cr;
        uint32_t old_phase = aes_phase();
        uint32_t neu = value & ~(M_AES_CCFC | M_AES_ERRC);

        g_wb.aes_cr_writes++;
        if ((value & M_AES_CCFC) != 0U) {
            g_wb.aes_ccf = 0U;
        }
        if ((value & M_AES_ERRC) != 0U) {
            g_wb.aes_rderr = 0U;
            g_wb.aes_wrerr = 0U;
        }
        g_wb.aes_cr = neu;
        if (((old & M_AES_EN) != 0U) && ((neu & M_AES_EN) == 0U)) {
            /* Disabling resets the state machine. */
            g_wb.aes_din_n = 0U;
            g_wb.aes_dout_pos = 4U;
            g_wb.aes_active = 0U;
        }
        if (((old & M_AES_EN) == 0U) && ((neu & M_AES_EN) != 0U) && ((aes_chmod() == 3U) || (aes_chmod() == 4U)) &&
            (aes_phase() == 0U)) {
            aes_init_phase();
        } else if ((aes_chmod() == 4U) && ((neu & M_AES_EN) != 0U) && (aes_phase() == 3U) && (old_phase != 3U)) {
            if (aes_mode() != 0U) {
                g_wb.aes_final_mode_bad++;
            } else {
                g_wb.aes_final_mode_ok++;
            }
            aes_ccm_final();
        } else {
            /* Other writes only configure. */
        }
    } else if (off == 0x08U) {
        if ((g_wb.aes_cr & M_AES_EN) == 0U) {
            proto();
        } else {
            g_wb.aes_din[g_wb.aes_din_n] = value;
            g_wb.aes_din_n++;
            if (g_wb.aes_din_n == 4U) {
                g_wb.aes_din_n = 0U;
                aes_block();
            }
        }
    } else if (((off >= 0x10U) && (off < 0x20U)) || ((off >= 0x30U) && (off < 0x40U))) {
        uint32_t idx = (off < 0x20U) ? ((off - 0x10U) / 4U) : (4U + ((off - 0x30U) / 4U));

        if ((g_wb.aes_cr & M_AES_EN) != 0U) {
            proto();
        }
        g_wb.aes_key[idx] = value;
    } else if ((off >= 0x20U) && (off < 0x30U)) {
        if ((g_wb.aes_cr & M_AES_EN) != 0U) {
            proto();
        }
        g_wb.aes_iv[(off - 0x20U) / 4U] = value;
    } else {
        proto();
    }
}

/* ------------------------------------------------------------------------- */
/* HSEM                                                                       */
/* ------------------------------------------------------------------------- */

static uint32_t hsem_read(uint32_t off)
{
    uint32_t v = 0U;
    uint32_t id;

    if ((off >= 0x80U) && (off < 0x100U)) {
        id = (off - 0x80U) / 4U;
        if (g_wb.sem_owner[id] == 0U) {
            g_wb.sem_owner[id] = 4U;
            g_wb.sem_takes++;
        }
        v = (g_wb.sem_owner[id] << 8) | 0x80000000U;
    } else if (off < 0x80U) {
        id = off / 4U;
        v = (g_wb.sem_owner[id] != 0U) ? ((g_wb.sem_owner[id] << 8) | 0x80000000U) : 0U;
    } else {
        proto();
    }
    return v;
}

static void hsem_write(uint32_t off, uint32_t value)
{
    uint32_t id;
    uint32_t core = (value >> 8) & 0xFU;

    if (off < 0x80U) {
        id = off / 4U;
        g_wb.sem_last_release = value;
        g_wb.sem_last_id = id;
        if (g_wb.sem_owner[id] == core) {
            g_wb.sem_owner[id] = 0U;
            if (core == 4U) {
                g_wb.sem_releases++;
            }
        } else {
            proto();
        }
    } else {
        proto();
    }
}

/* ------------------------------------------------------------------------- */
/* RNG                                                                        */
/* ------------------------------------------------------------------------- */

static uint32_t rng_read(uint32_t off)
{
    uint32_t v = 0U;

    if (off == 0x00U) {
        v = g_wb.rng_cr;
    } else if (off == 0x04U) {
        uint32_t drdy = ((g_wb.rng_pos < g_wb.rng_n) && (g_wb.rng_drdy_block == 0U)) ? 1U : 0U;

        v = drdy | (g_wb.rng_cecs << 1) | (g_wb.rng_secs << 2) | (g_wb.rng_ceis << 5) | (g_wb.rng_seis << 6);
    } else if (off == 0x08U) {
        g_wb.rng_dr_reads++;
        if (g_wb.rng_pos < g_wb.rng_n) {
            v = g_wb.rng_words[g_wb.rng_pos];
            g_wb.rng_pos++;
        } else {
            g_wb.rng_underruns++;
        }
        if (g_wb.rng_secs_clear_after != 0U) {
            g_wb.rng_secs_clear_after--;
            if (g_wb.rng_secs_clear_after == 0U) {
                g_wb.rng_secs = 0U;
            }
        }
    } else {
        proto();
    }
    return v;
}

static void rng_write(uint32_t off, uint32_t value)
{
    if (off == 0x00U) {
        g_wb.rng_cr = value;
        g_wb.rng_cr_writes++;
    } else if (off == 0x04U) {
        /* SEIS and CEIS are cleared by writing 0. */
        if ((value & (1U << 6)) == 0U) {
            g_wb.rng_seis = 0U;
            if (g_wb.rng_seis_rearm != 0U) {
                g_wb.rng_seis_rearm--;
                g_wb.rng_seis = 1U;
            }
        }
        if ((value & (1U << 5)) == 0U) {
            g_wb.rng_ceis = 0U;
            if (g_wb.rng_ceis_rearm != 0U) {
                g_wb.rng_ceis_rearm--;
                g_wb.rng_ceis = 1U;
            }
        }
    } else {
        proto();
    }
}

/* ------------------------------------------------------------------------- */
/* PKA                                                                        */
/* ------------------------------------------------------------------------- */

/* P-256 constants for operand checks (SP 800-186, independent of the driver tables). */
static const uint8_t k_p[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t k_b[32] = {
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};
static const uint8_t k_n[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
static const uint8_t k_gx[32] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
static const uint8_t k_gy[32] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};

uint32_t ut_wb_ram_word(uint32_t off)
{
    return g_wb.pka_ram[(off - 0x400U) / 4U];
}

void ut_wb_ram_get(uint32_t off, uint8_t *out, uint32_t len)
{
    uint32_t words = (len + 3U) / 4U;
    uint32_t w;
    uint32_t b;
    uint32_t pos;

    for (w = 0U; w < words; w++) {
        for (b = 0U; b < 4U; b++) {
            pos = (w * 4U) + b;
            if (pos < len) {
                out[len - 1U - pos] = (uint8_t)(ut_wb_ram_word(off + (w * 4U)) >> (8U * b));
            }
        }
    }
}

/** Read an operand and check the zero word that must follow it. */
static void ram_op(uint32_t off, uint8_t *out, uint32_t len)
{
    ut_wb_ram_get(off, out, len);
    if (ut_wb_ram_word(off + (((len + 3U) / 4U) * 4U)) != 0U) {
        proto();
    }
}

static void ram_put(uint32_t off, const uint8_t *in, uint32_t len)
{
    uint32_t words = (len + 3U) / 4U;
    uint32_t w;
    uint32_t b;
    uint32_t pos;
    uint32_t v;

    for (w = 0U; w < words; w++) {
        v = 0U;
        for (b = 0U; b < 4U; b++) {
            pos = (w * 4U) + b;
            if (pos < len) {
                v |= (uint32_t)in[len - 1U - pos] << (8U * b);
            }
        }
        g_wb.pka_ram[((off - 0x400U) / 4U) + w] = v;
    }
}

static void ram_set(uint32_t off, uint32_t v)
{
    g_wb.pka_ram[(off - 0x400U) / 4U] = v;
}

/** Check the curve operands common to the ECC operations: |a| = 3 negative, prime p. */
static void check_curve(uint32_t sign_off, uint32_t a_off, uint32_t p_off)
{
    uint8_t buf[32];
    uint8_t three[32] = { 0 };

    three[31] = 3U;
    if (ut_wb_ram_word(sign_off) != 1U) {
        proto();
    }
    ram_op(a_off, buf, 32U);
    if (memcmp(buf, three, 32U) != 0) {
        proto();
    }
    ram_op(p_off, buf, 32U);
    if (memcmp(buf, k_p, 32U) != 0) {
        proto();
    }
}

static uint32_t bitlen(const uint8_t *d, uint32_t len)
{
    uint32_t i = 0U;
    uint32_t bits = 0U;
    uint8_t t;

    while ((i < len) && (d[i] == 0U)) {
        i++;
    }
    if (i < len) {
        bits = (len - i - 1U) * 8U;
        for (t = d[i]; t != 0U; t = (uint8_t)(t >> 1)) {
            bits++;
        }
    }
    return bits;
}

static void pka_op_mul(void)
{
    uint8_t k[32];
    uint8_t px[32];
    uint8_t py[32];
    uint8_t zero[32] = { 0 };
    const uint8_t *rx = zero;
    const uint8_t *ry = zero;
    uint32_t i;

    check_curve(0x408U, 0x40CU, 0x460U);
    ram_op(0x508U, k, 32U);
    ram_op(0x55CU, px, 32U);
    ram_op(0x5B0U, py, 32U);
    g_wb.pka_exp_bits = ut_wb_ram_word(0x400U);
    g_wb.pka_op_bits = ut_wb_ram_word(0x404U);
    if ((g_wb.pka_exp_bits != bitlen(k, 32U)) || (g_wb.pka_op_bits != 256U)) {
        proto();
    }
    for (i = 0U; i < g_wb.mul_n; i++) {
        if ((memcmp(k, g_wb.mul_tab[i].k, 32U) == 0) && (memcmp(px, g_wb.mul_tab[i].px, 32U) == 0) &&
            (memcmp(py, g_wb.mul_tab[i].py, 32U) == 0)) {
            rx = g_wb.mul_tab[i].rx;
            ry = g_wb.mul_tab[i].ry;
        }
    }
    ram_put(0x55CU, rx, 32U);
    ram_put(0x5B0U, ry, 32U);
}

static void pka_op_check(void)
{
    uint8_t x[32];
    uint8_t y[32];
    uint8_t b[32];
    uint8_t y2[32];
    uint8_t x2[32];
    uint8_t x3[32];
    uint8_t rhs[32];
    uint8_t three[32] = { 0 };
    uint8_t t3[32];
    uint32_t result;

    three[31] = 3U;
    check_curve(0x408U, 0x40CU, 0x460U);
    ram_op(0x7FCU, b, 32U);
    ram_op(0x55CU, x, 32U);
    ram_op(0x5B0U, y, 32U);
    if ((memcmp(b, k_b, 32U) != 0) || (ut_wb_ram_word(0x404U) != 256U)) {
        proto();
    }
    /* y^2 == x^3 - 3x + b (mod p) with x, y < p. */
    if ((memcmp(x, k_p, 32U) >= 0) || (memcmp(y, k_p, 32U) >= 0)) {
        result = 1U;
    } else {
        ut_ref_mulmod(y2, y, y, k_p, 32U);
        ut_ref_mulmod(x2, x, x, k_p, 32U);
        ut_ref_mulmod(x3, x2, x, k_p, 32U);
        ut_ref_mulmod(t3, x, three, k_p, 32U);
        /* rhs = x3 - t3 + b: compute as x3 + (p - t3) + b. */
        {
            uint8_t neg[32];
            int borrow = 0;
            int i;
            int d;
            int carry = 0;

            for (i = 31; i >= 0; i--) {
                d = (int)k_p[i] - (int)t3[i] - borrow;
                borrow = (d < 0) ? 1 : 0;
                neg[i] = (uint8_t)d;
            }
            /* rhs = x3 + neg (mod p) */
            for (i = 31; i >= 0; i--) {
                d = (int)x3[i] + (int)neg[i] + carry;
                rhs[i] = (uint8_t)d;
                carry = d >> 8;
            }
            if ((carry != 0) || (memcmp(rhs, k_p, 32U) >= 0)) {
                borrow = 0;
                for (i = 31; i >= 0; i--) {
                    d = (int)rhs[i] - (int)k_p[i] - borrow;
                    borrow = (d < 0) ? 1 : 0;
                    rhs[i] = (uint8_t)d;
                }
            }
            carry = 0;
            for (i = 31; i >= 0; i--) {
                d = (int)rhs[i] + (int)b[i] + carry;
                rhs[i] = (uint8_t)d;
                carry = d >> 8;
            }
            if ((carry != 0) || (memcmp(rhs, k_p, 32U) >= 0)) {
                borrow = 0;
                for (i = 31; i >= 0; i--) {
                    d = (int)rhs[i] - (int)k_p[i] - borrow;
                    borrow = (d < 0) ? 1 : 0;
                    rhs[i] = (uint8_t)d;
                }
            }
        }
        result = (memcmp(rhs, y2, 32U) == 0) ? 0U : 1U;
    }
    if (g_wb.pka_force_check == 1U) {
        result = 1U;
    } else if (g_wb.pka_force_check == 2U) {
        result = 0U;
    } else {
        /* Computed. */
    }
    ram_set(0x400U, result);
}

static void pka_op_sign(void)
{
    uint8_t gx[32];
    uint8_t gy[32];
    uint8_t k[32];
    uint8_t e[32];
    uint8_t d[32];
    uint8_t n[32];
    uint8_t zero[32] = { 0 };
    const uint8_t *r = zero;
    const uint8_t *s = zero;
    uint32_t err = 1U;
    uint32_t i;

    check_curve(0x408U, 0x40CU, 0x460U);
    ram_op(0x508U, k, 32U);
    ram_op(0x55CU, gx, 32U);
    ram_op(0x5B0U, gy, 32U);
    ram_op(0xDE8U, e, 32U);
    ram_op(0xE3CU, d, 32U);
    ram_op(0xE94U, n, 32U);
    if ((ut_wb_ram_word(0x400U) != 256U) || (ut_wb_ram_word(0x404U) != 256U) || (memcmp(gx, k_gx, 32U) != 0) ||
        (memcmp(gy, k_gy, 32U) != 0) || (memcmp(n, k_n, 32U) != 0)) {
        proto();
    }
    for (i = 0U; i < g_wb.sign_n; i++) {
        if ((memcmp(d, g_wb.sign_tab[i].d, 32U) == 0) && (memcmp(k, g_wb.sign_tab[i].k, 32U) == 0) &&
            (memcmp(e, g_wb.sign_tab[i].e, 32U) == 0)) {
            r = g_wb.sign_tab[i].r;
            s = g_wb.sign_tab[i].s;
            err = 0U;
        }
    }
    if (g_wb.pka_force_sign_err != 0U) {
        err = 1U;
    }
    if (g_wb.pka_force_sign_zero != 0U) {
        r = zero;
        s = zero;
        err = 0U;
    }
    ram_put(0x700U, r, 32U);
    ram_put(0x754U, s, 32U);
    ram_set(0xEE8U, err);
}

static void pka_op_verify(void)
{
    uint8_t gx[32];
    uint8_t gy[32];
    uint8_t qx[32];
    uint8_t qy[32];
    uint8_t r[32];
    uint8_t s[32];
    uint8_t e[32];
    uint8_t n[32];
    uint32_t result = 1U;
    uint32_t i;

    check_curve(0x45CU, 0x460U, 0x4B8U);
    ram_op(0x5E8U, gx, 32U);
    ram_op(0x63CU, gy, 32U);
    ram_op(0xF40U, qx, 32U);
    ram_op(0xF94U, qy, 32U);
    ram_op(0x1098U, r, 32U);
    ram_op(0xA44U, s, 32U);
    ram_op(0xFE8U, e, 32U);
    ram_op(0xD5CU, n, 32U);
    if ((ut_wb_ram_word(0x404U) != 256U) || (ut_wb_ram_word(0x4B4U) != 256U) || (memcmp(gx, k_gx, 32U) != 0) ||
        (memcmp(gy, k_gy, 32U) != 0) || (memcmp(n, k_n, 32U) != 0)) {
        proto();
    }
    for (i = 0U; i < g_wb.verify_n; i++) {
        if ((memcmp(qx, g_wb.verify_tab[i].qx, 32U) == 0) && (memcmp(qy, g_wb.verify_tab[i].qy, 32U) == 0) &&
            (memcmp(e, g_wb.verify_tab[i].e, 32U) == 0) && (memcmp(r, g_wb.verify_tab[i].r, 32U) == 0) &&
            (memcmp(s, g_wb.verify_tab[i].s, 32U) == 0)) {
            result = 0U;
        }
    }
    if (g_wb.pka_force_verify == 1U) {
        result = 1U;
    } else if (g_wb.pka_force_verify == 2U) {
        result = 0U;
    } else {
        /* Table answer. */
    }
    ram_set(0x5B0U, result);
}

static void pka_op_modexp(void)
{
    uint8_t base[400];
    uint8_t exp[400];
    uint8_t mod[400];
    uint8_t res[400];
    uint32_t op_bits = ut_wb_ram_word(0x404U);
    uint32_t exp_bits = ut_wb_ram_word(0x400U);
    uint32_t len = op_bits / 8U;
    uint32_t elen = exp_bits / 8U;

    g_wb.pka_exp_bits = exp_bits;
    g_wb.pka_op_bits = op_bits;
    if (((op_bits % 8U) != 0U) || ((exp_bits % 8U) != 0U) || (len == 0U) || (len > 392U) || (elen == 0U) ||
        (elen > 392U)) {
        proto();
        return;
    }
    ram_op(0xA44U, base, len);
    ram_op(0xBD0U, exp, elen);
    ram_op(0xD5CU, mod, len);
    ut_ref_modexp(res, base, exp, elen, mod, len);
    ram_put(0xA44U, res, len);
}

static void pka_start(void)
{
    uint32_t mode = (g_wb.pka_cr >> 8) & 0x3FU;
    uint32_t i;

    g_wb.pka_starts++;
    g_wb.pka_last_mode = mode;
    g_wb.pka_wipe_checked = 0U;
    for (i = 0U; i < UT_WB_PKA_WORDS; i++) {
        if (g_wb.pka_ram[i] != 0U) {
            g_wb.pka_wipe_checked++;
        }
    }
    if (g_wb.pka_never_end != 0U) {
        return;
    }
    if ((g_wb.pka_ramerr != 0U) || ((g_wb.pka_fault_start != 0U) && (g_wb.pka_starts == g_wb.pka_fault_start))) {
        g_wb.pka_flags |= (1U << 19);
        return;
    }
    if (g_wb.pka_addrerr != 0U) {
        g_wb.pka_flags |= (1U << 20);
        return;
    }
    if (mode == 0x20U) {
        pka_op_mul();
    } else if (mode == 0x28U) {
        pka_op_check();
    } else if (mode == 0x24U) {
        pka_op_sign();
    } else if (mode == 0x26U) {
        pka_op_verify();
    } else if (mode == 0x00U) {
        pka_op_modexp();
    } else {
        proto();
    }
    g_wb.pka_flags |= (1U << 17);
}

static uint32_t pka_read(uint32_t off)
{
    uint32_t v = 0U;

    if (off == 0x00U) {
        v = g_wb.pka_cr;
    } else if (off == 0x04U) {
        v = g_wb.pka_flags | (g_wb.pka_busy << 16);
    } else if ((off >= 0x400U) && (off < 0x11F8U)) {
        v = g_wb.pka_ram[(off - 0x400U) / 4U];
    } else {
        proto();
    }
    return v;
}

static void pka_write(uint32_t off, uint32_t value)
{
    if (off == 0x00U) {
        g_wb.pka_cr = value & ~2U;
        if ((value & 1U) == 0U) {
            /* Clearing EN aborts: flags are reset. */
            g_wb.pka_flags = 0U;
        } else if ((value & 2U) != 0U) {
            pka_start();
        } else {
            /* Configuration only. */
        }
    } else if (off == 0x08U) {
        g_wb.pka_flags &= ~value;
    } else if ((off >= 0x400U) && (off < 0x11F8U)) {
        g_wb.pka_ram[(off - 0x400U) / 4U] = value;
    } else {
        proto();
    }
}

/* ------------------------------------------------------------------------- */
/* bus                                                                        */
/* ------------------------------------------------------------------------- */

uint32_t noxtls_stm32wb_bus_rd(uint32_t addr)
{
    uint32_t v = 0U;

    if ((addr >= NOXTLS_STM32WB_CONFIG_AES1_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_AES1_BASE + M_AES_SPAN))) {
        v = aes_read(addr - NOXTLS_STM32WB_CONFIG_AES1_BASE);
    } else if ((addr >= NOXTLS_STM32WB_CONFIG_RNG_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_RNG_BASE + 0x0CU))) {
        v = rng_read(addr - NOXTLS_STM32WB_CONFIG_RNG_BASE);
    } else if ((addr >= NOXTLS_STM32WB_CONFIG_HSEM_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_HSEM_BASE + 0x100U))) {
        v = hsem_read(addr - NOXTLS_STM32WB_CONFIG_HSEM_BASE);
    } else if ((addr >= NOXTLS_STM32WB_CONFIG_PKA_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_PKA_BASE + 0x11F8U))) {
        v = pka_read(addr - NOXTLS_STM32WB_CONFIG_PKA_BASE);
    } else {
        g_wb.bad_access++;
    }
    return v;
}

void noxtls_stm32wb_bus_wr(uint32_t addr, uint32_t value)
{
    if ((addr >= NOXTLS_STM32WB_CONFIG_AES1_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_AES1_BASE + M_AES_SPAN))) {
        aes_write(addr - NOXTLS_STM32WB_CONFIG_AES1_BASE, value);
    } else if ((addr >= NOXTLS_STM32WB_CONFIG_RNG_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_RNG_BASE + 0x0CU))) {
        rng_write(addr - NOXTLS_STM32WB_CONFIG_RNG_BASE, value);
    } else if ((addr >= NOXTLS_STM32WB_CONFIG_HSEM_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_HSEM_BASE + 0x100U))) {
        hsem_write(addr - NOXTLS_STM32WB_CONFIG_HSEM_BASE, value);
    } else if ((addr >= NOXTLS_STM32WB_CONFIG_PKA_BASE) && (addr < (NOXTLS_STM32WB_CONFIG_PKA_BASE + 0x11F8U))) {
        pka_write(addr - NOXTLS_STM32WB_CONFIG_PKA_BASE, value);
    } else {
        g_wb.bad_access++;
    }
}
