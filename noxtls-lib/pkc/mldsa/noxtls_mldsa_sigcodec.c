/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* This file is part of the NoxTLS Library.
*
* File:    noxtls_mldsa_sigcodec.c
* Summary: Internal ML-DSA signature codec helpers.
*/

#include <string.h>

#include "noxtls_mldsa_internal.h"

static void mldsa_bitpack_put(uint8_t *dst, uint32_t *bit_off, uint32_t value, uint8_t bit_count)
{
    uint8_t i;
    for(i = 0u; i < bit_count; ++i) {
        uint32_t bit = (value >> i) & 1u;
        uint32_t byte_idx = (*bit_off) >> 3;
        uint8_t bit_idx = (uint8_t)((*bit_off) & 7u);
        if(bit != 0u) {
            dst[byte_idx] = (uint8_t)(dst[byte_idx] | (uint8_t)(1u << bit_idx));
        } else {
            dst[byte_idx] = (uint8_t)(dst[byte_idx] & (uint8_t)(~(1u << bit_idx)));
        }
        (*bit_off)++;
    }
}

static uint32_t mldsa_bitpack_get(const uint8_t *src, uint32_t *bit_off, uint8_t bit_count)
{
    uint32_t value = 0u;
    uint8_t i;
    for(i = 0u; i < bit_count; ++i) {
        uint32_t byte_idx = (*bit_off) >> 3;
        uint8_t bit_idx = (uint8_t)((*bit_off) & 7u);
        uint32_t bit = (uint32_t)((src[byte_idx] >> bit_idx) & 1u);
        value |= (bit << i);
        (*bit_off)++;
    }
    return value;
}

static noxtls_return_t mldsa_sig_format(noxtls_mldsa_param_t param,
                                        noxtls_mldsa_param_spec_t *spec,
                                        uint8_t *z_bits,
                                        uint32_t *c_len,
                                        uint32_t *z_len,
                                        uint32_t *h_len,
                                        uint32_t *total_len)
{
    uint32_t local_c_len;
    uint8_t local_z_bits;
    noxtls_return_t rc;

    if(spec == NULL || z_bits == NULL || c_len == NULL || z_len == NULL || h_len == NULL || total_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = noxtls_mldsa_internal_get_param_spec(param, spec);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(spec->gamma1 == 131072) {
        local_z_bits = 18u;
    } else if(spec->gamma1 == 524288) {
        local_z_bits = 20u;
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    if(param == NOXTLS_MLDSA_44) {
        local_c_len = 32u;
    } else if(param == NOXTLS_MLDSA_65) {
        local_c_len = 48u;
    } else if(param == NOXTLS_MLDSA_87) {
        local_c_len = 64u;
    } else {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    *z_bits = local_z_bits;
    *c_len = local_c_len;
    *z_len = ((uint32_t)spec->l * NOXTLS_MLDSA_N * local_z_bits) / 8u;
    *h_len = (uint32_t)spec->omega + (uint32_t)spec->k;
    *total_len = *c_len + *z_len + *h_len;
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t mldsa_encode_z(const noxtls_mldsa_param_spec_t *spec,
                                      uint8_t z_bits,
                                      const noxtls_mldsa_polyvecl_t *z,
                                      uint8_t *dst,
                                      uint32_t dst_len)
{
    uint32_t bit_off = 0u;
    uint32_t i;
    uint32_t j;

    if(spec == NULL || z == NULL || dst == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    memset(dst, 0, dst_len);
    for(j = 0u; j < spec->l; ++j) {
        for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
            int32_t coeff = z->v[j].coeff[i];
            if(coeff < -spec->gamma1 || coeff > spec->gamma1) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            mldsa_bitpack_put(dst, &bit_off, (uint32_t)(coeff + spec->gamma1), z_bits);
        }
    }
    if((bit_off / 8u) != dst_len) {
        return NOXTLS_RETURN_FAILED;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t mldsa_decode_z(const noxtls_mldsa_param_spec_t *spec,
                                      uint8_t z_bits,
                                      const uint8_t *src,
                                      uint32_t src_len,
                                      noxtls_mldsa_polyvecl_t *z)
{
    uint32_t bit_off = 0u;
    uint32_t i;
    uint32_t j;

    if(spec == NULL || src == NULL || z == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    noxtls_mldsa_poly_zero(&z->v[0]);
    noxtls_mldsa_poly_zero(&z->v[1]);
    noxtls_mldsa_poly_zero(&z->v[2]);
    noxtls_mldsa_poly_zero(&z->v[3]);
    noxtls_mldsa_poly_zero(&z->v[4]);
    noxtls_mldsa_poly_zero(&z->v[5]);
    noxtls_mldsa_poly_zero(&z->v[6]);

    for(j = 0u; j < spec->l; ++j) {
        for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
            uint32_t enc = mldsa_bitpack_get(src, &bit_off, z_bits);
            int32_t coeff = (int32_t)enc - spec->gamma1;
            if(coeff < -spec->gamma1 || coeff > spec->gamma1) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            z->v[j].coeff[i] = coeff;
        }
    }
    if((bit_off / 8u) != src_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t mldsa_encode_h(const noxtls_mldsa_param_spec_t *spec,
                                      const noxtls_mldsa_polyveck_t *h,
                                      uint8_t *dst,
                                      uint32_t dst_len)
{
    uint32_t hint_count = 0u;
    uint32_t i;
    uint32_t j;

    if(spec == NULL || h == NULL || dst == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(dst_len != ((uint32_t)spec->omega + (uint32_t)spec->k)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(dst, 0, dst_len);
    for(j = 0u; j < spec->k; ++j) {
        for(i = 0u; i < NOXTLS_MLDSA_N; ++i) {
            int32_t coeff = h->v[j].coeff[i];
            if(coeff != 0 && coeff != 1) {
                return NOXTLS_RETURN_INVALID_PARAM;
            }
            if(coeff == 1) {
                if(hint_count >= spec->omega) {
                    return NOXTLS_RETURN_INVALID_PARAM;
                }
                dst[hint_count] = (uint8_t)i;
                hint_count++;
            }
        }
        dst[spec->omega + j] = (uint8_t)hint_count;
    }
    return NOXTLS_RETURN_SUCCESS;
}

static noxtls_return_t mldsa_decode_h(const noxtls_mldsa_param_spec_t *spec,
                                      const uint8_t *src,
                                      uint32_t src_len,
                                      noxtls_mldsa_polyveck_t *h)
{
    uint32_t i;
    uint32_t j;
    uint32_t hint_cursor = 0u;

    if(spec == NULL || src == NULL || h == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    if(src_len != ((uint32_t)spec->omega + (uint32_t)spec->k)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    for(j = 0u; j < NOXTLS_MLDSA_K_MAX; ++j) {
        noxtls_mldsa_poly_zero(&h->v[j]);
    }

    for(j = 0u; j < spec->k; ++j) {
        uint32_t hint_bound = (uint32_t)src[spec->omega + j];
        uint8_t prev_index = 0u;

        if(hint_bound < hint_cursor || hint_bound > spec->omega) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        for(i = hint_cursor; i < hint_bound; ++i) {
            uint8_t coeff_index = src[i];
            if(i > hint_cursor && coeff_index <= prev_index) {
                return NOXTLS_RETURN_BAD_DATA;
            }
            h->v[j].coeff[coeff_index] = 1;
            prev_index = coeff_index;
        }
        hint_cursor = hint_bound;
    }
    for(i = hint_cursor; i < spec->omega; ++i) {
        if(src[i] != 0u) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mldsa_pack_signature_internal(noxtls_mldsa_param_t param,
                                                     const noxtls_mldsa_sig_parts_t *parts,
                                                     uint8_t *sig,
                                                     uint32_t *sig_len)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint8_t z_bits;
    uint32_t c_len;
    uint32_t z_len;
    uint32_t h_len;
    uint32_t need_len;

    if(parts == NULL || sig_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = mldsa_sig_format(param, &spec, &z_bits, &c_len, &z_len, &h_len, &need_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    if(sig == NULL || *sig_len < need_len) {
        *sig_len = need_len;
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memcpy(sig, parts->c_seed, c_len);
    rc = mldsa_encode_z(&spec, z_bits, &parts->z, sig + c_len, z_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mldsa_encode_h(&spec, &parts->h, sig + c_len + z_len, h_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    *sig_len = need_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_mldsa_unpack_signature_internal(noxtls_mldsa_param_t param,
                                                       const uint8_t *sig,
                                                       uint32_t sig_len,
                                                       noxtls_mldsa_sig_parts_t *parts)
{
    noxtls_mldsa_param_spec_t spec;
    noxtls_return_t rc;
    uint8_t z_bits;
    uint32_t c_len;
    uint32_t z_len;
    uint32_t h_len;
    uint32_t need_len;

    if(sig == NULL || parts == NULL) {
        return NOXTLS_RETURN_NULL;
    }

    rc = mldsa_sig_format(param, &spec, &z_bits, &c_len, &z_len, &h_len, &need_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(sig_len != need_len) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }

    memset(parts->c_seed, 0, sizeof(parts->c_seed));
    memcpy(parts->c_seed, sig, c_len);
    rc = noxtls_mldsa_make_challenge(param, parts->c_seed, c_len, &parts->c);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mldsa_decode_z(&spec, z_bits, sig + c_len, z_len, &parts->z);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    rc = mldsa_decode_h(&spec, sig + c_len + z_len, h_len, &parts->h);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }

    return NOXTLS_RETURN_SUCCESS;
}
