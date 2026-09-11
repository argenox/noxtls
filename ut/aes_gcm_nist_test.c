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
* File:    aes_gcm_nist_test.c
* Summary: NIST SP 800-38D AES-GCM known-answer host tests
*
*
*****************************************************************************/

/**
 * @file aes_gcm_nist_test.c
 * @brief Host unit tests for AES-GCM (NIST SP 800-38D Appendix B vectors).
 * @ingroup noxtls_encryption
 */

#include <stdio.h>
#include <string.h>

#include "noxtls_common.h"
#include "encryption/aes/noxtls_aes_gcm.h"

typedef struct {
    const char *name;
    noxtls_aes_type_t type;
    const uint8_t *key;
    uint32_t key_len;
    const uint8_t *nonce; /* 12 bytes */
    const uint8_t *aad;
    uint32_t aad_len;
    const uint8_t *plaintext;
    uint32_t pt_len;
    const uint8_t *ciphertext;
    const uint8_t *tag; /* 16 bytes */
} aes_gcm_nist_vector_t;

/* NIST SP 800-38D Appendix B, Test Case 2 (AES-128, empty plaintext). */
static const uint8_t tc2_key[16] = {0};
static const uint8_t tc2_nonce[12] = {0};
static const uint8_t tc2_tag[16] = {
    0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
    0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
};

/* NIST SP 800-38D Appendix B, Test Case 3 (AES-128, 128-bit plaintext). */
static const uint8_t tc3_key[16] = {0};
static const uint8_t tc3_nonce[12] = {0};
static const uint8_t tc3_pt[16] = {0};
static const uint8_t tc3_ct[16] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};
static const uint8_t tc3_tag[16] = {
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
    0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};

/* NIST SP 800-38D Appendix B, Test Case 4 (AES-128, 512-bit PT + AAD). */
static const uint8_t tc4_key[16] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static const uint8_t tc4_nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};
static const uint8_t tc4_aad[20] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};
static const uint8_t tc4_pt[60] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};
static const uint8_t tc4_ct[60] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91
};
static const uint8_t tc4_tag[16] = {
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

/* NIST SP 800-38D Appendix B, Test Case 14 (AES-256, 128-bit plaintext). */
static const uint8_t tc14_key[32] = {0};
static const uint8_t tc14_nonce[12] = {0};
static const uint8_t tc14_pt[16] = {0};
static const uint8_t tc14_ct[16] = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
};
static const uint8_t tc14_tag[16] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
};

static const aes_gcm_nist_vector_t g_vectors[] = {
    {
        "NIST-B-TC2-AES128-empty",
        NOXTLS_AES_128_BIT,
        tc2_key, sizeof(tc2_key),
        tc2_nonce,
        NULL, 0U,
        NULL, 0U,
        NULL,
        tc2_tag
    },
    {
        "NIST-B-TC3-AES128-16B",
        NOXTLS_AES_128_BIT,
        tc3_key, sizeof(tc3_key),
        tc3_nonce,
        NULL, 0U,
        tc3_pt, sizeof(tc3_pt),
        tc3_ct,
        tc3_tag
    },
    {
        "NIST-B-TC4-AES128-60B-AAD",
        NOXTLS_AES_128_BIT,
        tc4_key, sizeof(tc4_key),
        tc4_nonce,
        tc4_aad, sizeof(tc4_aad),
        tc4_pt, sizeof(tc4_pt),
        tc4_ct,
        tc4_tag
    },
    {
        "NIST-B-TC14-AES256-16B",
        NOXTLS_AES_256_BIT,
        tc14_key, sizeof(tc14_key),
        tc14_nonce,
        NULL, 0U,
        tc14_pt, sizeof(tc14_pt),
        tc14_ct,
        tc14_tag
    },
};

static int run_vector(const aes_gcm_nist_vector_t *v)
{
    uint8_t ct[64];
    uint8_t pt[64];
    uint8_t tag[16];
    noxtls_return_t rc;

    if(v->pt_len > sizeof(ct)) {
        fprintf(stderr, "%s: plaintext too large for test buffer\n", v->name);
        return -1;
    }

    memset(ct, 0xA5, sizeof(ct));
    memset(tag, 0x5A, sizeof(tag));

    rc = noxtls_aes_gcm_encrypt(v->key, v->type, v->nonce,
                                v->aad, v->aad_len,
                                (v->pt_len > 0U) ? v->plaintext : (const uint8_t *)"",
                                v->pt_len,
                                ct, tag);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "%s: encrypt failed (%d)\n", v->name, (int)rc);
        return -1;
    }

    if(v->pt_len > 0U && memcmp(ct, v->ciphertext, v->pt_len) != 0) {
        unsigned i;
        fprintf(stderr, "%s: ciphertext mismatch\n  got ", v->name);
        for(i = 0U; i < v->pt_len; i++) {
            fprintf(stderr, "%02x", ct[i]);
        }
        fprintf(stderr, "\n  exp ");
        for(i = 0U; i < v->pt_len; i++) {
            fprintf(stderr, "%02x", v->ciphertext[i]);
        }
        fprintf(stderr, "\n");
        return -1;
    }
    if(memcmp(tag, v->tag, sizeof(tag)) != 0) {
        unsigned i;
        fprintf(stderr, "%s: tag mismatch\n  got ", v->name);
        for(i = 0U; i < 16U; i++) {
            fprintf(stderr, "%02x", tag[i]);
        }
        fprintf(stderr, "\n  exp ");
        for(i = 0U; i < 16U; i++) {
            fprintf(stderr, "%02x", v->tag[i]);
        }
        fprintf(stderr, "\n");
        return -1;
    }

    memset(pt, 0x3C, sizeof(pt));
    rc = noxtls_aes_gcm_decrypt(v->key, v->type, v->nonce,
                                v->aad, v->aad_len,
                                ct, v->pt_len, tag, pt);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        fprintf(stderr, "%s: decrypt failed (%d)\n", v->name, (int)rc);
        return -1;
    }
    if(v->pt_len > 0U && memcmp(pt, v->plaintext, v->pt_len) != 0) {
        fprintf(stderr, "%s: plaintext mismatch after decrypt\n", v->name);
        return -1;
    }

    /* Negative: flip one tag byte. */
    tag[0] ^= 0x01U;
    rc = noxtls_aes_gcm_decrypt(v->key, v->type, v->nonce,
                                v->aad, v->aad_len,
                                ct, v->pt_len, tag, pt);
    if(rc != NOXTLS_RETURN_BAD_DATA) {
        fprintf(stderr, "%s: expected BAD_DATA on bad tag, got %d\n", v->name, (int)rc);
        return -1;
    }

    printf("PASS %s\n", v->name);
    return 0;
}

int main(void)
{
    unsigned i;
    int failures = 0;

    for(i = 0U; i < (sizeof(g_vectors) / sizeof(g_vectors[0])); i++) {
        if(run_vector(&g_vectors[i]) != 0) {
            failures++;
        }
    }

    if(failures != 0) {
        fprintf(stderr, "aes_gcm_nist_test: %d vector(s) failed\n", failures);
        return 1;
    }

    printf("aes_gcm_nist_test: all %u vectors passed\n",
           (unsigned)(sizeof(g_vectors) / sizeof(g_vectors[0])));
    return 0;
}
