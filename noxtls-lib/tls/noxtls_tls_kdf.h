/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* All rights reserved.
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
*
*
* NOTICE:  All information contained herein, source code, binaries and
* derived works is, and remains
* the property of Argenox Technologies and its suppliers,
* if any.  The intellectual and technical concepts contained
* herein are proprietary to Argenox Technologies
* and its suppliers may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Argenox Technologies.
*
* THIS SOFTWARE IS PROVIDED BY ARGENOX "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL ARGENOX TECHNOLOGIES LLC BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* CONTACT: info@argenox.com
* 
*
* File:    noxtls_tls_kdf.h
* Summary: TLS Key Derivation Functions (PRF, HKDF)
*
*/

#ifndef _NOXTLS_TLS_KDF_H_
#define _NOXTLS_TLS_KDF_H_

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_tls_common.h"
#include "mdigest/noxtls_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC Context */
typedef struct
{
    noxtls_hash_algos_t hash_algo;  /* Hash algorithm (SHA-256 or SHA-384) */
    uint8_t key[128];                 /* HMAC key (max size for SHA-512) */
    uint32_t key_len;                 /* Key length */
    uint8_t o_key_pad[128];           /* Outer key padding */
    uint8_t i_key_pad[128];           /* Inner key padding */
    void *hash_ctx;                    /* Hash context (opaque) */
} hmac_context_t;

/* HMAC Functions */
noxtls_return_t hmac_init(hmac_context_t *ctx, noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len);
noxtls_return_t hmac_update(hmac_context_t *ctx, const uint8_t *data, uint32_t data_len);
noxtls_return_t hmac_final(hmac_context_t *ctx, uint8_t *mac, uint32_t *mac_len);
noxtls_return_t hmac_free(hmac_context_t *ctx);
noxtls_return_t hmac_compute(noxtls_hash_algos_t hash_algo, const uint8_t *key, uint32_t key_len,
                               const uint8_t *data, uint32_t data_len, uint8_t *mac, uint32_t *mac_len);

/* TLS 1.2 PRF (Pseudo-Random Function) */
noxtls_return_t tls12_prf(const uint8_t *secret, uint32_t secret_len,
                           const uint8_t *label, uint32_t label_len,
                           const uint8_t *seed, uint32_t seed_len,
                           uint8_t *output, uint32_t output_len,
                           noxtls_hash_algos_t hash_algo);

/* TLS 1.0/1.1 PRF (uses MD5 and SHA-1) */
noxtls_return_t tls10_prf(const uint8_t *secret, uint32_t secret_len,
                           const uint8_t *label, uint32_t label_len,
                           const uint8_t *seed, uint32_t seed_len,
                           uint8_t *output, uint32_t output_len);

/* HKDF Functions (RFC 5869) */
noxtls_return_t hkdf_extract(noxtls_hash_algos_t hash_algo,
                               const uint8_t *salt, uint32_t salt_len,
                               const uint8_t *ikm, uint32_t ikm_len,
                               uint8_t *prk, uint32_t *prk_len);

noxtls_return_t hkdf_expand(noxtls_hash_algos_t hash_algo,
                              const uint8_t *prk, uint32_t prk_len,
                              const uint8_t *info, uint32_t info_len,
                              uint8_t *okm, uint32_t okm_len);

/* TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1) */
noxtls_return_t tls13_hkdf_expand_label(noxtls_hash_algos_t hash_algo,
                                          const uint8_t *secret, uint32_t secret_len,
                                          const uint8_t *label, uint32_t label_len,
                                          const uint8_t *context, uint32_t context_len,
                                          uint8_t *output, uint32_t output_len);

/* TLS 1.3 Derive-Secret (RFC 8446 Section 7.1) */
noxtls_return_t tls13_derive_secret(noxtls_hash_algos_t hash_algo,
                                      const uint8_t *secret, uint32_t secret_len,
                                      const uint8_t *label, uint32_t label_len,
                                      const uint8_t *messages, uint32_t messages_len,
                                      uint8_t *output, uint32_t output_len);

#ifdef __cplusplus
}
#endif

#endif /* _NOXTLS_TLS_KDF_H_ */

