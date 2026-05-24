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
* File:    noxtls_ecdh.c
* Summary: Elliptic Curve Diffie-Hellman (ECDH) Key Exchange Implementation
*
*
*****************************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/noxtls_memory.h"
#include "common/noxtls_memory_compat.h"
#include "noxtls_ecdh.h"

/**
 * @brief ECDH Compute Shared Secret
 * 
 * Computes the shared secret from our private key and peer's public key.
 * Shared secret = d * Q_peer, where d is our private key and Q_peer is peer's public point.
 * 
 * @param private_key Our private key
 * @param peer_public_key Peer's public key point
 * @param shared_secret Output buffer for shared secret
 * @param shared_secret_len Input: buffer size, Output: actual shared secret length
 * @return NOXTLS_RETURN_SUCCESS on success
 */
noxtls_return_t noxtls_ecdh_compute_shared_secret(ecc_key_t *private_key, const ecc_point_t *peer_public_key, uint8_t *shared_secret, uint32_t *shared_secret_len)
{
    uint32_t required_len;
    noxtls_return_t rc;
    uint32_t i;
    int is_infinity = 1;

    if(private_key == NULL || peer_public_key == NULL || shared_secret == NULL || shared_secret_len == NULL) {
        return NOXTLS_RETURN_NULL;
    }
    
    if(private_key->curve == NULL) {
        return NOXTLS_RETURN_FAILED;
    }
    
    required_len = private_key->curve->size;
    
    if(*shared_secret_len < required_len) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Reject infinity and off-curve peer points before secret-scalar multiply. */
    rc = noxtls_ecc_point_validate_public(peer_public_key, private_key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_FAILED;
    }
    
    /* Compute shared secret = d * Q_peer using scalar multiplication */
    /* This uses the same scalar multiplication as ECC */
    ecc_point_t shared_point;
    noxtls_ecc_point_init(&shared_point, private_key->curve->size);
    
    rc = noxtls_ecc_point_multiply(&shared_point, private_key->d, peer_public_key, private_key->curve);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    
    /* Verify shared point is not at infinity (should not happen with valid inputs) */
    is_infinity = 1;
    for(i = 0; i < required_len; i++) {
        if(shared_point.x[i] != 0 || shared_point.y[i] != 0) {
            is_infinity = 0;
            break;
        }
    }
    if(is_infinity) {
        return NOXTLS_RETURN_FAILED;  /* Shared secret cannot be at infinity */
    }
    
    /* Extract x-coordinate as shared secret */
    memcpy(shared_secret, shared_point.x, required_len);
    *shared_secret_len = required_len;
    
    return NOXTLS_RETURN_SUCCESS;
}

