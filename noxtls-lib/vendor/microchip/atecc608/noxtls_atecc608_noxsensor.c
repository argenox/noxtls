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
* File:    noxtls_atecc608_noxsensor.c
* Summary: NoxSensor ATECC608 driver binding for the NoxTLS ATECC608 provider
*
*****************************************************************************/

#include "noxtls_atecc608_noxsensor.h"

#if NOXTLS_FEATURE_ATECC608 && defined(NOXTLS_ATECC608_NOXSENSOR)

#include "noxsensor/noxsensor_atecc608.h"

static int ns_get_public_key(void *device, uint8_t slot, uint8_t pub_xy[64])
{
    return (noxsensor_atecc608_get_public_key((noxsensor_atecc608_t *)device, slot, pub_xy) == NOXSENSOR_OK) ? 0 : -1;
}

static int ns_sign_digest(void *device, uint8_t slot, const uint8_t digest[32], uint8_t sig_rs[64])
{
    return (noxsensor_atecc608_sign_digest((noxsensor_atecc608_t *)device, slot, digest, sig_rs) == NOXSENSOR_OK) ? 0 : -1;
}

static int ns_ecdh_keygen(void *device, uint16_t key_id, uint8_t pub_xy[64])
{
    noxsensor_atecc608_t *se = (noxsensor_atecc608_t *)device;

    if (key_id == NOXTLS_ATECC608_KEYID_TEMPKEY) {
        /* TempKey is volatile: keep the chip awake from key generation until the shared secret is computed.
         * The chip's own watchdog (about 1.3 s) still ends the session, so this only suits fast links. */
        if (noxsensor_atecc608_begin(se) != NOXSENSOR_OK) {
            return -1;
        }

        return (noxsensor_atecc608_ecdh_ephemeral_keygen(se, pub_xy) == NOXSENSOR_OK) ? 0 : -1;
    }

    return (noxsensor_atecc608_genkey_private(se, key_id, pub_xy) == NOXSENSOR_OK) ? 0 : -1;
}

static int ns_ecdh(void *device, uint16_t key_id, const uint8_t peer_xy[64], uint8_t secret[32])
{
    noxsensor_atecc608_t *se = (noxsensor_atecc608_t *)device;

    if (key_id == NOXTLS_ATECC608_KEYID_TEMPKEY) {
        noxsensor_status_t rc = noxsensor_atecc608_ecdh_ephemeral(se, peer_xy, secret);

        (void)noxsensor_atecc608_end(se);
        return (rc == NOXSENSOR_OK) ? 0 : -1;
    }

    return (noxsensor_atecc608_ecdh_slot(se, (uint8_t)key_id, peer_xy, secret) == NOXSENSOR_OK) ? 0 : -1;
}

static int ns_random(void *device, uint8_t *out, uint32_t len)
{
    return (noxsensor_atecc608_random_bytes((noxsensor_atecc608_t *)device, out, len) == NOXSENSOR_OK) ? 0 : -1;
}

void noxtls_atecc608_noxsensor_backend(noxtls_atecc608_backend_t *backend, struct noxsensor_atecc608 *device)
{
    if (backend != NULL) {
        backend->device = device;
        backend->get_public_key = ns_get_public_key;
        backend->sign_digest = ns_sign_digest;
        backend->ecdh_keygen = ns_ecdh_keygen;
        backend->ecdh = ns_ecdh;
        backend->random = ns_random;
    }
}

#endif
