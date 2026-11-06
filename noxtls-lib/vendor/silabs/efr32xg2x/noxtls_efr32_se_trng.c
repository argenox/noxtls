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
* File:    noxtls_efr32_se_trng.c
* Summary: EFR32xG2x Secure Engine TRNG entropy source
*
*****************************************************************************/

/**
 * @file noxtls_efr32_se_trng.c
 * @brief SE_COMMAND_TRNG_GET_RANDOM (output transfer + byte-count parameter) as an
 *        entropy source for the NoxTLS CTR-DRBG (NIST SP 800-90A §8.6.3).
 * @ingroup noxtls_efr32
 *
 * The SE conditions its TRNG output itself (NIST SP 800-90B health tests run
 * inside the SE); the command returns an error response when the source fails.
 * Requests are served in words and chunks of NOXTLS_EFR32_TRNG_CHUNK bytes.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_efr32_se_ops.h"

/** @brief Bytes per SE TRNG command (multiple of 4). */
#define NOXTLS_EFR32_TRNG_CHUNK         64U
/** @brief The SE delivers whole words. */
#define NOXTLS_EFR32_TRNG_WORD          4U

/** Staging buffer of the TRNG command (owned while the mailbox is held). */
static struct {
    noxtls_efr32_se_xfer_t out;                 /**< Output transfer. */
    uint8_t data[NOXTLS_EFR32_TRNG_CHUNK];      /**< Random bytes. */
} s_noxtls_efr32_trng;

noxtls_return_t noxtls_efr32_se_trng_fill(uint8_t *buf, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t done = 0U;

    if ((buf == NULL) && (len != 0U)) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_efr32_op_allowed(NOXTLS_EFR32_OP_TRNG) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        /* Allowed. */
    }
    while ((rc == NOXTLS_RETURN_SUCCESS) && (done < len)) {
        uint32_t take = ((len - done) > NOXTLS_EFR32_TRNG_CHUNK) ? NOXTLS_EFR32_TRNG_CHUNK : (len - done);
        uint32_t words = (take + (NOXTLS_EFR32_TRNG_WORD - 1U)) & ~(NOXTLS_EFR32_TRNG_WORD - 1U);
        noxtls_efr32_se_cmd_t cmd;

        rc = noxtls_efr32_se_acquire();
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_efr32_se_xfer_set(&s_noxtls_efr32_trng.out, s_noxtls_efr32_trng.data, words);
            (void)memset(&cmd, 0, sizeof(cmd));
            cmd.command = NOXTLS_EFR32_SE_CMD_TRNG;
            cmd.out = &s_noxtls_efr32_trng.out;
            cmd.params[0] = words;
            cmd.nparams = 1U;
            rc = noxtls_efr32_se_run(&cmd, (uint32_t)NOXTLS_EFR32_CONFIG_SE_TIMEOUT_US);
            if (rc == NOXTLS_RETURN_SUCCESS) {
                (void)memcpy(&buf[done], s_noxtls_efr32_trng.data, take);
                done += take;
            }
            noxtls_efr32_wipe(s_noxtls_efr32_trng.data, (uint32_t)sizeof(s_noxtls_efr32_trng.data));
            noxtls_efr32_se_release();
        }
    }
    if ((rc != NOXTLS_RETURN_SUCCESS) && (buf != NULL)) {
        noxtls_efr32_wipe(buf, len);
        if (rc == NOXTLS_RETURN_INVALID_PARAM) {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    return rc;
}
