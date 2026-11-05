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
* File:    noxtls_efr32_se_hash.c
* Summary: EFR32xG2x Secure Engine SHA-2 block compression
*
*****************************************************************************/

/**
 * @file noxtls_efr32_se_hash.c
 * @brief SE_COMMAND_HASHUPDATE: whole-block SHA-256 / SHA-512 compression with the
 *        chaining value passed in and out (FIPS 180-4 §6.2.2 and §6.4.2).
 * @ingroup noxtls_efr32
 *
 * Command layout (Simplicity SDK v2025.6.3 sl_se_manager_hash.c, Zlib, re-expressed):
 * command word HASHUPDATE | algorithm option; one parameter, the data length;
 * input chain: [chaining value] -> [data]; output chain: [chaining value].
 * The chaining value is in FIPS 180-4 byte order (big-endian words), 32 bytes
 * for SHA-256 and 64 bytes for SHA-512. Finalization (padding, length) stays in
 * NoxTLS, so SHA-224 / SHA-384 use the same commands. Messages longer than
 * NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES are split into several commands, the
 * chaining value carried in the module between them.
 */

#include <stddef.h>
#include <string.h>

#include "noxtls_efr32_se_ops.h"

/** Staging buffers of the hash command (owned while the mailbox is held). */
static struct {
    noxtls_efr32_se_xfer_t in_state;   /**< Chaining value in. */
    noxtls_efr32_se_xfer_t in_data;    /**< Message blocks in. */
    noxtls_efr32_se_xfer_t out_state;  /**< Chaining value out. */
    uint8_t state[NOXTLS_EFR32_SE_STATE_512]; /**< Chaining value. */
} s_noxtls_efr32_hash;

/**
 * @brief Run one HASHUPDATE command (mailbox owned).
 * @internal
 *
 * @param[in] option     Algorithm option.
 * @param[in] state_len  Chaining value bytes.
 * @param[in] data       Blocks.
 * @param[in] data_len   Bytes.
 *
 * @return noxtls_efr32_se_run() result.
 */
static noxtls_return_t noxtls_efr32_hash_cmd(uint32_t option, uint32_t state_len, const uint8_t *data, uint32_t data_len)
{
    noxtls_efr32_se_cmd_t cmd;
    uint64_t kib = ((uint64_t)data_len + 1023U) / 1024U;
    uint64_t timeout = (uint64_t)NOXTLS_EFR32_CONFIG_SE_TIMEOUT_US + (kib * (uint64_t)NOXTLS_EFR32_CONFIG_SE_US_PER_KIB);

    noxtls_efr32_se_xfer_set(&s_noxtls_efr32_hash.in_state, s_noxtls_efr32_hash.state, state_len);
    noxtls_efr32_se_xfer_set(&s_noxtls_efr32_hash.in_data, data, data_len);
    noxtls_efr32_se_xfer_set(&s_noxtls_efr32_hash.out_state, s_noxtls_efr32_hash.state, state_len);
    noxtls_efr32_se_xfer_link(&s_noxtls_efr32_hash.in_state, &s_noxtls_efr32_hash.in_data);
    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.command = NOXTLS_EFR32_SE_CMD_HASHUPDATE | option;
    cmd.in = &s_noxtls_efr32_hash.in_state;
    cmd.out = &s_noxtls_efr32_hash.out_state;
    cmd.params[0] = data_len;
    cmd.nparams = 1U;
    return noxtls_efr32_se_run(&cmd, (timeout > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)timeout);
}

noxtls_return_t noxtls_efr32_se_hash_blocks(uint32_t alg, uint8_t *state, const uint8_t *data, uint32_t block_count)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;
    uint32_t state_len = (alg == NOXTLS_EFR32_SE_HASH_SHA512) ? NOXTLS_EFR32_SE_STATE_512 : NOXTLS_EFR32_SE_STATE_256;
    uint32_t block = (alg == NOXTLS_EFR32_SE_HASH_SHA512) ? NOXTLS_EFR32_SE_BLOCK_512 : NOXTLS_EFR32_SE_BLOCK_256;
    uint32_t option = (alg == NOXTLS_EFR32_SE_HASH_SHA512) ? NOXTLS_EFR32_SE_OPT_HASH_SHA512 : NOXTLS_EFR32_SE_OPT_HASH_SHA256;
    uint64_t total = (uint64_t)block_count * (uint64_t)block;

    if ((alg != NOXTLS_EFR32_SE_HASH_SHA256) && (alg != NOXTLS_EFR32_SE_HASH_SHA512)) {
        rc = NOXTLS_RETURN_INVALID_PARAM;
    } else if ((state == NULL) || ((data == NULL) && (block_count != 0U))) {
        rc = NOXTLS_RETURN_NULL;
    } else if (noxtls_efr32_op_allowed((alg == NOXTLS_EFR32_SE_HASH_SHA512) ? NOXTLS_EFR32_OP_SHA512 :
                                       NOXTLS_EFR32_OP_SHA256) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else if ((block_count == 0U) || (total > (uint64_t)UINT32_MAX)) {
        rc = (block_count == 0U) ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_NOT_SUPPORTED;
    } else if (noxtls_efr32_dma_in_ok(data, (uint32_t)total) == 0U) {
        rc = NOXTLS_RETURN_NOT_SUPPORTED;
    } else {
        uint8_t work[NOXTLS_EFR32_SE_STATE_512];
        uint32_t done = 0U;
        uint32_t len = (uint32_t)total;

        (void)memcpy(work, state, state_len);
        while ((rc == NOXTLS_RETURN_SUCCESS) && (done < len)) {
            uint32_t take = ((len - done) > (uint32_t)NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES) ?
                            (uint32_t)NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES : (len - done);

            rc = noxtls_efr32_se_acquire();
            if (rc == NOXTLS_RETURN_SUCCESS) {
                (void)memcpy(s_noxtls_efr32_hash.state, work, state_len);
                rc = noxtls_efr32_hash_cmd(option, state_len, &data[done], take);
                if (rc == NOXTLS_RETURN_SUCCESS) {
                    (void)memcpy(work, s_noxtls_efr32_hash.state, state_len);
                    done += take;
                }
                noxtls_efr32_wipe(s_noxtls_efr32_hash.state, (uint32_t)sizeof(s_noxtls_efr32_hash.state));
                noxtls_efr32_se_release();
            }
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            (void)memcpy(state, work, state_len);
        }
        noxtls_efr32_wipe(work, (uint32_t)sizeof(work));
    }
    return rc;
}
