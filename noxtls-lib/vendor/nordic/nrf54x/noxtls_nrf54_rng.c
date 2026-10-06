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
* File:    noxtls_nrf54_rng.c
* Summary: CRACEN TRNG entropy source
*
*****************************************************************************/

/**
 * @file noxtls_nrf54_rng.c
 * @brief Entropy from the CRACEN TRNG (nRF54L product specifications, CRACEN
 *        "RNGCONTROL"), sequence described in noxtls_nrf54_rng.h.
 * @ingroup noxtls_nrf54
 */

#include <stddef.h>

#include "noxtls_nrf54_rng.h"

/** @brief Bytes per FIFO word. */
#define NOXTLS_NRF54_RNG_WORD_BYTES     4U
/** @brief Bytes delivered per FIFO fill (16 words), used for the timeout. */
#define NOXTLS_NRF54_RNG_FILL_BYTES     64U
/** @brief Bits per byte. */
#define NOXTLS_NRF54_RNG_BITS_PER_BYTE  8U
/** @brief Byte mask. */
#define NOXTLS_NRF54_RNG_BYTE_MSK       UINT32_C(0xFF)

/** State of the request in progress. */
typedef struct {
    uint8_t *buf;      /**< Destination. */
    uint32_t len;      /**< Bytes requested. */
    uint32_t done;     /**< Bytes delivered. */
    uint32_t control;  /**< CONTROL value while running. */
    uint8_t key_set;   /**< Non-zero once the conditioning key is loaded. */
    uint8_t restarts;  /**< Restarts used by this request. */
    uint8_t failed;    /**< Non-zero: health tests kept failing. */
} noxtls_nrf54_rng_req_t;

/** Health counters. */
static noxtls_nrf54_rng_health_t s_noxtls_nrf54_rng_health;

/**
 * @brief Program the TRNG from reset and start it.
 * @internal
 *
 * @param[in,out] req Request.
 */
static void noxtls_nrf54_rng_start(noxtls_nrf54_rng_req_t *req)
{
    uint8_t lite = (noxtls_nrf54_cracen_hw()->variant == NOXTLS_NRF54_VARIANT_LITE) ? 1U : 0U;
    uint32_t control = NOXTLS_NRF54_RNG_CTRL_ENABLE | NOXTLS_NRF54_RNG_CTRL_INTENFULL | NOXTLS_NRF54_RNG_CTRL_INTENREP |
                       ((NOXTLS_NRF54_RNG_NB128_DEFAULT & NOXTLS_NRF54_RNG_CTRL_NB128_MSK) << NOXTLS_NRF54_RNG_CTRL_NB128_POS);

    noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_CONTROL, NOXTLS_NRF54_RNG_CTRL_SOFTRST);
    if (lite != 0U) {
        /* The CRACEN Lite cut-off registers lose their values at every power-up. */
        noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_REPEAT, NOXTLS_NRF54_RNG_LITE_REPEAT_CUTOFF);
        noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_PROPCUT, NOXTLS_NRF54_RNG_LITE_PROP_CUTOFF);
    } else {
        noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_OFFTIMER, NOXTLS_NRF54_RNG_OFFTIMER_DEFAULT);
        control |= NOXTLS_NRF54_RNG_CTRL_INTENPROP;
    }
    noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_CLKDIV, (lite != 0U) ? NOXTLS_NRF54_RNG_CLKDIV_LM20 : NOXTLS_NRF54_RNG_CLKDIV_L15);
    noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_WARMUP, NOXTLS_NRF54_RNG_WARMUP_DEFAULT);
    req->control = control;
    req->key_set = 0U;
    noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_CONTROL, control);
}

/**
 * @brief Account a health-test failure and restart, or give up.
 * @internal
 *
 * @param[in,out] req    Request.
 * @param[in]     status STATUS value.
 *
 * @return Non-zero when the request failed for good.
 */
static uint8_t noxtls_nrf54_rng_on_error(noxtls_nrf54_rng_req_t *req, uint32_t status)
{
    noxtls_nrf54_rng_health_t *h = &s_noxtls_nrf54_rng_health;
    uint8_t give_up = 0U;

    if ((status & NOXTLS_NRF54_RNG_ST_STARTUPFAIL) != 0U) {
        h->startup_failures++;
    }
    if ((status & NOXTLS_NRF54_RNG_ST_REPFAIL) != 0U) {
        h->repetition_failures++;
    }
    if ((status & NOXTLS_NRF54_RNG_ST_PROPFAIL) != 0U) {
        h->proportion_failures++;
    }
    h->last_status = status;
    if (req->restarts < (uint8_t)NOXTLS_NRF54_CONFIG_RNG_RESTARTS) {
        /* Discard everything delivered so far and start again. */
        req->restarts++;
        h->restarts++;
        req->done = 0U;
        noxtls_nrf54_rng_start(req);
    } else {
        req->failed = 1U;
        give_up = 1U;
    }
    return give_up;
}

/**
 * @brief Advance the request (conditioning key, FIFO drain, health tests).
 * @internal
 *
 * @param[in,out] ctx noxtls_nrf54_rng_req_t.
 *
 * @return Non-zero when the request is complete or failed.
 */
static uint8_t noxtls_nrf54_rng_service(void *ctx)
{
    noxtls_nrf54_rng_req_t *req = (noxtls_nrf54_rng_req_t *)ctx;
    uint32_t status = noxtls_nrf54_core_rd(NOXTLS_NRF54_RNG_STATUS);
    uint32_t state = (status >> NOXTLS_NRF54_RNG_ST_STATE_POS) & NOXTLS_NRF54_RNG_ST_STATE_MSK;
    uint8_t done = 0U;

    if (state == NOXTLS_NRF54_RNG_STATE_ERROR) {
        done = noxtls_nrf54_rng_on_error(req, status);
    } else if ((state != NOXTLS_NRF54_RNG_STATE_RESET) && (state != NOXTLS_NRF54_RNG_STATE_STARTUP)) {
        uint32_t level = noxtls_nrf54_core_rd(NOXTLS_NRF54_RNG_FIFOLEVEL);

        if (req->key_set == 0U) {
            if (level >= NOXTLS_NRF54_RNG_KEY_WORDS) {
                uint32_t i;

                for (i = 0U; i < NOXTLS_NRF54_RNG_KEY_WORDS; i++) {
                    noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_KEY0 + (i * NOXTLS_NRF54_RNG_WORD_BYTES),
                                         noxtls_nrf54_core_rd(NOXTLS_NRF54_RNG_FIFO));
                }
                /* Output produced so far used the reset key: flush it. */
                noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_CONTROL, req->control | NOXTLS_NRF54_RNG_CTRL_SOFTRST);
                noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_CONTROL, req->control);
                req->key_set = 1U;
            }
        } else {
            while ((level > 0U) && (req->done < req->len)) {
                uint32_t word = noxtls_nrf54_core_rd(NOXTLS_NRF54_RNG_FIFO);
                uint32_t i;

                for (i = 0U; (i < NOXTLS_NRF54_RNG_WORD_BYTES) && (req->done < req->len); i++) {
                    req->buf[req->done] = (uint8_t)(word & NOXTLS_NRF54_RNG_BYTE_MSK);
                    word >>= NOXTLS_NRF54_RNG_BITS_PER_BYTE;
                    req->done++;
                }
                level--;
            }
            done = (req->done >= req->len) ? 1U : 0U;
        }
    } else {
        /* Warm-up / start-up tests running. */
    }
    return done;
}

noxtls_return_t noxtls_nrf54_rng_fill(uint8_t *buf, uint32_t len)
{
    noxtls_return_t rc = NOXTLS_RETURN_SUCCESS;

    if (buf == NULL) {
        rc = NOXTLS_RETURN_NULL;
    } else if (len == 0U) {
        /* Nothing requested. */
    } else {
        rc = noxtls_nrf54_cracen_acquire(NOXTLS_NRF54_MOD_RNG);
        if ((rc == NOXTLS_RETURN_SUCCESS) &&
            ((noxtls_nrf54_cracen_caps()->inclips & NOXTLS_NRF54_INCLIPS_BA431) == 0U)) {
            noxtls_nrf54_cracen_release();
            rc = NOXTLS_RETURN_NOT_SUPPORTED;
        }
        if (rc == NOXTLS_RETURN_SUCCESS) {
            noxtls_nrf54_rng_req_t req = { NULL, 0U, 0U, 0U, 0U, 0U, 0U };
            uint64_t fills = ((uint64_t)len + (NOXTLS_NRF54_RNG_FILL_BYTES - 1U)) / NOXTLS_NRF54_RNG_FILL_BYTES;
            uint64_t timeout = (uint64_t)NOXTLS_NRF54_CONFIG_RNG_TIMEOUT_US +
                               ((fills * (uint64_t)NOXTLS_NRF54_CONFIG_RNG_US_PER_FILL) *
                                ((uint64_t)NOXTLS_NRF54_CONFIG_RNG_RESTARTS + 1U));

            req.buf = buf;
            req.len = len;
            noxtls_nrf54_rng_start(&req);
            rc = noxtls_nrf54_cracen_wait(NOXTLS_NRF54_MOD_RNG, noxtls_nrf54_rng_service, &req,
                                          (timeout > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)timeout);
            noxtls_nrf54_core_wr(NOXTLS_NRF54_RNG_CONTROL, NOXTLS_NRF54_RNG_CTRL_OFF);
            if ((rc == NOXTLS_RETURN_SUCCESS) && (req.failed != 0U)) {
                rc = NOXTLS_RETURN_FAILED;
            }
            if (rc != NOXTLS_RETURN_SUCCESS) {
                noxtls_nrf54_wipe(buf, len);
            } else {
                s_noxtls_nrf54_rng_health.requests++;
            }
            noxtls_nrf54_cracen_release();
        }
    }
    return rc;
}

const noxtls_nrf54_rng_health_t *noxtls_nrf54_rng_health(void)
{
    return &s_noxtls_nrf54_rng_health;
}

void noxtls_nrf54_rng_reset_health(void)
{
    noxtls_nrf54_wipe(&s_noxtls_nrf54_rng_health, (uint32_t)sizeof(s_noxtls_nrf54_rng_health));
}
