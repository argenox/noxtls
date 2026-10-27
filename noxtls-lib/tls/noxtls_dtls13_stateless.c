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
* File:    noxtls_dtls13_stateless.c
* Summary: DTLS 1.3 stateless HelloRetryRequest and second-ClientHello binder check
*
* A server that keeps no state for a first ClientHello answers it with a HelloRetryRequest
* that carries a cookie (RFC 9147 Section 5.1; RFC 8446 Sections 4.1.4 and 4.2.2). The
* second ClientHello returns the cookie; the transcript then starts with
* message_hash(ClientHello1) followed by the HelloRetryRequest (RFC 8446 Section 4.4.1).
* The HelloRetryRequest is a deterministic function of the echoed legacy_session_id, the
* cookie, the cipher suite and the group, so it is rebuilt from the second ClientHello
* instead of being stored. Nothing here allocates or touches a connection context.
*
*****************************************************************************/

#include <stdint.h>

#include "noxtls_common.h"
#include "noxtls_ct.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls13.h"
#include "noxtls_tls13_psk.h"
#include "noxtls_dtls13_stateless.h"
#include "mdigest/noxtls_hash.h"
#include "mdigest/sha256/noxtls_sha256.h"

#if NOXTLS_FEATURE_DTLS

/* RFC 8446 Section 4.1.3: ServerHello.random of a HelloRetryRequest, SHA-256("HelloRetryRequest"). */
static const uint8_t s_dtls13_hrr_random[32] = {
    0xCFU, 0x21U, 0xADU, 0x74U, 0xE5U, 0x9AU, 0x61U, 0x11U,
    0xBEU, 0x1DU, 0x8CU, 0x02U, 0x1EU, 0x65U, 0xB8U, 0x91U,
    0xC2U, 0xA2U, 0x11U, 0x16U, 0x7AU, 0xBBU, 0x8CU, 0x5EU,
    0x07U, 0x9EU, 0x09U, 0xE2U, 0xC8U, 0xA8U, 0x33U, 0x9CU
};

/* Offsets inside a ClientHello body, RFC 8446 Section 4.1.2 and RFC 9147 Section 5.3. */
#define ST_CH_RANDOM_OFFSET     2U
#define ST_CH_SESSION_ID_OFFSET 34U
/* Smallest ClientHello body: version, random, empty session_id, empty legacy_cookie, one
 * suite, one compression method and an extension block length. */
#define ST_CH_BODY_MIN          (2U + 32U + 1U + 1U + 2U + 2U + 1U + 1U + 2U)

static uint16_t st_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8U) | (uint16_t)p[1]);
}

static uint32_t st_u24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16U) | ((uint32_t)p[1] << 8U) | (uint32_t)p[2];
}

static uint64_t st_u48(const uint8_t *p)
{
    uint64_t v = 0U;
    uint32_t i;

    for(i = 0U; i < 6U; i += 1U) {
        v = (v << 8U) | (uint64_t)p[i];
    }
    return v;
}

static void st_put_u16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 8U) & 0xFFU);
    p[1] = (uint8_t)(v & 0xFFU);
}

static void st_put_u48(uint8_t *p, uint64_t v)
{
    uint64_t rest = v;
    uint32_t i;

    for(i = 6U; i > 0U; i -= 1U) {
        p[i - 1U] = (uint8_t)(rest & 0xFFU);
        rest >>= 8U;
    }
}

static void st_put_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 16U) & 0xFFU);
    p[1] = (uint8_t)((v >> 8U) & 0xFFU);
    p[2] = (uint8_t)(v & 0xFFU);
}

uint8_t dtls13_suite_is_sha256(uint16_t cipher_suite)
{
    return ((cipher_suite == TLS_CIPHER_SUITE_AES_128_GCM_SHA256) ||
            (cipher_suite == TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) ||
            (cipher_suite == TLS_CIPHER_SUITE_AES_128_CCM_SHA256) ||
            (cipher_suite == TLS_CIPHER_SUITE_AES_128_CCM_8_SHA256)) ? 1U : 0U;
}

void dtls13_message_hash(const uint8_t *ch1_hash, uint8_t *out)
{
    out[0] = TLS_HANDSHAKE_MESSAGE_HASH;
    st_put_u24(&out[1], 32U);
    noxtls_copy_u8(&out[4], 32U, ch1_hash, 32U);
}

/**
 * Check the record and handshake headers of a datagram that must hold exactly one epoch-0
 * record with one unfragmented ClientHello (RFC 9147 Sections 4 and 5.2); the body is not
 * parsed.
 * @param[out] body ClientHello body, @p body_len its length.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_BAD_DATA.
 */
static noxtls_return_t st_client_hello_record(const uint8_t *dgram, uint32_t len,
                                              const uint8_t **body, uint32_t *body_len)
{
    const uint8_t *hs;
    uint32_t record_len;
    uint32_t msg_len;
    uint16_t version;

    if(len < (DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    /* RFC 9147 Section 4: DTLSPlaintext, epoch 0; the first ClientHello may use 0xFEFF. */
    version = st_u16(&dgram[DTLS_RECORD_VERSION_OFFSET]);
    if((dgram[DTLS_RECORD_TYPE_OFFSET] != TLS_RECORD_HANDSHAKE) ||
       ((version != DTLS_1_3_LEGACY_RECORD_VERSION) && (version != 0xFEFFU)) ||
       (st_u16(&dgram[DTLS_RECORD_EPOCH_OFFSET]) != 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    record_len = (uint32_t)st_u16(&dgram[DTLS_RECORD_LENGTH_OFFSET]);
    if((DTLS_RECORD_HEADER_SIZE + record_len) != len) {
        return NOXTLS_RETURN_BAD_DATA;  /* exactly one record */
    }
    hs = &dgram[DTLS_RECORD_HEADER_SIZE];
    msg_len = st_u24(&hs[DTLS_HANDSHAKE_LENGTH_OFFSET]);
    if((hs[DTLS_HANDSHAKE_TYPE_OFFSET] != TLS_HANDSHAKE_CLIENT_HELLO) ||
       (st_u24(&hs[DTLS_HANDSHAKE_FRAGMENT_OFFSET]) != 0U) ||
       (st_u24(&hs[DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET]) != msg_len) ||
       ((DTLS_HANDSHAKE_HEADER_SIZE + msg_len) != record_len)) {
        return NOXTLS_RETURN_BAD_DATA;  /* exactly one unfragmented ClientHello */
    }
    *body = &hs[DTLS_HANDSHAKE_BODY_OFFSET];
    *body_len = msg_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t dtls13_parse_client_hello_datagram(const uint8_t *dgram, uint32_t len, dtls13_ch_view_t *view)
{
    const uint8_t *body = NULL;
    uint32_t msg_len = 0U;
    uint32_t off;
    uint8_t sid_len;
    uint16_t suites_len;
    uint16_t exts_len;
    uint32_t p;
    noxtls_return_t rc;

    if((dgram == NULL) || (view == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    noxtls_secure_zero(view, sizeof(*view));
    rc = st_client_hello_record(dgram, len, &body, &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if((msg_len < ST_CH_BODY_MIN) || (st_u16(body) != DTLS_1_3_LEGACY_RECORD_VERSION)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    sid_len = body[ST_CH_SESSION_ID_OFFSET];
    off = ST_CH_SESSION_ID_OFFSET + 1U;
    if((sid_len > TLS_SESSION_ID_MAX_LEN) || ((off + (uint32_t)sid_len + 1U) > msg_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    view->session_id = &body[off];
    view->session_id_len = sid_len;
    off += (uint32_t)sid_len;
    /* RFC 9147 Section 5.1: a DTLS 1.3 ClientHello has an empty legacy_cookie. */
    if(body[off] != 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    off += 1U;
    if((off + 2U) > msg_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    suites_len = st_u16(&body[off]);
    off += 2U;
    if((suites_len == 0U) || ((suites_len & 1U) != 0U) || ((off + (uint32_t)suites_len + 2U) > msg_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    view->suites = &body[off];
    view->suites_len = suites_len;
    off += (uint32_t)suites_len;
    /* RFC 8446 Section 4.1.2: exactly one compression method, null. */
    if((body[off] != 1U) || (body[off + 1U] != 0U)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    off += 2U;
    if((off + 2U) > msg_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    exts_len = st_u16(&body[off]);
    off += 2U;
    if((off + (uint32_t)exts_len) != msg_len) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    view->exts = &body[off];
    view->exts_len = exts_len;
    p = 0U;
    while(p < (uint32_t)exts_len) {
        uint32_t ext_len;
        if((p + 4U) > (uint32_t)exts_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        ext_len = (uint32_t)st_u16(&view->exts[p + 2U]);
        p += 4U;
        if((p + ext_len) > (uint32_t)exts_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        p += ext_len;
    }
    view->record_seq = st_u48(&dgram[DTLS_RECORD_SEQUENCE_OFFSET]);
    view->message_seq = st_u16(&dgram[DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET]);
    view->body = body;
    view->body_len = msg_len;
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t dtls13_ch_find_extension(const dtls13_ch_view_t *view, uint16_t type,
                                         const uint8_t **data, uint16_t *data_len)
{
    uint32_t p = 0U;

    if((view == NULL) || (view->exts == NULL) || (data == NULL) || (data_len == NULL)) {
        return NOXTLS_RETURN_FAILED;
    }
    while((p + 4U) <= (uint32_t)view->exts_len) {
        uint16_t ext_type = st_u16(&view->exts[p]);
        uint16_t ext_len = st_u16(&view->exts[p + 2U]);
        p += 4U;
        if((p + (uint32_t)ext_len) > (uint32_t)view->exts_len) {
            return NOXTLS_RETURN_FAILED;
        }
        if(ext_type == type) {
            *data = &view->exts[p];
            *data_len = ext_len;
            return NOXTLS_RETURN_SUCCESS;
        }
        p += (uint32_t)ext_len;
    }
    return NOXTLS_RETURN_FAILED;
}

noxtls_return_t dtls13_ch_cookie(const dtls13_ch_view_t *view, const uint8_t **cookie, uint16_t *cookie_len)
{
    const uint8_t *data = NULL;
    uint16_t data_len = 0U;
    uint16_t len;

    if(dtls13_ch_find_extension(view, TLS_EXTENSION_COOKIE, &data, &data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    /* RFC 8446 Section 4.2.2: opaque cookie<1..2^16-1>. */
    if(data_len < 3U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    len = st_u16(data);
    if((len == 0U) || (((uint32_t)len + 2U) != (uint32_t)data_len) || (len > NOXTLS_DTLS13_STATELESS_COOKIE_MAX)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    *cookie = &data[2];
    *cookie_len = len;
    return NOXTLS_RETURN_SUCCESS;
}

/** 1 when @p suite is in the ClientHello's cipher_suites. */
static uint8_t st_ch_offers_suite(const dtls13_ch_view_t *view, uint16_t suite)
{
    uint32_t i;

    for(i = 0U; (i + 2U) <= (uint32_t)view->suites_len; i += 2U) {
        if(st_u16(&view->suites[i]) == suite) {
            return 1U;
        }
    }
    return 0U;
}

/**
 * Walk the key_share extension, RFC 8446 Section 4.2.8.
 * @param[out] entries Number of KeyShareEntry values.
 * @param[out] has_group 1 when one of them is for @p group.
 * @return NOXTLS_RETURN_SUCCESS (also when absent: 0 entries); NOXTLS_RETURN_BAD_DATA.
 */
static noxtls_return_t st_ch_key_shares(const dtls13_ch_view_t *view, uint16_t group,
                                        uint32_t *entries, uint8_t *has_group)
{
    const uint8_t *data = NULL;
    uint16_t data_len = 0U;
    uint32_t p = 2U;

    *entries = 0U;
    *has_group = 0U;
    if(dtls13_ch_find_extension(view, TLS_EXTENSION_KEY_SHARE, &data, &data_len) != NOXTLS_RETURN_SUCCESS) {
        return NOXTLS_RETURN_SUCCESS;
    }
    if((data_len < 2U) || (((uint32_t)st_u16(data) + 2U) != (uint32_t)data_len)) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    while(p < (uint32_t)data_len) {
        uint32_t kex_len;
        if((p + 4U) > (uint32_t)data_len) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        kex_len = (uint32_t)st_u16(&data[p + 2U]);
        if((kex_len == 0U) || ((p + 4U + kex_len) > (uint32_t)data_len)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
        if(st_u16(&data[p]) == group) {
            *has_group = 1U;
        }
        *entries += 1U;
        p += 4U + kex_len;
    }
    return NOXTLS_RETURN_SUCCESS;
}

/** 1 when the ClientHello's supported_groups lists @p group (RFC 8446 Section 4.2.7). */
static uint8_t st_ch_lists_group(const dtls13_ch_view_t *view, uint16_t group)
{
    const uint8_t *data = NULL;
    uint16_t data_len = 0U;
    uint32_t i;

    if(dtls13_ch_find_extension(view, TLS_EXTENSION_SUPPORTED_GROUPS, &data, &data_len) != NOXTLS_RETURN_SUCCESS) {
        return 0U;
    }
    if((data_len < 2U) || (((uint32_t)st_u16(data) + 2U) != (uint32_t)data_len)) {
        return 0U;
    }
    for(i = 2U; (i + 2U) <= (uint32_t)data_len; i += 2U) {
        if(st_u16(&data[i]) == group) {
            return 1U;
        }
    }
    return 0U;
}

noxtls_return_t dtls13_ch2_check_hrr_params(const dtls13_ch_view_t *view, uint16_t cipher_suite, uint16_t group)
{
    uint32_t entries = 0U;
    uint8_t has_group = 0U;

    if((view == NULL) || (dtls13_suite_is_sha256(cipher_suite) == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    /* RFC 8446 Section 4.1.2: the second ClientHello keeps the cipher suites. */
    if(st_ch_offers_suite(view, cipher_suite) == 0U) {
        return NOXTLS_RETURN_BAD_DATA;
    }
    if(group != 0U) {
        /* RFC 8446 Section 4.1.2: one KeyShareEntry for the group the HelloRetryRequest named. */
        if((st_ch_key_shares(view, group, &entries, &has_group) != NOXTLS_RETURN_SUCCESS) ||
           (entries != 1U) || (has_group == 0U)) {
            return NOXTLS_RETURN_BAD_DATA;
        }
    }
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t dtls13_build_hrr_message(const uint8_t *session_id, uint8_t session_id_len,
                                         uint16_t cipher_suite, uint16_t group,
                                         const uint8_t *cookie, uint16_t cookie_len,
                                         uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    uint32_t need;
    uint32_t off = 0U;

    if((out_len == NULL) || (cookie == NULL) || ((session_id == NULL) && (session_id_len != 0U)) ||
       (session_id_len > TLS_SESSION_ID_MAX_LEN)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    need = 4U + 2U + 32U + 1U + (uint32_t)session_id_len + 2U + 1U + 2U + 6U +
           ((group != 0U) ? 6U : 0U) + 6U + (uint32_t)cookie_len;
    *out_len = need;
    if((out == NULL) || (cap < need)) {
        return NOXTLS_RETURN_BUFFER_TOO_SMALL;
    }
    out[off] = TLS_HANDSHAKE_SERVER_HELLO;
    st_put_u24(&out[off + 1U], need - 4U);
    off += 4U;
    st_put_u16(&out[off], DTLS_VERSION_1_2);  /* legacy_version */
    off += 2U;
    noxtls_copy_u8(&out[off], 32U, s_dtls13_hrr_random, 32U);
    off += 32U;
    out[off] = session_id_len;
    off += 1U;
    if(session_id_len > 0U) {
        noxtls_copy_u8(&out[off], (size_t)session_id_len, session_id, (size_t)session_id_len);
        off += (uint32_t)session_id_len;
    }
    st_put_u16(&out[off], (uint32_t)cipher_suite);
    off += 2U;
    out[off] = 0U;  /* legacy_compression_method */
    off += 1U;
    st_put_u16(&out[off], need - off - 2U);
    off += 2U;
    /* Extension order as in the NoxTLS stateful HelloRetryRequest. */
    st_put_u16(&out[off], (uint32_t)TLS_EXTENSION_SUPPORTED_VERSIONS);
    st_put_u16(&out[off + 2U], 2U);
    st_put_u16(&out[off + 4U], DTLS_VERSION_1_3);
    off += 6U;
    if(group != 0U) {
        st_put_u16(&out[off], (uint32_t)TLS_EXTENSION_KEY_SHARE);
        st_put_u16(&out[off + 2U], 2U);
        st_put_u16(&out[off + 4U], (uint32_t)group);
        off += 6U;
    }
    st_put_u16(&out[off], (uint32_t)TLS_EXTENSION_COOKIE);
    st_put_u16(&out[off + 2U], (uint32_t)cookie_len + 2U);
    st_put_u16(&out[off + 4U], (uint32_t)cookie_len);
    off += 6U;
    noxtls_copy_u8(&out[off], (size_t)cookie_len, cookie, (size_t)cookie_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls13_stateless_hrr(const uint8_t *ch1, uint32_t ch1_len,
                                            const uint8_t *cookie, uint16_t cookie_len,
                                            uint16_t cipher_suite, uint16_t group,
                                            uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    dtls13_ch_view_t view;
    uint32_t msg_len = 0U;
    uint32_t total;
    uint32_t body_len;
    noxtls_return_t rc;

    if((ch1 == NULL) || (cookie == NULL) || (out == NULL) || (out_len == NULL) ||
       (cookie_len == 0U) || (cookie_len > NOXTLS_DTLS13_STATELESS_COOKIE_MAX) ||
       (dtls13_suite_is_sha256(cipher_suite) == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = dtls13_parse_client_hello_datagram(ch1, ch1_len, &view);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    if(st_ch_offers_suite(&view, cipher_suite) == 0U) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    if(group != 0U) {
        uint32_t entries = 0U;
        uint8_t has_group = 0U;
        rc = st_ch_key_shares(&view, group, &entries, &has_group);
        if(rc != NOXTLS_RETURN_SUCCESS) {
            return rc;
        }
        /* RFC 8446 Section 4.2.8: a group the client supports and sent no share for. */
        const uint8_t listed = st_ch_lists_group(&view, group);
        if((has_group != 0U) || (listed == 0U)) {
            return NOXTLS_RETURN_INVALID_PARAM;
        }
    }
    (void)dtls13_build_hrr_message(view.session_id, view.session_id_len, cipher_suite, group,
                                   cookie, cookie_len, NULL, 0U, &msg_len);
    /* Record header, then the 12-byte DTLS handshake header in place of the 4-byte one. */
    total = DTLS_RECORD_HEADER_SIZE + 8U + msg_len;
    *out_len = total;
    if(cap < total) {
        return NOXTLS_RETURN_BUFFER_TOO_SMALL;
    }
    rc = dtls13_build_hrr_message(view.session_id, view.session_id_len, cipher_suite, group, cookie, cookie_len,
                                  &out[DTLS_RECORD_HEADER_SIZE + 8U], cap - (DTLS_RECORD_HEADER_SIZE + 8U), &msg_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    body_len = msg_len - 4U;
    /* RFC 9147 Section 4: epoch 0 DTLSPlaintext with CH1's record sequence number. */
    out[DTLS_RECORD_TYPE_OFFSET] = TLS_RECORD_HANDSHAKE;
    st_put_u16(&out[DTLS_RECORD_VERSION_OFFSET], DTLS_1_3_LEGACY_RECORD_VERSION);
    st_put_u16(&out[DTLS_RECORD_EPOCH_OFFSET], 0U);
    st_put_u48(&out[DTLS_RECORD_SEQUENCE_OFFSET], view.record_seq);
    st_put_u16(&out[DTLS_RECORD_LENGTH_OFFSET], DTLS_HANDSHAKE_HEADER_SIZE + body_len);
    /* RFC 9147 Section 5.2: one unfragmented message with CH1's message_seq. */
    out[DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_TYPE_OFFSET] = TLS_HANDSHAKE_SERVER_HELLO;
    st_put_u24(&out[DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_LENGTH_OFFSET], body_len);
    st_put_u16(&out[DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_MESSAGE_SEQ_OFFSET], (uint32_t)view.message_seq);
    st_put_u24(&out[DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_FRAGMENT_OFFSET], 0U);
    st_put_u24(&out[DTLS_RECORD_HEADER_SIZE + DTLS_HANDSHAKE_FRAGMENT_LEN_OFFSET], body_len);
    return NOXTLS_RETURN_SUCCESS;
}

noxtls_return_t noxtls_dtls13_client_hello_hash(const uint8_t *ch, uint32_t ch_len, uint8_t hash[32])
{
    noxtls_sha_ctx_t sha;
    uint8_t header[4];
    const uint8_t *body = NULL;
    uint32_t body_len = 0U;
    noxtls_return_t rc;

    if((ch == NULL) || (hash == NULL)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    /* Only the framing is checked: the hash covers whatever ClientHello body is there. */
    rc = st_client_hello_record(ch, ch_len, &body, &body_len);
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    /* RFC 9147 Section 5.2: the transcript uses msg_type, length and body, without
     * message_seq and the fragment fields. */
    header[0] = TLS_HANDSHAKE_CLIENT_HELLO;
    st_put_u24(&header[1], body_len);
    rc = noxtls_sha256_init(&sha, NOXTLS_HASH_SHA_256);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&sha, header, sizeof(header));
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_update(&sha, body, body_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = noxtls_sha256_finish(&sha, hash);
    }
    noxtls_secure_zero(&sha, sizeof(sha));
    return rc;
}

/**
 * Find the binder of @p identity in a ClientHello handshake message with the TLS 1.3 header.
 * @param[in,out] id_copy Scratch of @p identity_len bytes.
 * @return NOXTLS_RETURN_SUCCESS; NOXTLS_RETURN_AUTH_FAILED when not offered;
 *         NOXTLS_RETURN_BAD_DATA for a malformed pre_shared_key extension.
 */
static noxtls_return_t st_find_identity_binder(const uint8_t *ch, uint32_t ch_len,
                                               const uint8_t *identity, uint16_t identity_len,
                                               uint8_t *id_copy, uint32_t *binder_offset, uint16_t *binder_len)
{
    uint16_t index;

    for(index = 0U; index < 0xFFFFU; index += 1U) {
        uint16_t selected = 0U;
        uint16_t id_len = identity_len;
        noxtls_return_t rc = tls13_psk_find_clienthello_binder(ch, ch_len, index, binder_offset, binder_len,
                                                               &selected, id_copy, &id_len);
        if(rc == NOXTLS_RETURN_FAILED) {
            return NOXTLS_RETURN_AUTH_FAILED;  /* no pre_shared_key extension */
        }
        if(rc != NOXTLS_RETURN_SUCCESS) {
            /* BAD_DATA also ends the identities list: an index past the last one. */
            return (index == 0U) ? NOXTLS_RETURN_BAD_DATA : NOXTLS_RETURN_AUTH_FAILED;
        }
        if((id_len == identity_len) && (noxtls_ct_equal(id_copy, identity, (size_t)identity_len) != 0)) {
            return NOXTLS_RETURN_SUCCESS;
        }
    }
    return NOXTLS_RETURN_AUTH_FAILED;
}

noxtls_return_t noxtls_dtls13_ch2_binder_check(const uint8_t *ch2, uint32_t len,
                                               const uint8_t ch1_hash[32],
                                               uint16_t cipher_suite, uint16_t group,
                                               const uint8_t *identity, uint16_t identity_len,
                                               const uint8_t *psk, uint16_t psk_len,
                                               uint8_t *scratch, uint32_t scratch_len)
{
    dtls13_ch_view_t view;
    const uint8_t *cookie = NULL;
    uint16_t cookie_len = 0U;
    uint32_t hrr_len = 0U;
    uint32_t prefix_len;
    uint32_t ch_len;
    uint32_t need;
    uint8_t *ch;
    uint8_t expected[32];
    uint32_t binder_offset = 0U;
    uint16_t binder_len = 0U;
    noxtls_return_t rc;

    if((ch2 == NULL) || (ch1_hash == NULL) || (identity == NULL) || (identity_len == 0U) ||
       (psk == NULL) || (psk_len == 0U) || (scratch == NULL) || (dtls13_suite_is_sha256(cipher_suite) == 0U)) {
        return NOXTLS_RETURN_INVALID_PARAM;
    }
    rc = dtls13_parse_client_hello_datagram(ch2, len, &view);
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = dtls13_ch_cookie(&view, &cookie, &cookie_len);
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        rc = dtls13_ch2_check_hrr_params(&view, cipher_suite, group);
    }
    if(rc != NOXTLS_RETURN_SUCCESS) {
        return rc;
    }
    (void)dtls13_build_hrr_message(view.session_id, view.session_id_len, cipher_suite, group,
                                   cookie, cookie_len, NULL, 0U, &hrr_len);
    /* scratch: message_hash(CH1) || HelloRetryRequest || CH2 (TLS 1.3 header) || identity copy */
    prefix_len = 36U + hrr_len;
    ch_len = 4U + view.body_len;
    need = prefix_len + ch_len + (uint32_t)identity_len;
    if(scratch_len < need) {
        return NOXTLS_RETURN_BUFFER_TOO_SMALL;
    }
    dtls13_message_hash(ch1_hash, scratch);
    rc = dtls13_build_hrr_message(view.session_id, view.session_id_len, cipher_suite, group, cookie, cookie_len,
                                  &scratch[36], scratch_len - 36U, &hrr_len);
    ch = &scratch[prefix_len];
    if(rc == NOXTLS_RETURN_SUCCESS) {
        ch[0] = TLS_HANDSHAKE_CLIENT_HELLO;
        st_put_u24(&ch[1], view.body_len);
        noxtls_copy_u8(&ch[4], (size_t)view.body_len, view.body, (size_t)view.body_len);
        rc = st_find_identity_binder(ch, ch_len, identity, identity_len, &ch[ch_len], &binder_offset, &binder_len);
    }
    if((rc == NOXTLS_RETURN_SUCCESS) && (binder_len != 32U)) {
        rc = NOXTLS_RETURN_BAD_DATA;  /* a SHA-256 PSK has 32-byte binders */
    }
    if(rc == NOXTLS_RETURN_SUCCESS) {
        /* RFC 8446 Section 4.2.11.2: binder over Transcript-Hash(message_hash, HRR, Truncate(CH2)). */
        rc = tls13_psk_compute_external_binder(NOXTLS_HASH_SHA_256, 1U, psk, psk_len, ch, ch_len,
                                               binder_offset, binder_len, expected,
                                               scratch, prefix_len, NULL);
        if(rc == NOXTLS_RETURN_SUCCESS) {
            rc = (noxtls_secret_memcmp(&ch[binder_offset], expected, sizeof(expected)) == 0) ?
                 NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_AUTH_FAILED;
        } else if(rc == NOXTLS_RETURN_BAD_DATA) {
            /* Malformed ClientHello: keep BAD_DATA. */
        } else {
            rc = NOXTLS_RETURN_FAILED;
        }
    }
    noxtls_secure_zero(expected, sizeof(expected));
    noxtls_secure_zero(scratch, (size_t)need);
    return rc;
}

#endif /* NOXTLS_FEATURE_DTLS */
