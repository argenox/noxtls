/* Copyright (c) 2026 Argenox Technologies LLC.
 * SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial */
/** @file server_name_ack_test.c
 * @brief RFC 6066 Section 3 direction-specific SNI extension regression tests.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "noxtls_tls_common.h"
#include "noxtls_tls13.h"
#include "common/noxtls_memory.h"

static tls13_context_t client;

/**
 * @brief Verify that server acknowledgments and client names retain distinct formats.
 *
 * @return Zero after positive, malformed, duplicate and direction checks pass.
 */
int main(void)
{
    const uint8_t acknowledgment[] = {0,4,0,0,0,0};
    const uint8_t client_name[] = {0,12,0,0,0,8,0,6,0,0,3,'i','o','t'};
    const uint8_t duplicate[] = {0,8,0,0,0,0,0,0,0,0};
    const uint8_t nonempty[] = {0,5,0,0,0,1,0};
    const uint8_t trailing[] = {0,4,0,0,0,0,0};
    const uint8_t unknown[] = {0,4,0xfa,0xfa,0,0};
    const uint8_t empty[] = {0,0};
    const uint8_t encrypted_extensions[] = {8,0,0,6,0,4,0,0,0,0};
    tls_extensions_t extensions = {0};
    tls_extension_t *found = NULL;

    assert(noxtls_tls_parse_server_extensions(acknowledgment,sizeof(acknowledgment),&extensions) == NOXTLS_RETURN_SUCCESS);
    assert(extensions.count == 1U && extensions.sni == NULL);
    assert(noxtls_tls_find_extension(&extensions,TLS_EXTENSION_SERVER_NAME,&found) == NOXTLS_RETURN_SUCCESS);
    assert(found != NULL && found->length == 0U && found->data == NULL);
    (void)noxtls_tls_extensions_free(&extensions);
    /* Feed the real TLS 1.3 client entry point through its owned coalesced-message
     * queue. This tests extension dispatch and transcript handling, not a mock parser. */
    for (unsigned offered = 0U; offered < 2U; ++offered) {
        assert(noxtls_tls13_context_init(&client,TLS_ROLE_CLIENT) == NOXTLS_RETURN_SUCCESS);
        if (offered != 0U) {
            client.server_name = (const uint8_t *)"iot";
            client.server_name_len = 3U;
        }
        client.pending_handshake_msg = NOXTLS_MALLOC(sizeof(encrypted_extensions));
        assert(client.pending_handshake_msg != NULL);
        memcpy(client.pending_handshake_msg,encrypted_extensions,sizeof(encrypted_extensions));
        client.pending_handshake_len = sizeof(encrypted_extensions);
        assert(noxtls_tls13_recv_encrypted_extensions(&client) ==
            (offered != 0U ? NOXTLS_RETURN_SUCCESS : NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER));
        assert(client.pending_handshake_msg == NULL);
        (void)noxtls_tls13_context_free(&client);
    }
    assert(noxtls_tls_parse_extensions(acknowledgment,sizeof(acknowledgment),&extensions) == NOXTLS_RETURN_BAD_DATA);
    assert(noxtls_tls_parse_extensions(client_name,sizeof(client_name),&extensions) == NOXTLS_RETURN_SUCCESS);
    assert(extensions.sni != NULL && extensions.sni->name_len == 3U);
    (void)noxtls_tls_extensions_free(&extensions);
    assert(noxtls_tls_parse_server_extensions(client_name,sizeof(client_name),&extensions) == NOXTLS_RETURN_BAD_DATA);
    assert(noxtls_tls_parse_server_extensions(duplicate,sizeof(duplicate),&extensions) == NOXTLS_RETURN_TLS_ALERT_ILLEGAL_PARAMETER);
    assert(noxtls_tls_parse_server_extensions(nonempty,sizeof(nonempty),&extensions) == NOXTLS_RETURN_BAD_DATA);
    assert(noxtls_tls_parse_server_extensions(trailing,sizeof(trailing),&extensions) == NOXTLS_RETURN_BAD_DATA);
    assert(noxtls_tls_parse_server_extensions(acknowledgment,sizeof(acknowledgment)-1U,&extensions) == NOXTLS_RETURN_BAD_DATA);
    assert(noxtls_tls_parse_server_extensions(NULL,0U,&extensions) == NOXTLS_RETURN_NULL);
    assert(noxtls_tls_parse_server_extensions(acknowledgment,sizeof(acknowledgment),NULL) == NOXTLS_RETURN_NULL);
    assert(noxtls_tls_parse_server_extensions(empty,sizeof(empty),&extensions) == NOXTLS_RETURN_SUCCESS);
    (void)noxtls_tls_extensions_free(&extensions);
    assert(noxtls_tls_parse_server_extensions(unknown,sizeof(unknown),&extensions) == NOXTLS_RETURN_SUCCESS);
    (void)noxtls_tls_extensions_free(&extensions);
    puts("Server SNI acknowledgment, strict client SNI, malformed and duplicate rejection PASS");
    return 0;
}
