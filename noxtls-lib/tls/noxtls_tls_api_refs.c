#include "noxtls_tls_noxsight.h"
/*****************************************************************************
* Copyright (c) [2019] - [2026], Argenox Technologies LLC
* SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
*
* File:    noxtls_tls_api_refs.c
* Summary: Second-TU references for public TLS APIs (MISRA Rule 8.7).
*****************************************************************************/

#include <stdint.h>
#include "noxtls_misra_refs.h"

#include "noxtls_tls.h"
#include "noxtls_tls12.h"
#include "noxtls_tls13.h"
#include "noxtls_tls_common.h"
#include "noxtls_dtls_common.h"
#include "noxtls_tls_unified.h"
/**
 * @brief Take addresses of public TLS APIs so they are referenced from a
 *        second translation unit (Rule 8.7) without changing behavior.
 */
static void noxtls_tls_misra_api_refs(void)
{
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_client_certificate);

    NOXTLS_MISRA_REF_FN(&dtls_set_retransmit);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls12_context_init);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls13_context_init);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls13_context_init_with_workspaces);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls13_send_new_connection_id);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_check_replay);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_recv_handshake_fragment);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_set_ack_range_limit);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_set_anti_amplification_limit);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_set_flight_buffer);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_set_mtu);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls_update_replay_window);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_dhe_send_client_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_ecdhe_recv_client_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_ecdhe_recv_server_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_ecdhe_send_client_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_ecdhe_send_server_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_get_peer_ocsp_response);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_client_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_certificate_verify_build_signed_content);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_certificate_verify_build_signed_content_ex);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_certificate_verify_transcript_hash_length);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_key_share_decode);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_process_client_key_share);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_record_size_limit);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_accept);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_close);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_connect);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_flush);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_free);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_get_cipher_suite);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_get_peer_certificate);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_get_resumption_identity);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_get_session_identity);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_get_version);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_handshake);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_init);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_init_version);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_is_resumed);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_recv);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_send);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_client_cert_ecdsa);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_client_cert_rsa);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_client_fallback_scsv);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_force_cert_verify_fail);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_io_callbacks);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_io_mode);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_io_tx_queue_limit);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_maximum_record_payload);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_request_client_auth);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_require_client_auth);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_server_alpn_protocols);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_server_cert);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_server_cert_chain);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_server_cipher_suites);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_server_private_key);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_sni);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_time_callback);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_tls13_session);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_connection_set_verify_crl);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_ecc_curve_to_named_group);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_encode_ecc_point_uncompressed);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_parse_extension_alpn);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_parse_extension_key_share);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_parse_extension_signature_algorithms);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_parse_extension_sni);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_parse_extension_supported_groups);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_parse_extension_supported_versions);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_set_record_dump_file);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_verify_certificate_signature);
    NOXTLS_MISRA_REF_FN(&tls12_compute_master_secret);
    NOXTLS_MISRA_REF_FN(&tls12_derive_keys);
    NOXTLS_MISRA_REF_FN(&tls12_set_workspaces);
    NOXTLS_MISRA_REF_FN(&tls_accept_auto);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls13_send_new_connection_ids);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_client_session_ticket_len);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_certificate);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_change_cipher_spec);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_change_cipher_spec_client);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_client_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_client_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_finished);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_finished_client);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_server_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_server_hello_done);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_recv_server_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_certificate);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_certificate_request);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_change_cipher_spec);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_change_cipher_spec_server);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_client_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_finished);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_finished_server);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_hello_request);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_server_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_server_hello_done);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_send_server_key_exchange);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_client_accept_server_rpk);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_client_offer_client_rpk);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_client_request_ocsp_status);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_crypto_provider_server);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_crypto_provider_server);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_heartbeat);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_server_ecdsa_leaf_certificate);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_server_expected_client_sni);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_server_ocsp_response);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_server_private_ecdsa);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_server_rsa_pss_leaf_material);
    NOXTLS_MISRA_REF_FN(&noxtls_tls12_set_server_use_rpk);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_accept);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_clear_server_ecdsa_identities);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_context_free);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_context_init);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_get_channel_binding);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_certificate);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_certificate_request);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_certificate_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_client_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_encrypted_extensions);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_server_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_certificate);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_certificate_request);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_certificate_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_client_certificate_verify);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_client_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_encrypted_extensions);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_finished);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_finished_server);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_server_hello);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_client_cert_ecdsa);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_client_cert_ed448);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_client_fallback_scsv);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_client_supported_groups);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_keylog_file);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_alpn_protocols);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_cipher_suites);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_ecdsa);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_ed25519);
    #if NOXTLS_FEATURE_ML_DSA
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_mldsa);
#endif
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_rsa);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_verify_crl);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_add_server_ecdsa_identity);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_session_import);
    #if NOXTLS_FEATURE_SLH_DSA
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_slhdsa);
#endif
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_context_init_with_workspaces);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_export_keying_material);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_last_accept_fail_step);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_last_connect_fail_step);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_finished);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_recv_finished_client);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_early_data);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_send_key_update);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_session_export);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_client_cert_ed25519);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_client_signature_algorithms);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_prefer_chacha20);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_expected_client_sni);
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_ed448);
#if NOXTLS_FEATURE_FALCON
    NOXTLS_MISRA_REF_FN(&noxtls_tls13_set_server_private_falcon);
#endif
    NOXTLS_MISRA_REF_FN(&noxtls_dtls13_rotate_connection_id);
    NOXTLS_MISRA_REF_FN(&noxtls_dtls13_send_request_connection_id);
    NOXTLS_MISRA_REF_FN(&tls13_set_workspaces);
#if NOXTLS_FEATURE_ML_DSA
    NOXTLS_MISRA_REF_FN(&tls13_set_client_cert_mldsa);
#endif
#if NOXTLS_FEATURE_SLH_DSA
    NOXTLS_MISRA_REF_FN(&tls13_set_client_cert_slhdsa);
#endif
#if NOXTLS_FEATURE_FALCON
    NOXTLS_MISRA_REF_FN(&tls13_set_client_cert_falcon);
#endif
    NOXTLS_MISRA_REF_FN(&tls13_set_external_psk);
    NOXTLS_MISRA_REF_FN(&noxtls_tls_decode_ecc_point_uncompressed);
}

/* Keep refs TU live for analyzers without exporting linkage (Rule 8.7). */
__attribute__((used)) static void noxtls_tls_misra_api_refs_keep(void)
{
    noxtls_tls_misra_api_refs();

    (void)(TLS_STATE_ERROR);
#if defined(NOXTLS_NS_MOD_SESSION)
    (void)(NOXTLS_NS_MOD_SESSION);
    (void)(NOXTLS_EVT_SESSION_RESUME);
    (void)(NOXTLS_STATE_RECV_ENC_EXT);
    (void)(NOXTLS_STATE_CLOSED);
#endif
}
