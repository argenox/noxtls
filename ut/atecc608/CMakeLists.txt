# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# ATECC608B/C secure element provider: unit tests against a fake backend (software ECC behind the backend table)
# and end-to-end TLS 1.2 / 1.3 handshakes where the server or client key and the ECDHE keys live in the
# simulated chip. Each test is its own ctest (process), like ut/tls_loopback.
if(NOT NOXTLS_CFG_FEATURE_ATECC608 OR NOT COMMAND noxtls_lb_add_suite)
    return()
endif()

set(_atecc_tests
    atecc608_provider_init_args
    atecc608_provider_sign_hashes
    atecc608_provider_sign_errors
    atecc608_provider_sign_der_edge_cases
    atecc608_bound_key_signs_through_chip
    atecc608_opaque_table_limits
    atecc608_bound_key_ecdh_in_chip
    atecc608_ecdhe_generation_p256_only
    atecc608_e2e_tls13_server_key_ecdhe
    atecc608_e2e_tls13_client_key
    atecc608_e2e_tls13_key_software_ecdhe
    atecc608_e2e_tls13_ecdhe_only
    atecc608_e2e_tls12_server_key_ecdhe
    atecc608_e2e_tls12_client_key
    atecc608_e2e_tls12_ecdhe_only
    atecc608_e2e_tls13_chip_sign_failure
    atecc608_e2e_tls13_chip_keygen_failure
    atecc608_e2e_tls12_chip_sign_failure
    atecc608_e2e_tls12_chip_keygen_failure)
if(NOXTLS_CFG_FEATURE_ATECC608_ENTROPY)
    list(APPEND _atecc_tests atecc608_entropy_port)
endif()

noxtls_lb_add_suite(atecc608_test atecc608_test.c ${_atecc_tests})
target_link_libraries(atecc608_test PRIVATE noxtls_atecc608)
