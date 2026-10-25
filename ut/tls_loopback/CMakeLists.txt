# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# End-to-end TLS loopback regression tests: both endpoints in one process over an
# in-memory link. Each scenario is registered as its own ctest (separate process),
# so library-global state (session caches, trust store) cannot leak between them.
# lb_alloc.c replaces noxtls_memory.c in these executables to check for leaks,
# double frees and heap overruns.

set(NOXTLS_LB_DIR "${CMAKE_CURRENT_SOURCE_DIR}" CACHE INTERNAL "Shared loopback fixture directory")

add_library(noxtls_lb_fixture STATIC
    lb_fixture.c
    loopback_pki.c
)
target_include_directories(noxtls_lb_fixture PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../.."
    "${CMAKE_CURRENT_SOURCE_DIR}/../../noxtls-lib"
)
target_compile_definitions(noxtls_lb_fixture PUBLIC NOXTLS_TEST_ALLOCATOR_FAULT_INJECTION=1)
target_link_libraries(noxtls_lb_fixture PUBLIC noxtls_tls noxtls_cert noxtls_pkc noxtls_drbg noxtls_common)

# noxtls_lb_add_suite(<exe> <source> <test names...>)
function(noxtls_lb_add_suite exe source)
    # lb_alloc.c is an object of the executable (not an archive member) so its
    # noxtls_malloc/noxtls_free definitions always win over libnoxtls_common.
    add_executable(${exe} ${source} "${NOXTLS_LB_DIR}/lb_alloc.c")
    target_link_libraries(${exe} PRIVATE noxtls_lb_fixture)
    foreach(test_name ${ARGN})
        add_test(NAME ${test_name} COMMAND ${exe} ${test_name})
        set_tests_properties(${test_name} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120 LABELS "tls_loopback")
    endforeach()
endfunction()

if(NOXTLS_CFG_FEATURE_TLS13)
    noxtls_lb_add_suite(tls13_loopback_test tls13_loopback_test.c
        tls13_x25519_aes128gcm
        tls13_p256_aes256gcm
        tls13_p384_chacha20
        tls13_prefer_chacha20
        tls13_aes128ccm
        tls13_aes128ccm8
        tls13_ecdsa_chain
        tls13_rsa_pss_server
        tls13_ed25519_server
        tls13_missing_intermediate
        tls13_hostname_san_wildcard
        tls13_hostname_mismatch
        tls13_untrusted_ca
        tls13_mtls_ecdsa
        tls13_peer_cert_retention
        tls13_mtls_rsa_client
        tls13_mtls_optional_no_cert
        tls13_mtls_required_missing
        tls13_mtls_untrusted_client
        tls13_resumption_ticket
        tls13_resumption_bad_ticket
        tls13_early_data
        tls13_early_data_multi_record
        tls13_key_update
        tls13_exporter_channel_binding
        tls13_data_small_reads
        tls13_data_interleaved
        tls13_fragmented_transport
        tls13_record_size_limit
        tls13_server_close
        tls13_alloc_failure_sweep
    )
endif()

if(NOXTLS_CFG_FEATURE_TLS12)
    noxtls_lb_add_suite(tls12_loopback_test tls12_loopback_test.c
        tls12_ecdhe_ecdsa_aes128gcm
        tls12_ecdhe_ecdsa_aes256gcm
        tls12_ecdhe_ecdsa_chacha20
        tls12_ecdhe_ecdsa_aes128ccm
        tls12_ecdhe_ecdsa_aes128cbc_sha256
        tls12_ecdhe_ecdsa_aes256cbc_sha384
        tls12_ecdhe_rsa_aes128gcm
        tls12_ecdhe_rsa_aes256gcm
        tls12_ecdhe_rsa_chacha20
        tls12_ecdhe_rsa_aes128cbc_sha
        tls12_default_negotiation
        tls12_hostname_mismatch
        tls12_untrusted_ca
        tls12_missing_intermediate
        tls12_mtls_ecdsa
        tls12_mtls_rsa
        tls12_mtls_peer_certificate
        tls12_mtls_required_missing
        tls12_ticket_resumption
        tls12_secure_renegotiation_info
        tls12_ocsp_stapling_handshake
        tls12_max_fragment_length
        tls12_data_small_reads
        tls12_data_interleaved
        tls12_fragmented_transport
        tls12_alloc_failure_sweep
        tls12_mtls_ecdsa_cv_sha256_prf_sha384
        tls12_mtls_rsa_cv_sha256_prf_sha384
        tls12_mtls_ecdsa_cbc_sha384
        tls12_mtls_ecdsa_cv_same_hash
        tls12_mtls_optional_no_cert
        tls12_ems_on
        tls12_ems_off
        tls12_ems_resumption
        tls12_ems_resumption_upgrade
        tls10_rsa_cbc_handshake
        tls11_rsa_cbc_handshake
        tls12_alloc_failure_sweep_mtls
        tls12_client_hello_no_legacy_offer
        tls12_server_rejects_legacy_only_client
        tls12_server_rejects_sha1_signature_algorithms
        tls12_client_rejects_unoffered_suite
        tls12_client_rejects_sha1_server_key_exchange
        unified_client_rejects_unoffered_tls12_suite
        tls12_legacy_static_rsa_cbc
    )
endif()

if(NOXTLS_CFG_FEATURE_DTLS AND NOXTLS_CFG_FEATURE_TLS12 AND NOXTLS_CFG_FEATURE_TLS13)
    noxtls_lb_add_suite(dtls_loopback_test dtls_loopback_test.c
        dtls13_ecdsa_handshake_data
        dtls13_chacha20_handshake_data
        dtls12_ecdsa_gcm_handshake_data
        dtls12_mtls_sha384_handshake_data
    )
endif()

if(NOXTLS_CFG_FEATURE_TLS12 AND NOXTLS_CFG_FEATURE_TLS13)
    noxtls_lb_add_suite(unified_loopback_test unified_loopback_test.c
        unified_tls13_negotiation
        unified_downgrade_to_tls12_server
        unified_tls12_client_auto_server
        unified_tls13_fixed_both
        unified_version_mismatch
        unified_mtls_ecdsa_client
        unified_tls13_resumption
        unified_tls12_resumption
        unified_maximum_record_payload
        unified_fragmented_transport
        unified_server_fixed_version
        unified_handshake_reentry_after_want_write
    )
endif()

# NoxTLS <-> OpenSSL interoperability over localhost TCP (applications/tlscurl as the
# NoxTLS client, applications/https_server as the NoxTLS server). Registered only when
# the openssl CLI, Python 3 and both applications are available. The applications are
# added after ut/ by the root CMakeLists, so registration is deferred to the end of
# the top-level directory.
find_program(NOXTLS_OPENSSL_EXECUTABLE openssl)
find_package(Python3 COMPONENTS Interpreter QUIET)
set(NOXTLS_LB_INTEROP_CASES
    client_tls13
    client_tls13_hrr
    client_tls13_chacha20
    client_tls13_aes256
    client_tls12_gcm
    client_tls12_chacha20
    client_tls12_ems_sha384
    server_tls13
    server_tls13_chacha20
    server_tls13_p256
    server_tls13_rsa
    server_tls13_resumption
    server_tls12_rsa
    server_tls12_rsa_chacha20
    server_tls12_session_id_resumption
    server_tls12_ticket_resumption
    server_tls12_ems_sha384
    server_tls12_mtls_rsa_pss_sha384
    server_tls12_mtls_rsa_pkcs1_sha384
    server_tls12_mtls_ecdsa_sha256_prf_sha384
    server_tls12_mtls_no_resumption
    client_tls12_cbc_only_server
    client_tls12_sha1_only_server
    server_tls12_cbc_only_client
    server_tls12_sha1_only_client
    CACHE INTERNAL "openssl_interop.py cases registered as ctests")

# The legacy-policy cases expect a refusal by default and a working handshake when the
# corresponding opt-in is enabled.
set(NOXTLS_LB_INTEROP_FLAGS "")
if(NOXTLS_CFG_TLS12_ENABLE_LEGACY_CIPHER_SUITES)
    list(APPEND NOXTLS_LB_INTEROP_FLAGS --legacy-suites)
endif()
if(NOXTLS_CFG_TLS12_ENABLE_SHA1_SIGNATURES AND NOXTLS_CFG_FEATURE_SHA1)
    list(APPEND NOXTLS_LB_INTEROP_FLAGS --sha1-sigs)
endif()
set(NOXTLS_LB_INTEROP_FLAGS "${NOXTLS_LB_INTEROP_FLAGS}" CACHE INTERNAL "openssl_interop.py build-policy flags")

function(noxtls_lb_register_interop src_dir bin_dir python openssl)
    if(NOT (TARGET tlscurl AND TARGET https_server))
        message(STATUS "OpenSSL interop tests skipped: tlscurl/https_server not built")
        return()
    endif()
    foreach(case_name ${NOXTLS_LB_INTEROP_CASES})
        add_test(NAME interop_${case_name}
                 COMMAND "${python}" "${src_dir}/openssl_interop.py"
                         --openssl "${openssl}"
                         --tlscurl "$<TARGET_FILE:tlscurl>"
                         --https-server "$<TARGET_FILE:https_server>"
                         --pki "${src_dir}/loopback_pki.c"
                         --work-dir "${bin_dir}/interop"
                         --case ${case_name}
                         ${NOXTLS_LB_INTEROP_FLAGS})
        set_tests_properties(interop_${case_name} PROPERTIES TIMEOUT 90 LABELS "openssl_interop")
    endforeach()
endfunction()

if(NOXTLS_OPENSSL_EXECUTABLE AND Python3_Interpreter_FOUND AND BUILD_APPLICATIONS AND
   NOT (CMAKE_VERSION VERSION_LESS 3.19))
    # DEFER evaluates its arguments when the call runs: bake the current values in.
    cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY [[${CMAKE_SOURCE_DIR}]] CALL noxtls_lb_register_interop [[${CMAKE_CURRENT_SOURCE_DIR}]] [[${CMAKE_CURRENT_BINARY_DIR}]] [[${Python3_EXECUTABLE}]] [[${NOXTLS_OPENSSL_EXECUTABLE}]])")
endif()
