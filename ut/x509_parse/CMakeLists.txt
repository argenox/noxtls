# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# X.509 parse / field / chain / CRL / writer regression tests. Shares the
# loopback fixture (PKI, accounting allocator, test runner) from ut/tls_loopback.

add_executable(x509_parse_test x509_parse_test.c "${NOXTLS_LB_DIR}/lb_alloc.c")
target_link_libraries(x509_parse_test PRIVATE noxtls_lb_fixture noxtls_utility)
if(NOXTLS_CFG_HAVE_CERT_WRITE)
    target_compile_definitions(x509_parse_test PRIVATE NOXTLS_HAVE_CERT_WRITE=1)
endif()

set(_x509_parse_tests
    x509_ec_chain_fields
    x509_pem_matches_der
    x509_rsa_fields
    x509_ed25519_fields
    x509_hostname_rules
    x509_validity
    x509_signature_verify
    x509_public_key_extract_verify
    x509_trust_one_anchor
    x509_trust_three_anchors
    x509_chain_verify_api
    x509_crl_revocation
    x509_borrow_accessors
    x509_san_iterator
    x509_strict_der
    x509_chain_lazy
    x509_private_key_memory
    x509_crl_memory
    x509_spki_pss_detect
    x509_trust_store_memory
    x509_negative_truncated
    x509_negative_bad_lengths
    x509_negative_oversized
    x509_debug_print_smoke
)
if(NOXTLS_CFG_HAVE_CERT_WRITE)
    list(APPEND _x509_parse_tests x509_cert_write_roundtrip x509_cert_write_corpus x509_issuer_name_rfc5280)
endif()
foreach(test_name ${_x509_parse_tests})
    add_test(NAME ${test_name} COMMAND x509_parse_test ${test_name}
             WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(${test_name} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120 LABELS "x509_parse")
endforeach()

# Independent cross-check of the certificate / CSR writers with the openssl CLI.
find_program(NOXTLS_OPENSSL_EXECUTABLE openssl)
if(NOXTLS_OPENSSL_EXECUTABLE AND NOXTLS_CFG_HAVE_CERT_WRITE)
    add_test(NAME x509_write_openssl_crosscheck
             COMMAND "${CMAKE_COMMAND}"
                     "-DTEST_EXE=$<TARGET_FILE:x509_parse_test>"
                     "-DOPENSSL=${NOXTLS_OPENSSL_EXECUTABLE}"
                     "-DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/openssl_crosscheck"
                     -P "${CMAKE_CURRENT_SOURCE_DIR}/openssl_crosscheck.cmake")
    set_tests_properties(x509_write_openssl_crosscheck PROPERTIES TIMEOUT 120 LABELS "x509_parse;openssl")
endif()

# Regression tests for the X.509 hardening of the run-1 security audit (path validation,
# extensions, name constraints, CRL semantics, strict signature DER, ML-DSA, PEM sizing).
add_executable(x509_audit_test x509_audit_test.c "${NOXTLS_LB_DIR}/lb_alloc.c")
target_link_libraries(x509_audit_test PRIVATE noxtls_lb_fixture noxtls_utility)
if(NOXTLS_CFG_HAVE_CERT_WRITE)
    target_compile_definitions(x509_audit_test PRIVATE NOXTLS_HAVE_CERT_WRITE=1)
endif()
set(_x509_audit_tests
    x509_audit_eku_ku_presence
    x509_audit_name_constraints
    x509_audit_path_budget
    x509_audit_anchor_constraints
    x509_audit_ecdsa_sig_strict
    x509_audit_validity_required
    x509_audit_ext_walker
    x509_audit_ip_hostname
    x509_audit_crl_semantics
    x509_audit_pem_buffer_size
)
if(NOXTLS_CFG_FEATURE_ML_DSA AND NOXTLS_CFG_HAVE_CERT_WRITE)
    list(APPEND _x509_audit_tests x509_audit_mldsa_cert_signature)
endif()
foreach(test_name ${_x509_audit_tests})
    add_test(NAME ${test_name} COMMAND x509_audit_test ${test_name}
             WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(${test_name} PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120 LABELS "x509_parse")
endforeach()
