# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# DTLS 1.3 single-association support (noxtls_tls13.h): own connection ID, newest-record
# check, stateless HelloRetryRequest and second-ClientHello binder check, and the release
# of the handshake state. Registered in the heap and the static memory configurations;
# static builds with GNU ld wrap the C library allocator and assert zero calls.

if(NOT NOXTLS_CFG_FEATURE_DTLS)
    return()
endif()

set(_noxtls_sa_cases
    sa_cid_own_server
    sa_cid_mismatch_dropped
    sa_cid_api_errors
    sa_newest_record
    sa_stateless_hrr_roundtrip
    sa_stateless_hrr_cid
    sa_stateless_hrr_group
    sa_stateless_hrr_errors
    sa_binder_check_negative
    sa_accept_wrong_ch1_hash
    sa_hrr_observer
    sa_cookie_exchange_off
    sa_release_then_traffic
    sa_release_errors
    sa_exporter_vector
    sa_zero_allocation
    sa_ch1_hash_vector
    sa_binder_vectors
    sa_s0_binder_vector
)
noxtls_lb_add_suite(dtls13_single_association_test
    "${CMAKE_CURRENT_SOURCE_DIR}/dtls13_single_association_test.c" ${_noxtls_sa_cases})
set_tests_properties(${_noxtls_sa_cases} PROPERTIES LABELS "single_association")
if(NOXTLS_CONFIG_STATIC_MEMORY AND NOT MSVC AND NOT APPLE)
    target_compile_definitions(dtls13_single_association_test PRIVATE SA_WRAP_HEAP=1)
    target_link_options(dtls13_single_association_test PRIVATE
        "-Wl,--wrap=malloc" "-Wl,--wrap=calloc" "-Wl,--wrap=realloc" "-Wl,--wrap=free")
endif()
