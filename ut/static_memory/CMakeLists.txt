# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# Static memory tests (NOXTLS_CONFIG_STATIC_MEMORY=ON, docs/static-memory.md).
#
# static_memory_test runs DTLS 1.3 / TLS 1.3 PSK and certificate handshakes in
# caller-provided connection blocks. With GNU ld the C library allocator is wrapped
# and every case asserts zero calls. static_memory_symbols checks with nm that no
# NoxTLS library references malloc/calloc/realloc/free at all.

if(NOT NOXTLS_CONFIG_STATIC_MEMORY)
    # Heap builds: the reference numbers the static footprint report is compared with.
    noxtls_lb_add_suite(heap_footprint_test "${CMAKE_CURRENT_SOURCE_DIR}/heap_footprint_test.c" heap_footprint_report)
    set_tests_properties(heap_footprint_report PROPERTIES LABELS "static_memory")
    return()
endif()

set(_noxtls_static_cases
    static_dtls13_psk
    static_tls13_psk
    static_tls13_cert_ecdsa
    static_tls13_cert_rsa
    static_tls13_mtls_rsa_client
    static_tls13_mtls_ecdsa_client
    static_dtls13_cert_ecdsa
    static_release_timing
    static_application_flight_buffer
    static_pool_exhaustion
    static_peer_chain_too_deep
    static_footprint_report
)
noxtls_lb_add_suite(static_memory_test "${CMAKE_CURRENT_SOURCE_DIR}/static_memory_test.c" ${_noxtls_static_cases})
set_tests_properties(${_noxtls_static_cases} PROPERTIES LABELS "static_memory")
if(NOT MSVC AND NOT APPLE)
    target_compile_definitions(static_memory_test PRIVATE NOXTLS_STATIC_TEST_WRAP_HEAP=1)
    target_link_options(static_memory_test PRIVATE
        "-Wl,--wrap=malloc" "-Wl,--wrap=calloc" "-Wl,--wrap=realloc" "-Wl,--wrap=free")
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(_noxtls_static_libs)
foreach(_lib noxtls_common noxtls_hash noxtls_mac noxtls_kdf noxtls_encryption noxtls_drbg noxtls_pkc
             noxtls_cert noxtls_certificates noxtls_tls noxtls_pake)
    if(TARGET ${_lib})
        list(APPEND _noxtls_static_libs "$<TARGET_FILE:${_lib}>")
    endif()
endforeach()
if(CMAKE_NM)
    add_test(NAME static_memory_symbols
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/check_static_memory_symbols.py"
                --nm "${CMAKE_NM}" ${_noxtls_static_libs})
    set_tests_properties(static_memory_symbols PROPERTIES LABELS "static_memory")
endif()
add_test(NAME static_memory_symbols_self_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/check_static_memory_symbols.py"
            --self-test)
