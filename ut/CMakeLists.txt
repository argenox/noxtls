set(NOXTLS_ROOT_UT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ut")
# Link-time ABI fingerprint, in the heap and static-memory configurations.
if(TARGET noxtls_tls AND NOT TARGET noxtls_abi_match)
    add_subdirectory(abi_fingerprint)
endif()
if(TARGET noxtls_tls AND NOXTLS_CFG_FEATURE_TLS13 AND NOT TARGET psk_fail_step_test)
    add_subdirectory(psk_fail_step)
endif()
if(NOXTLS_CONFIG_STATIC_MEMORY)
    # Static memory (docs/static-memory.md): the second CTest configuration. Only the
    # TLS 1.3 / DTLS 1.3 handshake suites and the static-memory tests are registered;
    # the heap configuration runs everything else.
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME allocator_policy_check
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_allocator_policy.py")
    if(TARGET noxtls_tls AND TARGET noxtls_cert AND TARGET noxtls_pkc AND
       NOXTLS_CFG_FEATURE_TLS12 AND NOXTLS_CFG_FEATURE_TLS13)
        add_subdirectory(tls_loopback)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/static_memory/CMakeLists.txt")
        add_subdirectory(static_memory)
    endif()
    if(COMMAND noxtls_lb_add_suite)
        add_subdirectory(multi_context)
        add_subdirectory(dtls13_single_association)
    endif()
    return()
endif()
if(TARGET noxtls_tls AND NOT TARGET server_name_ack_test)
    add_subdirectory(server_name_ack)
endif()
option(NOXTLS_BUILD_ACCEL_ERROR_TESTS "Build focused accelerator error-contract UTNox tests" OFF)
if(NOXTLS_BUILD_ACCEL_ERROR_TESTS)
    add_subdirectory(accel_errors_aes)
    add_subdirectory(accel_errors_ecc)
endif()
if(NOT EXISTS "${NOXTLS_ROOT_UT_DIR}")
    # GPL tree may not ship the shared components/ut mirror; fall back to OEM UT.
    set(NOXTLS_ROOT_UT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../noxtls-oem/ut")
endif()
set(_noxtls_have_root_ut FALSE)
if(EXISTS "${NOXTLS_ROOT_UT_DIR}/common/noxtls_ct_test.c")
    set(_noxtls_have_root_ut TRUE)
endif()

if(_noxtls_have_root_ut)
add_executable(noxtls_ct_test "${NOXTLS_ROOT_UT_DIR}/common/noxtls_ct_test.c")
target_link_libraries(noxtls_ct_test PRIVATE noxtls_common)

add_test(NAME noxtls_ct_test COMMAND noxtls_ct_test)

add_executable(string_common_test "${NOXTLS_ROOT_UT_DIR}/common/string_common_test.c")
target_link_libraries(string_common_test PRIVATE noxtls_common)

add_test(NAME string_common_test COMMAND string_common_test)

add_executable(memory_hardening_test "${NOXTLS_ROOT_UT_DIR}/common/memory_hardening_test.c")
target_link_libraries(memory_hardening_test PRIVATE
    noxtls_common
    noxtls_pkc
    noxtls_cert
)

add_test(NAME memory_hardening_test COMMAND memory_hardening_test)

add_executable(pkc_memory_hardening_test "${NOXTLS_ROOT_UT_DIR}/pkc/pkc_memory_hardening_test.c")
target_link_libraries(pkc_memory_hardening_test PRIVATE
    noxtls_common
    noxtls_pkc
)
add_test(NAME pkc_memory_hardening_test COMMAND pkc_memory_hardening_test)

add_executable(cert_memory_hardening_test "${NOXTLS_ROOT_UT_DIR}/cert/cert_memory_hardening_test.c")
target_link_libraries(cert_memory_hardening_test PRIVATE
    noxtls_common
    noxtls_cert
)
if(DEFINED NOXTLS_HAVE_CERT_WRITE AND NOXTLS_HAVE_CERT_WRITE)
    target_compile_definitions(cert_memory_hardening_test PRIVATE NOXTLS_TEST_CERT_WRITE_API=1)
endif()
add_test(NAME cert_memory_hardening_test COMMAND cert_memory_hardening_test)

add_executable(bounded_memory_allocator_test "${NOXTLS_ROOT_UT_DIR}/common/bounded_memory_allocator_test.c")
target_link_libraries(bounded_memory_allocator_test PRIVATE
    noxtls_common
    noxtls_tls
    noxtls_pkc
    noxtls_cert
)
add_test(NAME bounded_memory_allocator_test COMMAND bounded_memory_allocator_test)
endif()

if(NOT TARGET utnox)
    set(_noxtls_utnox_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../utnox/utnox")
    if(EXISTS "${_noxtls_utnox_dir}/CMakeLists.txt")
        add_subdirectory("${_noxtls_utnox_dir}" utnox)
    endif()
endif()

set(_noxtls_have_utnox FALSE)
if(TARGET utnox)
    set(_noxtls_have_utnox TRUE)
endif()

if(_noxtls_have_utnox AND _noxtls_have_root_ut)
set(AES_ACCEL_BACKEND_TEST_SOURCE "${NOXTLS_ROOT_UT_DIR}/encryption/aes_accel_backend_test.c")
add_executable(aes_accel_backend_test "${AES_ACCEL_BACKEND_TEST_SOURCE}")
if(MSVC)
    set_source_files_properties("${AES_ACCEL_BACKEND_TEST_SOURCE}" PROPERTIES LANGUAGE CXX)
endif()
target_link_libraries(aes_accel_backend_test PRIVATE
    utnox
    noxtls_common
    noxtls_encryption
)
target_include_directories(aes_accel_backend_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib/encryption
    ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib/encryption/aes
)
add_test(NAME aes_accel_backend_test COMMAND aes_accel_backend_test)

set(CMAC_STREAMING_TEST_SOURCE "${NOXTLS_ROOT_UT_DIR}/encryption/cmac_streaming_test.c")
add_executable(cmac_streaming_test "${CMAC_STREAMING_TEST_SOURCE}")
if(MSVC)
    set_source_files_properties("${CMAC_STREAMING_TEST_SOURCE}" PROPERTIES LANGUAGE CXX)
endif()
target_link_libraries(cmac_streaming_test PRIVATE
    utnox
    noxtls_common
    noxtls_encryption
)
target_include_directories(cmac_streaming_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib
    ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib/encryption
    ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib/encryption/aes
)
add_test(NAME cmac_streaming_test COMMAND cmac_streaming_test)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(
    NAME allocator_policy_check
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_allocator_policy.py"
)
add_test(NAME allocator_policy_checker_self_test
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_allocator_policy.py" --self-test)
# docs/changelog.json is the source of release notes and quality records
# (pulled into noxtls-oem release packages); keep it valid against its schema.
add_test(
    NAME changelog_check
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_changelog.py"
)
# MISRA C:2025 analysis with CodeNox (several minutes; needs CodeNox and the
# Arm GNU toolchain). Gates on Mandatory/Required findings that are not in the
# committed baseline misra/misra-baseline.json, see misra/README.md.
option(NOXTLS_MISRA_CHECK "Register the CodeNox MISRA C:2025 analysis as a ctest (label: misra)" OFF)
set(NOXTLS_MISRA_BASELINE "${CMAKE_CURRENT_SOURCE_DIR}/../misra/misra-baseline.json" CACHE FILEPATH
    "MISRA findings baseline for the misra_codenox test (empty: gate on every finding)")
if(NOXTLS_MISRA_CHECK)
    set(_misra_args --out-dir "${CMAKE_BINARY_DIR}/misra")
    if(NOXTLS_MISRA_BASELINE)
        list(APPEND _misra_args --baseline "${NOXTLS_MISRA_BASELINE}")
    else()
        list(APPEND _misra_args --no-baseline)
    endif()
    add_test(NAME misra_codenox
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/misra/run_codenox.py" ${_misra_args})
    set_tests_properties(misra_codenox PROPERTIES LABELS "misra" TIMEOUT 3600 SKIP_RETURN_CODE 5)
endif()
# Application configs are generated copies of the top-level config; a stale
# copy builds application code against different struct layouts.
add_test(
    NAME app_config_sync_check
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../tools/app_config_sync/sync_app_configs.py"
            --root "${CMAKE_CURRENT_SOURCE_DIR}/.." --check
)

if(_noxtls_have_root_ut AND EXISTS "${NOXTLS_ROOT_UT_DIR}/tls/tls_version_policy_test.c")
add_executable(tls_version_policy_test "${NOXTLS_ROOT_UT_DIR}/tls/tls_version_policy_test.c")
target_link_libraries(tls_version_policy_test PRIVATE
    noxtls_common
    noxtls_tls
)
add_test(NAME tls_version_policy_test COMMAND tls_version_policy_test)
endif()

if(TARGET noxtls_tls)
add_executable(tls_nonblocking_io_test "${CMAKE_CURRENT_SOURCE_DIR}/tls_nonblocking_io_test.c")
target_link_libraries(tls_nonblocking_io_test PRIVATE noxtls_common noxtls_tls)
add_test(NAME tls_nonblocking_io_test COMMAND tls_nonblocking_io_test)

add_executable(noxtls_ecdh_diagnostic_test
    "${CMAKE_CURRENT_SOURCE_DIR}/ecdh_diagnostic_test.c")
target_link_libraries(noxtls_ecdh_diagnostic_test PRIVATE
    noxtls_common
    noxtls_pkc
    noxtls_tls
)
add_test(NAME noxtls_ecdh_diagnostic_test COMMAND noxtls_ecdh_diagnostic_test)
endif()

if(TARGET noxtls_cert)
    add_subdirectory(mtls_policy)
endif()

# End-to-end TLS loopback, X.509 parsing and RAM budget regression suites. The shared
# fixture drives TLS 1.3, TLS 1.2 and the unified API, so it needs both versions.
if(TARGET noxtls_tls AND TARGET noxtls_cert AND TARGET noxtls_pkc AND
   NOXTLS_CFG_FEATURE_TLS12 AND NOXTLS_CFG_FEATURE_TLS13)
    add_subdirectory(tls_loopback)
    add_subdirectory(x509_parse)
    add_subdirectory(ram_budget)
    add_subdirectory(static_memory)
    add_subdirectory(multi_context)
    add_subdirectory(dtls13_single_association)
endif()

if(NOXTLS_CFG_FEATURE_ED25519)
    add_executable(ed25519_rfc8032_test
        "${CMAKE_CURRENT_SOURCE_DIR}/ed25519_rfc8032_test.c")
    target_link_libraries(ed25519_rfc8032_test PRIVATE
        noxtls_common
        noxtls_pkc
    )
    add_test(NAME ed25519_rfc8032_test COMMAND ed25519_rfc8032_test)
endif()

# PKC correctness + heap-peak gates (ut/pkc_mem); feature gating is inside the sources.
if(TARGET noxtls_pkc)
    add_subdirectory(pkc_mem)
endif()

if(NOXTLS_CFG_FEATURE_AES_GCM)
    add_executable(aes_gcm_nist_test
        "${CMAKE_CURRENT_SOURCE_DIR}/aes_gcm_nist_test.c")
    target_link_libraries(aes_gcm_nist_test PRIVATE
        noxtls_common
        noxtls_encryption
    )
    target_include_directories(aes_gcm_nist_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../noxtls-lib
    )
    add_test(NAME aes_gcm_nist_test COMMAND aes_gcm_nist_test)
endif()

if(TARGET noxtls_encryption AND NOXTLS_CFG_FEATURE_AES_CMAC)
    add_executable(cmac_rfc4493_test cmac_rfc4493_test.c)
    target_link_libraries(cmac_rfc4493_test PRIVATE noxtls_encryption noxtls_common)
    add_test(NAME cmac_rfc4493_test COMMAND cmac_rfc4493_test)
endif()

if(TARGET noxtls_encryption)
    add_subdirectory(crypto_sym)
endif()

if(NOXTLS_CFG_FEATURE_SLH_DSA AND _noxtls_have_root_ut)
    add_executable(slhdsa_sizes_test "${NOXTLS_ROOT_UT_DIR}/pkc/test_slhdsa_sizes.c")
    target_link_libraries(slhdsa_sizes_test PRIVATE noxtls_common noxtls_pkc)
    add_test(NAME slhdsa_sizes_test COMMAND slhdsa_sizes_test)
endif()

option(NOXTLS_BUILD_PAKE_TESTS "Build PBKDF2, SPAKE2+, Matter PASE and EC-JPAKE UTNox tests" OFF)
if(NOXTLS_BUILD_PAKE_TESTS)
    add_subdirectory(pake)
endif()

option(NOXTLS_BUILD_CC13XX_PORT_TESTS "Build injected CC13xx port contract tests" OFF)
if(NOXTLS_BUILD_CC13XX_PORT_TESTS)
    add_subdirectory(cc13xx_aes)
    add_subdirectory(cc13xx_p256)
endif()

# Post-quantum KAT suites (each gated on its NOXTLS_CFG_FEATURE_* option).
add_subdirectory(pq)
