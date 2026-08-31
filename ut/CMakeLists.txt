set(NOXTLS_ROOT_UT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ut")
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

add_test(
    NAME allocator_policy_check
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_allocator_policy.py"
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

endif()

endif()

add_executable(noxtls_ecdh_diagnostic_test
    "${CMAKE_CURRENT_SOURCE_DIR}/ecdh_diagnostic_test.c")
target_link_libraries(noxtls_ecdh_diagnostic_test PRIVATE
    noxtls_common
    noxtls_pkc
    noxtls_tls
)
add_test(NAME noxtls_ecdh_diagnostic_test COMMAND noxtls_ecdh_diagnostic_test)
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

if(NOXTLS_CFG_FEATURE_SLH_DSA AND _noxtls_have_root_ut)
    add_executable(slhdsa_sizes_test "${NOXTLS_ROOT_UT_DIR}/pkc/test_slhdsa_sizes.c")
    target_link_libraries(slhdsa_sizes_test PRIVATE noxtls_common noxtls_pkc)
    add_test(NAME slhdsa_sizes_test COMMAND slhdsa_sizes_test)
endif()
