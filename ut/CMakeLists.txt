set(NOXTLS_ROOT_UT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ut"
    CACHE PATH "Path to the shared NoxTLS unit-test sources")
option(NOXTLS_REQUIRE_SHARED_UT_SOURCES
       "Fail configuration when the shared NoxTLS unit-test sources are absent"
       OFF)

if(EXISTS "${NOXTLS_ROOT_UT_DIR}/common/noxtls_ct_test.c")
    set(NOXTLS_SHARED_UT_SOURCES_AVAILABLE ON)
elseif(NOXTLS_REQUIRE_SHARED_UT_SOURCES)
    message(FATAL_ERROR
        "NOXTLS_ROOT_UT_DIR does not contain the shared NoxTLS unit-test sources: "
        "${NOXTLS_ROOT_UT_DIR}")
else()
    set(NOXTLS_SHARED_UT_SOURCES_AVAILABLE OFF)
    message(STATUS
        "NoxTLS shared unit-test sources are unavailable; skipping shared tests "
        "from ${NOXTLS_ROOT_UT_DIR}")
endif()

if(NOXTLS_SHARED_UT_SOURCES_AVAILABLE)
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

# Keep this embedded NoxTLS tree on the repository's newest UTNox checkout.
# The cache variable permits an explicit integrator override.
if(NOT DEFINED NOXTLS_UTNOX_DIR OR "${NOXTLS_UTNOX_DIR}" STREQUAL "")
    set(NOXTLS_UTNOX_DIR
        "${CMAKE_CURRENT_LIST_DIR}/../../../bluenox-stack/utnox/utnox"
        CACHE PATH "Path to the shared UTNox framework")
endif()

if(NOT EXISTS "${NOXTLS_UTNOX_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "NOXTLS_UTNOX_DIR does not contain UTNox: ${NOXTLS_UTNOX_DIR}")
endif()

if(NOT TARGET utnox)
    add_subdirectory("${NOXTLS_UTNOX_DIR}" utnox)
endif()

if(NOXTLS_SHARED_UT_SOURCES_AVAILABLE)
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
endif()

add_test(
    NAME allocator_policy_check
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_allocator_policy.py"
)

if(NOXTLS_SHARED_UT_SOURCES_AVAILABLE)
add_executable(tls_version_policy_test "${NOXTLS_ROOT_UT_DIR}/tls/tls_version_policy_test.c")
target_link_libraries(tls_version_policy_test PRIVATE
    noxtls_common
    noxtls_tls
)
add_test(NAME tls_version_policy_test COMMAND tls_version_policy_test)
endif()

if(NOXTLS_SHARED_UT_SOURCES_AVAILABLE AND NOXTLS_CFG_FEATURE_SLH_DSA)
    add_executable(slhdsa_sizes_test "${NOXTLS_ROOT_UT_DIR}/pkc/test_slhdsa_sizes.c")
    target_link_libraries(slhdsa_sizes_test PRIVATE noxtls_common noxtls_pkc)
    add_test(NAME slhdsa_sizes_test COMMAND slhdsa_sizes_test)
endif()
