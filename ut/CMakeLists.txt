set(NOXTLS_ROOT_UT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ut")

add_executable(noxtls_ct_test "${NOXTLS_ROOT_UT_DIR}/noxtls_ct_test.c")
target_link_libraries(noxtls_ct_test PRIVATE noxtls_common)

add_test(NAME noxtls_ct_test COMMAND noxtls_ct_test)

add_executable(string_common_test "${NOXTLS_ROOT_UT_DIR}/string_common_test.c")
target_link_libraries(string_common_test PRIVATE noxtls_common)

add_test(NAME string_common_test COMMAND string_common_test)

add_executable(memory_hardening_test "${NOXTLS_ROOT_UT_DIR}/memory_hardening_test.c")
target_link_libraries(memory_hardening_test PRIVATE
    noxtls_common
    noxtls_pkc
    noxtls_cert
)

add_test(NAME memory_hardening_test COMMAND memory_hardening_test)

add_executable(pkc_memory_hardening_test "${NOXTLS_ROOT_UT_DIR}/pkc_memory_hardening_test.c")
target_link_libraries(pkc_memory_hardening_test PRIVATE
    noxtls_common
    noxtls_pkc
)
add_test(NAME pkc_memory_hardening_test COMMAND pkc_memory_hardening_test)

add_executable(cert_memory_hardening_test "${NOXTLS_ROOT_UT_DIR}/cert_memory_hardening_test.c")
target_link_libraries(cert_memory_hardening_test PRIVATE
    noxtls_common
    noxtls_cert
)
if(DEFINED NOXTLS_HAVE_CERT_WRITE AND NOXTLS_HAVE_CERT_WRITE)
    target_compile_definitions(cert_memory_hardening_test PRIVATE NOXTLS_TEST_CERT_WRITE_API=1)
endif()
add_test(NAME cert_memory_hardening_test COMMAND cert_memory_hardening_test)

add_executable(bounded_memory_allocator_test "${NOXTLS_ROOT_UT_DIR}/bounded_memory_allocator_test.c")
target_link_libraries(bounded_memory_allocator_test PRIVATE
    noxtls_common
    noxtls_tls
    noxtls_pkc
    noxtls_cert
)
add_test(NAME bounded_memory_allocator_test COMMAND bounded_memory_allocator_test)

add_executable(aes_accel_backend_test "${NOXTLS_ROOT_UT_DIR}/aes_accel_backend_test.c")
target_link_libraries(aes_accel_backend_test PRIVATE
    noxtls_common
    noxtls_encryption
)
add_test(NAME aes_accel_backend_test COMMAND aes_accel_backend_test)

add_test(
    NAME allocator_policy_check
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/check_allocator_policy.py"
)

add_executable(tls_version_policy_test "${NOXTLS_ROOT_UT_DIR}/tls_version_policy_test.c")
target_link_libraries(tls_version_policy_test PRIVATE
    noxtls_common
    noxtls_tls
)
add_test(NAME tls_version_policy_test COMMAND tls_version_policy_test)
