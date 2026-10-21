# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
add_executable(x509_chain_memory_test x509_chain_memory_test.c
    "${CMAKE_CURRENT_SOURCE_DIR}/../../noxtls-lib/common/noxtls_memory.c")
target_compile_definitions(x509_chain_memory_test PRIVATE NOXTLS_USE_STATIC_BUFFERS=1
    NOXTLS_STATIC_ALLOCATOR_MODE=0 NOXTLS_TEST_ALLOCATOR_FAULT_INJECTION=1)
target_link_libraries(x509_chain_memory_test PRIVATE noxtls_cert noxtls_common)
target_compile_features(x509_chain_memory_test PRIVATE c_std_11)
add_test(NAME x509_chain_memory_test COMMAND x509_chain_memory_test)
