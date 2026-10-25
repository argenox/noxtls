# Copyright (c) 2026 Argenox Technologies LLC.
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(NoxTLSServerNameAck C)
    set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
    get_filename_component(_root "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
    add_subdirectory("${_root}" noxtls EXCLUDE_FROM_ALL)
    enable_testing()
endif()
add_executable(server_name_ack_test server_name_ack_test.c)
target_link_libraries(server_name_ack_test PRIVATE noxtls_tls)
target_compile_features(server_name_ack_test PRIVATE c_std_11)
add_test(NAME server_name_ack_test COMMAND server_name_ack_test)
# Server Certificate time policy needs the certificate receive path, which a
# PSK-only build (NOXTLS_TLS13_PEER_CERTIFICATES=OFF) does not compile.
if(NOT DEFINED NOXTLS_TLS13_PEER_CERTIFICATES OR NOXTLS_TLS13_PEER_CERTIFICATES)
    add_executable(server_time_policy_test server_time_policy_test.c)
    target_link_libraries(server_time_policy_test PRIVATE noxtls_tls)
    target_compile_features(server_time_policy_test PRIVATE c_std_11)
    add_test(NAME server_time_policy_test COMMAND server_time_policy_test)
endif()
