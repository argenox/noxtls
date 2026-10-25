# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# A PSK client facing a certificate-authenticating TLS 1.3 server. Build once
# with the default profile and once with -DNOXTLS_TLS13_PEER_CERTIFICATES=OFF.
if(NOT TARGET noxtls_tls OR NOT TARGET noxtls_cert OR NOT NOXTLS_CFG_FEATURE_TLS13)
    message(FATAL_ERROR "TLS 1.3 peer certificate tests require TLS13 and X.509")
endif()
if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()
add_executable(tls13_peer_cert_ut tls13_peer_cert_ut.c)
target_include_directories(tls13_peer_cert_ut PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../mtls_policy)
target_link_libraries(tls13_peer_cert_ut PRIVATE noxtls_tls noxtls_cert noxtls_pkc noxtls_common utnox)
set_target_properties(tls13_peer_cert_ut PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
add_test(NAME tls13_peer_cert_ut COMMAND tls13_peer_cert_ut RUN_ALL)
