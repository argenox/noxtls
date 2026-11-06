# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# ecc_hardening_test (added from ut/CMakeLists.txt when noxtls_pkc exists): regular scalar
# multiplication relations on every enabled curve, rejection-sampled scalars (no modulo
# bias), ECDSA round trips, the shared-DRBG lock hook under concurrent threads, and
# EC-JPAKE concurrent scalar draws when the PAKE library is built.

find_package(Threads REQUIRED)

add_executable(ecc_hardening_test ecc_hardening_test.c)
target_link_libraries(ecc_hardening_test PRIVATE noxtls_pkc noxtls_hash noxtls_common Threads::Threads)
if(TARGET noxtls_pake AND NOXTLS_CFG_FEATURE_ECJPAKE)
    target_compile_definitions(ecc_hardening_test PRIVATE ECC_HARDENING_HAVE_ECJPAKE=1)
    target_link_libraries(ecc_hardening_test PRIVATE noxtls_pake noxtls_pkc noxtls_hash noxtls_common)
endif()
add_test(NAME ecc_hardening_test COMMAND ecc_hardening_test)
