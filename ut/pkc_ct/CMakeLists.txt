# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# Constant-time bignum / RSA / DSA regression tests (added from ut/CMakeLists.txt when
# noxtls_pkc exists): noxtls_bn_mod_ct, the Fermat inverse, exponent-length independence of
# the secret-exponent path, RSA public-key validation, RSA key length and constant-time
# PKCS#1 v1.5 unpadding. Features that are compiled out are skipped inside the source.

add_executable(bignum_ct_audit_test bignum_ct_audit_test.c)
target_link_libraries(bignum_ct_audit_test PRIVATE noxtls_pkc noxtls_hash noxtls_common)
add_test(NAME bignum_ct_audit_test COMMAND bignum_ct_audit_test)
