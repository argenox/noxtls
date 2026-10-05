# Mutual-TLS certificate policy tests: raw X.509 extension lookup and
# per-context client-certificate verification for TLS 1.2 servers.
add_executable(x509_extension_lookup_test x509_extension_lookup_test.c)
target_include_directories(x509_extension_lookup_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(x509_extension_lookup_test PRIVATE noxtls_common noxtls_cert)
add_test(NAME x509_extension_lookup_test COMMAND x509_extension_lookup_test)
