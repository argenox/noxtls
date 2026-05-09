add_executable(noxtls_ct_test noxtls_ct_test.c)
target_link_libraries(noxtls_ct_test PRIVATE noxtls_common)

add_test(NAME noxtls_ct_test COMMAND noxtls_ct_test)

add_executable(string_common_test string_common_test.c)
target_link_libraries(string_common_test PRIVATE noxtls_common)

add_test(NAME string_common_test COMMAND string_common_test)
