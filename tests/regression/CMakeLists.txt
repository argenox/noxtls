add_executable(noxtls_ecc_p256_regression
  ecc_p256_regression.c
)

target_link_libraries(noxtls_ecc_p256_regression PRIVATE
  noxtls_pkc
  noxtls_common
)

add_test(NAME noxtls_ecc_p256_regression COMMAND noxtls_ecc_p256_regression)
