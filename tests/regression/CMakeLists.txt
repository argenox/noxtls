add_executable(noxtls_ecc_p256_regression
  ecc_p256_regression.c
)

target_link_libraries(noxtls_ecc_p256_regression PRIVATE
  noxtls_pkc
  noxtls_common
)

add_test(NAME noxtls_ecc_p256_regression COMMAND noxtls_ecc_p256_regression)

if(NOXTLS_CFG_FEATURE_ECC)
  # Exercise the real NoxV adapter without accessing host physical memory.
  add_executable(noxtls_noxv_ecc_adapter_test
    noxv_ecc_adapter_test.c
    ../../noxtls-lib/pkc/ecc/noxtls_ecc_accel_noxv_port.c)
  target_compile_definitions(noxtls_noxv_ecc_adapter_test PRIVATE
    NOXTLS_NOXV_ECC_P256_TIMEOUT_SPINS=32)
  target_link_libraries(noxtls_noxv_ecc_adapter_test PRIVATE noxtls_pkc noxtls_common)
  add_test(NAME noxtls_noxv_ecc_adapter_test COMMAND noxtls_noxv_ecc_adapter_test)
endif()

if(NOXTLS_CFG_FEATURE_SHA256)
  add_executable(noxtls_noxv_sha256_fallback_regression
    noxv_sha256_fallback_regression.c
    ../../noxtls-lib/mdigest/sha256/noxtls_sha256_accel_noxv_port.c)
  target_compile_definitions(noxtls_noxv_sha256_fallback_regression PRIVATE
    NOXTLS_NOXV_SHA256_TIMEOUT_SPINS=8)
  target_link_libraries(noxtls_noxv_sha256_fallback_regression PRIVATE
    noxtls_hash noxtls_common)
  add_test(NAME noxtls_noxv_sha256_fallback_regression
    COMMAND noxtls_noxv_sha256_fallback_regression)
endif()
