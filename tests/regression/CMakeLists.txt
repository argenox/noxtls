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

if(NOXTLS_CFG_FEATURE_AES_128 AND NOXTLS_CFG_FEATURE_AES_CCM)
  foreach(_ccm_gate IN ITEMS 0 1)
    set(_ccm_target noxtls_noxv_ccm_gate${_ccm_gate}_test)
    add_executable(${_ccm_target} noxv_ccm_adapter_test.c
      ../../noxtls-lib/encryption/aes/noxtls_aes_accel_noxv_port.c
      ../../noxtls-lib/encryption/aes/noxtls_aes_ccm.c)
    target_link_libraries(${_ccm_target} PRIVATE noxtls_encryption noxtls_common)
    target_compile_definitions(${_ccm_target} PRIVATE
      NOXTLS_NOXV_AES_TIMEOUT_SPINS=8 NOXTLS_NOXV_AES_EXTERNAL_IO=1
      CCM_TEST_GATE_ON=${_ccm_gate})
    set_target_properties(${_ccm_target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
    # Override the linked software reference profile only in this mocked port
    # executable; never enable physical MMIO in the other native regressions.
    if(MSVC)
      target_compile_options(${_ccm_target} PRIVATE
        /UNOXTLS_FEATURE_NOXV_HW_ACCEL /DNOXTLS_FEATURE_NOXV_HW_ACCEL=1
        /UNOXTLS_FEATURE_NOXV_CCM_ACCEL /DNOXTLS_FEATURE_NOXV_CCM_ACCEL=${_ccm_gate})
    else()
      target_compile_options(${_ccm_target} PRIVATE
        -UNOXTLS_FEATURE_NOXV_HW_ACCEL -DNOXTLS_FEATURE_NOXV_HW_ACCEL=1
        -UNOXTLS_FEATURE_NOXV_CCM_ACCEL -DNOXTLS_FEATURE_NOXV_CCM_ACCEL=${_ccm_gate})
    endif()
    add_test(NAME ${_ccm_target} COMMAND ${_ccm_target})
  endforeach()
endif()
