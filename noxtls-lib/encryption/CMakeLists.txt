# Encryption library (when NOXTLS_OMIT_UT_SOURCES=ON, exclude unit-test sources for embedded build)
set(ENC_SOURCES
)
if(NOXTLS_CFG_FEATURE_AES)
  list(APPEND ENC_SOURCES aes/noxtls_aes.c)
  if(NOT NOXTLS_OMIT_UT_SOURCES)
    list(APPEND ENC_SOURCES aes/noxtls_aes_debug.c)
  endif()
  if(ESP_PLATFORM)
    set(_noxtls_esp32_aes_accel "${NOXTLS_ESP_IDF_DIR}/target/esp32/noxtls_esp32_aes_accel.c")
    if(EXISTS "${_noxtls_esp32_aes_accel}")
      list(APPEND ENC_SOURCES "${_noxtls_esp32_aes_accel}")
      set(NOXTLS_PORT_AES_ACCEL_ENABLED ON)
    else()
      list(APPEND ENC_SOURCES aes/noxtls_aes_accel_esp.c)
      set(NOXTLS_PORT_AES_ACCEL_ENABLED OFF)
    endif()
  else()
    if(NOXTLS_CFG_FEATURE_STM32_HW_ACCEL)
      list(APPEND ENC_SOURCES
          aes/noxtls_aes_accel_stm32_port.c
          ${NOXTLS_LIB_ROOT}/vendor/st/common/noxtls_stm32_aes_core.c
          ${NOXTLS_LIB_ROOT}/vendor/st/common/noxtls_stm32_gcm_core.c
          ${NOXTLS_LIB_ROOT}/vendor/st/common/noxtls_stm32_accel_dispatch.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32f2/noxtls_stm32f2_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32f4/noxtls_stm32f4_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32f7/noxtls_stm32f7_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32h7/noxtls_stm32h7_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32l4/noxtls_stm32l4_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32u3/noxtls_stm32u3_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32u5/noxtls_stm32u5_accel.c
          ${NOXTLS_LIB_ROOT}/vendor/st/stm32wb/noxtls_stm32wb_accel.c
      )
      set(NOXTLS_PORT_AES_ACCEL_ENABLED ON)
    elseif(NOXTLS_CFG_FEATURE_NRF52_HW_ACCEL)
      list(APPEND ENC_SOURCES aes/noxtls_aes_accel_nrf52_port.c)
      set(NOXTLS_PORT_AES_ACCEL_ENABLED ON)
    else()
      list(APPEND ENC_SOURCES aes/noxtls_aes_accel_esp.c)
      set(NOXTLS_PORT_AES_ACCEL_ENABLED OFF)
    endif()
  endif()
  set(NOXTLS_AES_ACCEL_NI_SOURCE_ENABLED OFF)
  set(NOXTLS_AES_ACCEL_APPLE_SOURCE_ENABLED OFF)
  if(NOXTLS_CFG_FEATURE_AES_ACCEL_NI)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|X86_64|amd64|AMD64)$")
      list(APPEND ENC_SOURCES aes/noxtls_aes_accel_ni.c)
      set(NOXTLS_AES_ACCEL_NI_SOURCE_ENABLED ON)
    endif()
  endif()
  if(NOXTLS_CFG_FEATURE_AES_ACCEL_APPLE)
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
      list(APPEND ENC_SOURCES aes/noxtls_aes_accel_apple.c)
      set(NOXTLS_AES_ACCEL_APPLE_SOURCE_ENABLED ON)
    endif()
  endif()
  if(NOXTLS_CFG_FEATURE_AES_ECB)
    list(APPEND ENC_SOURCES aes/noxtls_aes_ecb.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_CBC)
    list(APPEND ENC_SOURCES aes/noxtls_aes_cbc.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_CTR)
    list(APPEND ENC_SOURCES aes/noxtls_aes_ctr.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_CFB)
    list(APPEND ENC_SOURCES aes/noxtls_aes_cfb.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_OFB)
    list(APPEND ENC_SOURCES aes/noxtls_aes_ofb.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_XTS)
    list(APPEND ENC_SOURCES aes/noxtls_aes_xts.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_GCM)
    list(APPEND ENC_SOURCES aes/noxtls_aes_gcm.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_CCM)
    list(APPEND ENC_SOURCES aes/noxtls_aes_ccm.c)
  endif()
  if(NOXTLS_CFG_FEATURE_AES_CMAC)
    list(APPEND ENC_SOURCES aes/noxtls_aes_cmac.c)
  endif()
endif()
if(NOXTLS_CFG_FEATURE_CAMELLIA)
  list(APPEND ENC_SOURCES
      camellia/noxtls_camellia.c
      camellia/noxtls_camellia_ecb.c
      camellia/noxtls_camellia_cbc.c
      camellia/noxtls_camellia_ctr.c
      camellia/noxtls_camellia_cfb.c
      camellia/noxtls_camellia_ofb.c
  )
endif()
if(NOXTLS_CFG_FEATURE_ARIA)
  list(APPEND ENC_SOURCES
      aria/noxtls_aria.c
      aria/noxtls_aria_ecb.c
      aria/noxtls_aria_cbc.c
      aria/noxtls_aria_ctr.c
      aria/noxtls_aria_cfb.c
      aria/noxtls_aria_ofb.c
  )
endif()
if(NOXTLS_CFG_FEATURE_CHACHA20_POLY1305)
  list(APPEND ENC_SOURCES
      chacha20/noxtls_chacha20.c
      chacha20/noxtls_chacha20_poly1305.c
  )
endif()
if(NOXTLS_CFG_FEATURE_DES)
  list(APPEND ENC_SOURCES
      des/noxtls_des.c
      des/noxtls_des_cbc.c
  )
endif()
if(NOXTLS_CFG_FEATURE_RC4)
  list(APPEND ENC_SOURCES rc4/noxtls_rc4.c)
endif()

if(NOT ENC_SOURCES)
  message(FATAL_ERROR "At least one NOXTLS_FEATURE_* cipher must be enabled.")
endif()
# _ut sources moved to ut/encryption; not built into library
add_library(noxtls_encryption STATIC
    ${ENC_SOURCES}
)

if(NOXTLS_PORT_AES_ACCEL_ENABLED)
  target_compile_definitions(noxtls_encryption PRIVATE NOXTLS_PORT_AES_ACCEL=1)
else()
  target_compile_definitions(noxtls_encryption PRIVATE NOXTLS_PORT_AES_ACCEL=0)
endif()

if(NOXTLS_AES_ACCEL_NI_SOURCE_ENABLED)
  if(NOT MSVC)
    target_compile_options(noxtls_encryption PRIVATE -maes -msse2)
  endif()
endif()

if(NOXTLS_AES_ACCEL_APPLE_SOURCE_ENABLED)
  if(APPLE)
    target_compile_options(noxtls_encryption PRIVATE -march=armv8-a+crypto)
  endif()
endif()

if(MSVC)
    # Disable Spectre mitigation warning C5045 for embedded targets.
    target_compile_options(noxtls_encryption PRIVATE /wd5045)
endif()

target_include_directories(noxtls_encryption PUBLIC
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/common
    ${NOXTLS_LIB_ROOT}/encryption
    ${NOXTLS_LIB_ROOT}/encryption/aes
    ${NOXTLS_LIB_ROOT}/encryption/camellia
    ${NOXTLS_LIB_ROOT}/encryption/aria
    ${NOXTLS_LIB_ROOT}/encryption/chacha20
    ${NOXTLS_LIB_ROOT}/encryption/des
    ${NOXTLS_LIB_ROOT}/encryption/rc4
)

target_link_libraries(noxtls_encryption
    noxtls_common
)
