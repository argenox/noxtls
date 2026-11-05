# Source lists of the STM32WB5x hardware backend (AES1 / PKA / RNG / HSEM), for the
# NoxTLS CMake build and for consumers that compile selected NoxTLS sources directly.
#
# Drivers (library noxtls_stm32wb):
#   NOXTLS_STM32WB_DRIVER_SOURCES  register bus, HSEM ownership, AES1 (ECB/CBC/CTR + GCM/CCM), PKA, RNG
# NoxTLS accelerator ports (compiled into the matching algorithm library):
#   NOXTLS_STM32WB_PORT_AES_SOURCES   noxtls_aes_accel.h hooks (needs the AES driver)
#   NOXTLS_STM32WB_PORT_DRBG_SOURCES  DRBG entropy hook (needs the RNG driver)
#   NOXTLS_STM32WB_PORT_ECC_SOURCES   P-256 point multiply + ECDSA sign/verify (needs the PKA driver, PKC DRBG)
#   NOXTLS_STM32WB_PORT_BN_SOURCES    big-number modexp platform hook (needs the PKA driver)
# Every NoxTLS source that calls a hook must be compiled with NOXTLS_FEATURE_STM32WB_HW_ACCEL=1.
set(NOXTLS_STM32WB_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(NOXTLS_STM32WB_DRIVER_SOURCES
  ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_bus.c
  ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_hsem.c
  ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_aes.c
  ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_aead.c
  ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_pka.c
  ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_rng.c)
set(NOXTLS_STM32WB_PORT_AES_SOURCES ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_port_aes.c)
set(NOXTLS_STM32WB_PORT_DRBG_SOURCES ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_port_drbg.c)
set(NOXTLS_STM32WB_PORT_ECC_SOURCES ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_port_ecc.c)
set(NOXTLS_STM32WB_PORT_BN_SOURCES ${NOXTLS_STM32WB_SRC_DIR}/noxtls_stm32wb_port_bn.c)
