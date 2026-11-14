# Source lists of the EFR32xG2x (Silicon Labs Series 2) hardware backend, for the
# NoxTLS CMake build and for consumers that compile selected NoxTLS sources
# directly.
#
# Drivers (one per engine; the core and the engine lock are always needed):
#   NOXTLS_EFR32_CORE_SOURCES   register access seam, DMA windows, engine ownership contract
#   NOXTLS_EFR32_AES_SOURCES    RADIOAES (BA411E) ECB / CBC / CTR / CCM
#   NOXTLS_EFR32_SE_SOURCES     Secure Engine mailbox, TRNG, SHA-2 block compression, P-256 / P-384
#   NOXTLS_EFR32_EXTRA_SOURCES  start-up self-test (known-answer tests through the hardware path)
# NoxTLS accelerator ports (compiled into the matching algorithm library):
#   NOXTLS_EFR32_PORT_AES_SOURCES    noxtls_aes_accel.h hooks
#   NOXTLS_EFR32_PORT_HASH_SOURCES   SHA-256 / SHA-512 block hooks
#   NOXTLS_EFR32_PORT_DRBG_SOURCES   DRBG entropy hook
#   NOXTLS_EFR32_PORT_ECC_SOURCES    point multiply, ECDSA sign / verify, ECDH hooks
# Every NoxTLS source that calls a hook must be compiled with NOXTLS_FEATURE_EFR32XG2X_HW_ACCEL=1.
set(NOXTLS_EFR32_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(NOXTLS_EFR32_CORE_SOURCES
  ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_core.c
  ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_engine_lock.c)
set(NOXTLS_EFR32_AES_SOURCES ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_aes_engine.c)
set(NOXTLS_EFR32_SE_SOURCES
  ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_semailbox.c
  ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_se_trng.c
  ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_se_hash.c
  ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_se_ecc.c)
set(NOXTLS_EFR32_EXTRA_SOURCES ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_selftest.c)
set(NOXTLS_EFR32_DRIVER_SOURCES
  ${NOXTLS_EFR32_CORE_SOURCES} ${NOXTLS_EFR32_AES_SOURCES} ${NOXTLS_EFR32_SE_SOURCES} ${NOXTLS_EFR32_EXTRA_SOURCES})
set(NOXTLS_EFR32_PORT_AES_SOURCES ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_port_aes.c)
set(NOXTLS_EFR32_PORT_HASH_SOURCES ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_port_hash.c)
set(NOXTLS_EFR32_PORT_DRBG_SOURCES ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_port_drbg.c)
set(NOXTLS_EFR32_PORT_ECC_SOURCES ${NOXTLS_EFR32_SRC_DIR}/noxtls_efr32_port_ecc.c)
