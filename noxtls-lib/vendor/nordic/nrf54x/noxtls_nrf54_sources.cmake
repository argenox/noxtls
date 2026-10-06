# Source lists of the nRF54L CRACEN backend, for the NoxTLS CMake build and for
# consumers that compile selected NoxTLS sources directly (for example the
# NoxOS application runtime, which only needs SHA-256 / SHA-512 / Ed25519).
#
# Drivers (one per engine; the core is always needed):
#   NOXTLS_NRF54_CORE_SOURCES  CRACEN core: ownership, waits, interrupt, CryptoMaster jobs
#   NOXTLS_NRF54_AES_SOURCES   BA411 AES-ECB/CBC/CTR and AES-GCM/CCM
#   NOXTLS_NRF54_HASH_SOURCES  BA413 SHA-224/256/384/512
#   NOXTLS_NRF54_RNG_SOURCES   TRNG
#   NOXTLS_NRF54_PKE_SOURCES   BA414EP (with the nRF54L15 microcode image)
#   NOXTLS_NRF54_KMU_SOURCES   KMU
# NoxTLS accelerator ports (compiled into the matching algorithm library):
#   NOXTLS_NRF54_PORT_AES_SOURCES      noxtls_aes_accel.h hooks (needs AES driver)
#   NOXTLS_NRF54_PORT_HASH_SOURCES     SHA-256 / SHA-512 block hooks (needs HASH driver)
#   NOXTLS_NRF54_PORT_DRBG_SOURCES     DRBG entropy hook (needs RNG driver)
#   NOXTLS_NRF54_PORT_ECC_SOURCES      P-256 point multiply + ECDSA verify (needs PKE driver, DRBG)
#   NOXTLS_NRF54_PORT_ED25519_SOURCES  Ed25519 verify (needs PKE driver)
# Every NoxTLS source that calls a hook must be compiled with NOXTLS_FEATURE_NRF54_HW_ACCEL=1.
set(NOXTLS_NRF54_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(NOXTLS_NRF54_CORE_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_cracen.c)
set(NOXTLS_NRF54_AES_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_aes.c ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_aead.c)
set(NOXTLS_NRF54_HASH_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_hash.c)
set(NOXTLS_NRF54_RNG_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_rng.c)
set(NOXTLS_NRF54_PKE_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_pke.c ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_ba414ep_ucode.c)
set(NOXTLS_NRF54_KMU_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_kmu.c)
set(NOXTLS_NRF54_DRIVER_SOURCES
  ${NOXTLS_NRF54_CORE_SOURCES} ${NOXTLS_NRF54_AES_SOURCES} ${NOXTLS_NRF54_HASH_SOURCES}
  ${NOXTLS_NRF54_RNG_SOURCES} ${NOXTLS_NRF54_PKE_SOURCES} ${NOXTLS_NRF54_KMU_SOURCES})
set(NOXTLS_NRF54_PORT_AES_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_port_aes.c)
set(NOXTLS_NRF54_PORT_HASH_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_port_hash.c)
set(NOXTLS_NRF54_PORT_DRBG_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_port_drbg.c)
set(NOXTLS_NRF54_PORT_ECC_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_port_ecc.c)
set(NOXTLS_NRF54_PORT_ED25519_SOURCES ${NOXTLS_NRF54_SRC_DIR}/noxtls_nrf54_port_ed25519.c)
