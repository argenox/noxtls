# Source lists of the ESP32-S31 hardware accelerator ports of NoxTLS.
#
# The ports call the ESP32-S31 drivers of nox-driver-lib (platforms/esp32s31/{sha,aes,pka}); they do not
# duplicate register code. Set NOXTLS_ESP32S31_DRIVER_DIR to the nox-driver-lib checkout (default: the
# sibling component of a NoxADK tree, <noxtls>/../nox-driver-lib) and link the application with the
# nox-driver-lib ESP32-S31 platform.
#   NOXTLS_ESP32S31_PORT_HASH_SOURCES  SHA-256 / SHA-512 block hooks (SHA engine)
#   NOXTLS_ESP32S31_PORT_AES_SOURCES   AES block, ECB / CBC / CTR hooks (AES engine; GCM/CCM stay in software)
#   NOXTLS_ESP32S31_PORT_ECC_SOURCES   P-192/256/384 point multiply, ECDSA sign + verify (ECC / ECDSA engines)
# Every NoxTLS source that calls a hook must be compiled with NOXTLS_FEATURE_ESP32S31_HW_ACCEL=1.
set(NOXTLS_ESP32S31_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}")
if(NOT NOXTLS_ESP32S31_DRIVER_DIR)
  get_filename_component(NOXTLS_ESP32S31_DRIVER_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../../../nox-driver-lib" ABSOLUTE)
endif()
set(NOXTLS_ESP32S31_DRIVER_INCLUDES
  ${NOXTLS_ESP32S31_DRIVER_DIR}/drivers
  ${NOXTLS_ESP32S31_DRIVER_DIR}/drivers/hash
  ${NOXTLS_ESP32S31_DRIVER_DIR}/drivers/aes
  ${NOXTLS_ESP32S31_DRIVER_DIR}/drivers/pka
  ${NOXTLS_ESP32S31_DRIVER_DIR}/platforms/esp32s31/common
  ${NOXTLS_ESP32S31_DRIVER_DIR}/platforms/esp32s31/sha
  ${NOXTLS_ESP32S31_DRIVER_DIR}/platforms/esp32s31/aes
  ${NOXTLS_ESP32S31_DRIVER_DIR}/platforms/esp32s31/pka)
set(NOXTLS_ESP32S31_PORT_HASH_SOURCES ${NOXTLS_ESP32S31_SRC_DIR}/noxtls_esp32s31_port_hash.c)
set(NOXTLS_ESP32S31_PORT_AES_SOURCES ${NOXTLS_ESP32S31_SRC_DIR}/noxtls_esp32s31_port_aes.c)
set(NOXTLS_ESP32S31_PORT_ECC_SOURCES ${NOXTLS_ESP32S31_SRC_DIR}/noxtls_esp32s31_port_ecc.c)
