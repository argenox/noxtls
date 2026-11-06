# Microchip ATECC608B / ATECC608C secure element provider for NoxTLS
# (NOXTLS_CFG_FEATURE_ATECC608, default OFF).
#
#   noxtls_atecc608                       provider: opaque ECDSA P-256 keys, secure element ECDHE
#   NOXTLS_CFG_FEATURE_ATECC608_ENTROPY   chip RNG as DRBG entropy (port compiled into noxtls_drbg)
#   NOXTLS_CFG_ATECC608_NOXSENSOR         also build the NoxSensor driver binding; set
#                                         NOXTLS_ATECC608_NOXSENSOR_INCLUDE_DIR to the NoxSensor component root.
include("${CMAKE_CURRENT_LIST_DIR}/../../../../cmake/nox_noxtls_sections.cmake")
set(NOXTLS_ATECC608_SOURCES noxtls_atecc608.c)
if(NOXTLS_CFG_ATECC608_NOXSENSOR)
  list(APPEND NOXTLS_ATECC608_SOURCES noxtls_atecc608_noxsensor.c)
endif()
add_library(noxtls_atecc608 STATIC ${NOXTLS_ATECC608_SOURCES})
nox_noxtls_enable_sections("noxtls_atecc608")
target_include_directories(noxtls_atecc608 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${NOXTLS_LIB_ROOT})
target_link_libraries(noxtls_atecc608 PUBLIC noxtls_pkc noxtls_hash noxtls_common)
if(NOXTLS_CFG_ATECC608_NOXSENSOR)
  if(NOT NOXTLS_ATECC608_NOXSENSOR_INCLUDE_DIR)
    message(FATAL_ERROR "NOXTLS_CFG_ATECC608_NOXSENSOR requires NOXTLS_ATECC608_NOXSENSOR_INCLUDE_DIR (the NoxSensor component root)")
  endif()
  target_compile_definitions(noxtls_atecc608 PUBLIC NOXTLS_ATECC608_NOXSENSOR=1)
  target_include_directories(noxtls_atecc608 PUBLIC ${NOXTLS_ATECC608_NOXSENSOR_INCLUDE_DIR})
endif()
