# Installation rules for the NoxTLS SDK (libraries, headers, CLIs, CMake package, pkg-config).
# Included from the top-level CMakeLists.txt after library/application targets are defined.

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Static libraries
# ---------------------------------------------------------------------------
set(_NOXTLS_LIBRARY_TARGETS
  noxtls_common
  noxtls_utility
  noxtls_hash
  noxtls_sha3
  noxtls_mac
  noxtls_kdf
  noxtls_encryption
  noxtls_drbg
  noxtls_pkc
  noxtls_certificates
  noxtls_cert
  noxtls_tls
)

set(_NOXTLS_INSTALL_LIBS)
foreach(_lib IN LISTS _NOXTLS_LIBRARY_TARGETS)
  if(TARGET "${_lib}")
    list(APPEND _NOXTLS_INSTALL_LIBS "${_lib}")
  endif()
endforeach()

if(NOT _NOXTLS_INSTALL_LIBS)
  message(FATAL_ERROR "NoxTLSInstall: no library targets found to install")
endif()

install(TARGETS ${_NOXTLS_INSTALL_LIBS}
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

# ---------------------------------------------------------------------------
# Public headers (layout matches release static-SDK archives)
# ---------------------------------------------------------------------------
file(GLOB _NOXTLS_ROOT_HEADERS "${NOXTLS_PROJECT_ROOT}/noxtls*.h")
install(FILES ${_NOXTLS_ROOT_HEADERS}
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(DIRECTORY "${NOXTLS_PROJECT_ROOT}/noxtls-lib/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/noxtls-lib"
  FILES_MATCHING PATTERN "*.h"
)

install(DIRECTORY "${NOXTLS_PROJECT_ROOT}/utility/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/utility"
  FILES_MATCHING PATTERN "*.h"
)

# ---------------------------------------------------------------------------
# Application CLIs (rename short/generic names to avoid PATH collisions)
# ---------------------------------------------------------------------------
# target_name -> installed OUTPUT_NAME (when different)
set(_NOXTLS_CLI_RENAME_TARGETS
  aes
  base64
  sha
  cert
  prime
  tls_test
  dtls_psk_test
)

foreach(_cli IN LISTS _NOXTLS_CLI_RENAME_TARGETS)
  if(TARGET "${_cli}")
    set_target_properties("${_cli}" PROPERTIES OUTPUT_NAME "noxtls-${_cli}")
  endif()
endforeach()

set(_NOXTLS_CLI_TARGETS
  noxtls
  tlscurl
  certgen
  pkc
  https_client
  https_server
  certificate
  dtls_psk_demo
  aes
  base64
  sha
  cert
  prime
  tls_test
  dtls_psk_test
)

set(_NOXTLS_INSTALL_CLIS)
foreach(_cli IN LISTS _NOXTLS_CLI_TARGETS)
  if(TARGET "${_cli}")
    list(APPEND _NOXTLS_INSTALL_CLIS "${_cli}")
  endif()
endforeach()

if(_NOXTLS_INSTALL_CLIS)
  install(TARGETS ${_NOXTLS_INSTALL_CLIS}
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  )
endif()

# ---------------------------------------------------------------------------
# CMake package config (find_package(NoxTLS))
# ---------------------------------------------------------------------------
set(_NOXTLS_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/NoxTLS")

configure_package_config_file(
  "${NOXTLS_PROJECT_ROOT}/cmake/NoxTLSConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/NoxTLSConfig.cmake"
  INSTALL_DESTINATION "${_NOXTLS_CMAKE_INSTALL_DIR}"
  PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_INCLUDEDIR
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/NoxTLSConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/NoxTLSConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/NoxTLSConfigVersion.cmake"
  DESTINATION "${_NOXTLS_CMAKE_INSTALL_DIR}"
)

# ---------------------------------------------------------------------------
# pkg-config
# ---------------------------------------------------------------------------
set(NOXTLS_PKGCONFIG_LIBS "")
# Link line: dependents first (static archive order).
foreach(_comp IN ITEMS tls cert certificates pkc kdf mac drbg encryption sha3 hash utility common)
  if(TARGET "noxtls_${_comp}")
    string(APPEND NOXTLS_PKGCONFIG_LIBS " -lnoxtls_${_comp}")
  endif()
endforeach()
if(NOT MSVC)
  string(APPEND NOXTLS_PKGCONFIG_LIBS " -lm")
endif()
string(STRIP "${NOXTLS_PKGCONFIG_LIBS}" NOXTLS_PKGCONFIG_LIBS)

configure_file(
  "${NOXTLS_PROJECT_ROOT}/cmake/noxtls.pc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/noxtls.pc"
  @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/noxtls.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
