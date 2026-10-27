# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# Link-time ABI fingerprint (noxtls-lib/tls/noxtls_abi.h): a consumer built with
# the library's layout links and runs; one built with another layout id or
# another record size fails to link and names noxtls_abi_<digits>; one built
# without the layout id links on the knob fingerprint.

add_executable(noxtls_abi_match abi_consumer.c)
target_link_libraries(noxtls_abi_match PRIVATE noxtls_tls)
add_test(NAME noxtls_abi_match COMMAND noxtls_abi_match)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_CROSSCOMPILING)
  get_directory_property(_defs DIRECTORY "${NOXTLS_PROJECT_ROOT}" COMPILE_DEFINITIONS)
  get_directory_property(_incs DIRECTORY "${NOXTLS_PROJECT_ROOT}" INCLUDE_DIRECTORIES)
  string(REPLACE ";" "\n" _defs_text "${_defs}")
  string(REPLACE ";" "\n" _incs_text "${_incs}")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/abi_defs.txt" "${_defs_text}\n")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/abi_incs.txt" "${_incs_text}\n")
  foreach(_case match stale_layout no_layout record_size)
    add_test(NAME noxtls_abi_link_${_case}
      COMMAND "${CMAKE_COMMAND}"
        "-DCC=${CMAKE_C_COMPILER}"
        "-DSOURCE=${CMAKE_CURRENT_SOURCE_DIR}/abi_consumer.c"
        "-DLIBRARY=$<TARGET_FILE:noxtls_common>"
        "-DDEFS=${CMAKE_CURRENT_BINARY_DIR}/abi_defs.txt"
        "-DINCS=${CMAKE_CURRENT_BINARY_DIR}/abi_incs.txt"
        "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/link_check"
        "-DCASE=${_case}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/abi_link_check.cmake")
  endforeach()
endif()
