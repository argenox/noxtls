# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# Link-time ABI fingerprint (noxtls-lib/tls/noxtls_abi.h).
#
# noxtls_abi_layout_hash() hashes the content of every NoxTLS header (and the
# consumer-owned configuration directory and static-memory profile, when set)
# together with the sizes of the public TLS contexts under this directory's
# compile definitions and include directories. The result is
# NOXTLS_ABI_LAYOUT_ID, which the caller hands to the NoxTLS targets and
# their consumers. Any header edit re-runs CMake, so the hash, and with it
# every consumer's compile command, follows the headers.

set(_NOXTLS_ABI_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}")

# Hash the headers and probe the context sizes.
#   out_var  Receives an 8-digit hexadecimal hash.
function(noxtls_abi_layout_hash out_var)
  set(_root "${NOXTLS_PROJECT_ROOT}")
  file(GLOB_RECURSE _headers LIST_DIRECTORIES false
       "${_root}/noxtls-lib/*.h" "${_root}/profiles/*.h")
  file(GLOB _root_headers LIST_DIRECTORIES false "${_root}/*.h")
  list(APPEND _headers ${_root_headers})
  if(NOXTLS_EXTERNAL_CONFIG_INCLUDE_DIR)
    file(GLOB _external LIST_DIRECTORIES false "${NOXTLS_EXTERNAL_CONFIG_INCLUDE_DIR}/*.h")
    list(APPEND _headers ${_external})
  endif()
  list(SORT _headers)
  set(_content "")
  foreach(_header IN LISTS _headers)
    file(SHA256 "${_header}" _one)
    file(RELATIVE_PATH _name "${_root}" "${_header}")
    string(APPEND _content "${_name}=${_one};")
  endforeach()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${_headers})

  get_directory_property(_definitions COMPILE_DEFINITIONS)
  get_directory_property(_includes INCLUDE_DIRECTORIES)
  set(_defines "")
  foreach(_definition IN LISTS _definitions)
    list(APPEND _defines "-D${_definition}")
  endforeach()
  set(_probe_dir "${CMAKE_CURRENT_BINARY_DIR}/noxtls_abi_probe")
  set(_probe_out "${_probe_dir}/noxtls_abi_probe.bin")
  file(REMOVE "${_probe_out}")
  set(_saved_type "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
  try_compile(_probe_ok "${_probe_dir}"
    SOURCES "${_NOXTLS_ABI_CMAKE_DIR}/noxtls_abi_probe.c"
    COMPILE_DEFINITIONS ${_defines}
    CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${_includes}"
    OUTPUT_VARIABLE _probe_log
    COPY_FILE "${_probe_out}")
  set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_saved_type}")
  # A port that generates its configuration header after this point (ESP-IDF on
  # the first configure) cannot compile the probe yet; the header hash and the
  # knobs in noxtls_abi.h still cover it, and the next configure adds the sizes.
  set(_sizes "NOXTLS_ABI_SIZES[unprobed]")
  if(_probe_ok)
    file(STRINGS "${_probe_out}" _records REGEX "NOXTLS_ABI_SIZES\\[[0-9,]+\\]")
    if(_records)
      list(GET _records 0 _record)
      string(REGEX MATCH "NOXTLS_ABI_SIZES\\[[0-9,]+\\]" _sizes "${_record}")
    endif()
  endif()
  if(_sizes STREQUAL "NOXTLS_ABI_SIZES[unprobed]")
    file(WRITE "${_probe_dir}/noxtls_abi_probe.log" "${_probe_log}")
    message(STATUS "NoxTLS ABI size probe unavailable (${_probe_dir}/noxtls_abi_probe.log); "
                   "the layout hash covers the headers only")
  endif()

  string(SHA256 _hash "${_sizes}|${_content}")
  string(SUBSTRING "${_hash}" 0 8 _hash)
  message(STATUS "NoxTLS ABI layout hash ${_hash} (${_sizes})")
  set(${out_var} "${_hash}" PARENT_SCOPE)
endfunction()
