# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# A consumer of the NoxTLS targets whose directory compile definitions disagree
# with the library's (cmake/noxtls_build_config.cmake): it still compiles the
# NoxTLS headers with the library's configuration, which outside_consumer.c
# checks at compile time, and links against the library's ABI fingerprint.

get_directory_property(_library_defs COMPILE_DEFINITIONS)
set(_mismatch "")
set(_expect "")
foreach(_name NOXTLS_FEATURE_DH NOXTLS_FEATURE_ML_KEM NOXTLS_FEATURE_DTLS NOXTLS_FEATURE_X25519
              NOXTLS_CONFIG_STATIC_MEMORY)
  set(_value 0)
  foreach(_definition IN LISTS _library_defs)
    if(_definition MATCHES "^${_name}=(.*)$")
      set(_value "${CMAKE_MATCH_1}")
    endif()
  endforeach()
  if(_value)
    list(APPEND _mismatch "${_name}=0")
  else()
    list(APPEND _mismatch "${_name}=1")
  endif()
  list(APPEND _expect "EXPECT_${_name}=${_value}")
endforeach()
# A static-memory library's profile is not this directory's; a heap library
# gets a profile here it must not see.
list(APPEND _mismatch "NOXTLS_STATIC_MEMORY_PROFILE=\"profiles/static_memory/noxtls_static_profile_node.h\"")
list(FIND _library_defs "NOXTLS_STATIC_MEMORY_PROFILE=\"profiles/static_memory/noxtls_static_profile_node.h\"" _same)
if(NOT _same EQUAL -1)
  list(REMOVE_ITEM _mismatch "NOXTLS_STATIC_MEMORY_PROFILE=\"profiles/static_memory/noxtls_static_profile_node.h\"")
  list(APPEND _mismatch "NOXTLS_STATIC_MEMORY_PROFILE=\"profiles/static_memory/noxtls_static_profile_leader_noxlink.h\"")
endif()
set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS ${_mismatch})

add_executable(noxtls_abi_outside_consumer outside_consumer.c)
# Built under this tree, but treated as a consumer outside it.
set_property(TARGET noxtls_abi_outside_consumer PROPERTY NOXTLS_BUILD_CONFIG_SKIP OFF)
target_compile_definitions(noxtls_abi_outside_consumer PRIVATE ${_expect})
target_link_libraries(noxtls_abi_outside_consumer PRIVATE noxtls_tls)
add_test(NAME noxtls_abi_outside_consumer COMMAND noxtls_abi_outside_consumer)
