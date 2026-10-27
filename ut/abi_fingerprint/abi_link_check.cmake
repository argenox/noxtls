# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# Compile abi_consumer.c with the library's definitions, changed as CASE says,
# link it against noxtls_common, and check the outcome (cmake -P script).
#
#   CC        C compiler driver (GCC or Clang command line)
#   SOURCE    abi_consumer.c
#   LIBRARY   noxtls_common archive
#   DEFS      File with the library's compile definitions, one per line
#   INCS      File with the include directories, one per line
#   WORK      Scratch directory
#   CASE      match | stale_layout | no_layout | record_size

file(STRINGS "${DEFS}" _defs)
file(STRINGS "${INCS}" _incs)

set(_expect_link TRUE)
set(_args "")
foreach(_def IN LISTS _defs)
  if(_def MATCHES "^NOXTLS_ABI_LAYOUT_ID=")
    if(CASE STREQUAL "stale_layout")
      # Headers from another layout: the id the consumer was built with differs.
      set(_def "NOXTLS_ABI_LAYOUT_ID=12345678")
      set(_expect_link FALSE)
    elseif(CASE STREQUAL "no_layout")
      # A build outside CMake: the knob fingerprint alone, which the library also defines.
      continue()
    endif()
  endif()
  if(CASE STREQUAL "record_size" AND _def MATCHES "^NOXTLS_TLS_MAX_(RECV_)?RECORD_SIZE=")
    continue()
  endif()
  list(APPEND _args "-D${_def}")
endforeach()
if(CASE STREQUAL "record_size")
  # A consumer compiled with another record size than the library.
  list(APPEND _args "-DNOXTLS_TLS_MAX_RECORD_SIZE=777U" "-DNOXTLS_TLS_MAX_RECV_RECORD_SIZE=777U")
  set(_expect_link FALSE)
endif()
foreach(_inc IN LISTS _incs)
  list(APPEND _args "-I${_inc}")
endforeach()

file(MAKE_DIRECTORY "${WORK}")
set(_exe "${WORK}/abi_consumer_${CASE}${CMAKE_EXECUTABLE_SUFFIX}")
file(REMOVE "${_exe}")
execute_process(
  COMMAND "${CC}" ${_args} "${SOURCE}" "${LIBRARY}" -o "${_exe}"
  RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)

if(_expect_link)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "case ${CASE}: expected a link, got ${_rc}:\n${_out}${_err}")
  endif()
  message(STATUS "case ${CASE}: linked")
else()
  if(_rc EQUAL 0)
    message(FATAL_ERROR "case ${CASE}: a mismatched consumer linked")
  endif()
  if(NOT "${_out}${_err}" MATCHES "noxtls_abi_([0-9a-f]+_)?[0-9a-f][0-9a-f][0-9a-f][0-9a-f]")
    message(FATAL_ERROR "case ${CASE}: the link failed without naming the fingerprint:\n${_out}${_err}")
  endif()
  string(REGEX MATCH "noxtls_abi_[0-9a-f_]+" _symbol "${_out}${_err}")
  message(STATUS "case ${CASE}: refused, unresolved ${_symbol}")
endif()
