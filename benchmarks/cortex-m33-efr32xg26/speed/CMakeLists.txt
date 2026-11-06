# Copyright (c) [2019] - [2026], Argenox Technologies LLC
# All rights reserved.
# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# This file is part of the NoxTLS Library.
#
# Licensed under the GNU General Public License v2.0 or later,
# or alternatively under a commercial license from Argenox Technologies LLC.
#
# See the LICENSE file in the project root for full details.
# CONTACT: info@argenox.com
#
# File:    CMakeLists.txt
# Summary: BRD4120A (EFR32MG26) NoxTLS software versus hardware speed benchmark
#

#
# On-target crypto speed benchmark of NoxTLS on the XG26-RB4120A. A standalone CMake project:
# it pulls in the nox-driver-lib EFR32xG2x platform (start-up, clock, EUSART) and NoxTLS built
# with NOXTLS_CFG_FEATURE_EFR32XG2X_HW_ACCEL=ON, and times every case on the software and on the
# hardware backend in one image (noxtls_efr32_set_enabled() switches the backend at run time).
#
#   cmake -S benchmarks/cortex-m33-efr32xg26/speed -B build/brd4120a_noxtls_speed -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=<nox-driver-lib>/platforms/efr32xg2x/cmake/arm-none-eabi-efr32.cmake \
#         -DNOXDRV_ARM_GNU_ROOT=C:/ARM/arm-gnu-toolchain-14.2.rel1-mingw-w64-x86_64-arm-none-eabi \
#         -DNOXTLS_SPEED_DRIVER_LIB_ROOT=<nox-driver-lib>
#   cmake --build build/brd4120a_noxtls_speed
#
# Outputs brd4120a_noxtls_speed.{elf,hex,bin,map} in the build directory. No vendor SDK, header or
# library is used: the register maps of both the platform and the backend are Argenox definitions.
cmake_minimum_required(VERSION 3.20)
project(brd4120a_noxtls_speed C)

get_filename_component(NOXTLS_SPEED_NOXTLS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(NOXTLS_SPEED_DRIVER_LIB_ROOT "${NOXTLS_SPEED_NOXTLS_ROOT}/../nox-driver-lib" CACHE PATH
    "nox-driver-lib checkout that provides platforms/efr32xg2x (branch feat/spec-efr32xg2x-platform)")
set(NOXTLS_SPEED_OPT_FLAGS "-O2" CACHE STRING "Optimisation flags of the benchmark and of NoxTLS")

if(NOT EXISTS "${NOXTLS_SPEED_DRIVER_LIB_ROOT}/platforms/efr32xg2x/CMakeLists.txt")
  message(FATAL_ERROR "NOXTLS_SPEED_DRIVER_LIB_ROOT='${NOXTLS_SPEED_DRIVER_LIB_ROOT}' has no platforms/efr32xg2x")
endif()

# Part, stack and heap of the platform (software P-256 needs a deep stack; ECC keys use the heap).
set(NOXDRV_EFR32_PART "MG26B410F3200IM68" CACHE STRING "EFR32 part")
set(NOXDRV_EFR32_STACK_SIZE "0x8000" CACHE STRING "Stack size in bytes")
set(NOXDRV_EFR32_HEAP_SIZE "0x20000" CACHE STRING "Heap size in bytes")

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS_RELEASE "${NOXTLS_SPEED_OPT_FLAGS} -g -DNDEBUG")

# NoxTLS: crypto only, with the EFR32 hardware backend.
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
set(NOXTLS_BUILD_SIZE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(NOXTLS_CFG_FEATURE_EFR32XG2X_HW_ACCEL ON CACHE BOOL "" FORCE)
# The crypto-only size profile switches off TLS, DTLS, certificates and the post-quantum algorithms.
include("${NOXTLS_SPEED_NOXTLS_ROOT}/cmake/NoxtlsSizeProfiles.cmake")
noxtls_apply_size_profile("crypto_only")

add_subdirectory("${NOXTLS_SPEED_DRIVER_LIB_ROOT}/platforms/efr32xg2x" platform)
add_subdirectory("${NOXTLS_SPEED_NOXTLS_ROOT}" noxtls)

set(_app brd4120a_noxtls_speed)
add_executable(${_app}
    noxtls_speed_main.c
    noxtls_speed_bench.c
    noxtls_speed_console.c
    noxtls_speed_timer.c
    noxtls_speed_sym.c
    noxtls_speed_pk.c
    noxtls_speed_rng.c
    $<TARGET_OBJECTS:noxdrv_efr32_startup>)
target_include_directories(${_app} PRIVATE "${CMAKE_CURRENT_LIST_DIR}")
# Archives are listed by path inside one link group (the algorithm libraries reference each other).
set(_speed_libs noxtls_pkc noxtls_encryption noxtls_hash noxtls_drbg noxtls_efr32 noxtls_utility noxtls_common)
set(_speed_link_libs "-Wl,--start-group")
foreach(_lib IN LISTS _speed_libs)
  list(APPEND _speed_link_libs "$<TARGET_FILE:${_lib}>")
endforeach()
list(APPEND _speed_link_libs "-Wl,--end-group")
target_link_libraries(${_app} PRIVATE noxdrv_efr32 ${_speed_link_libs})
add_dependencies(${_app} ${_speed_libs})
foreach(_lib IN LISTS _speed_libs)
  target_include_directories(${_app} PRIVATE $<TARGET_PROPERTY:${_lib},INTERFACE_INCLUDE_DIRECTORIES>)
endforeach()
noxdrv_efr32_target_options(${_app})
set_target_properties(${_app} PROPERTIES OUTPUT_NAME ${_app} SUFFIX ".elf")
noxdrv_efr32_link_options(${_app} "$<TARGET_FILE_DIR:${_app}>/${_app}.map")

add_custom_command(TARGET ${_app} POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:${_app}> $<TARGET_FILE_DIR:${_app}>/${_app}.hex
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${_app}> $<TARGET_FILE_DIR:${_app}>/${_app}.bin
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:${_app}>
    COMMENT "Creating hex / bin and printing the size"
    VERBATIM)
