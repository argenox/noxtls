# NoxTLS EFR32xG2x hardware backend: host unit tests (UTNox) against a functional
# RADIOAES / SEMAILBOX / CMU register mock (ut_efr32_mock.c) whose engine model is
# the NoxTLS software implementation (checked against FIPS / NIST vectors by the
# NoxTLS suites and again here through the hardware path).
#
# Standalone (NoxTLS built here with the EFR32xG2x backend and small poll budgets):
#   export PATH=/c/msys64/mingw64/bin:$PATH
#   cmake -S ut/efr32xg2x -B build/efr32_ut -G Ninja -DCMAKE_C_COMPILER=gcc -DENABLE_COVERAGE=ON
#   cmake --build build/efr32_ut && ctest --test-dir build/efr32_ut --output-on-failure
#   gcovr -r . --filter '.*vendor/silabs/efr32xg2x/.*' build/efr32_ut
# UTNOX_DIR selects the UTNox checkout (default: ../../../utnox/utnox, then the
# BlueNox copy in a shared component workspace).
cmake_minimum_required(VERSION 3.16)

if(NOT TARGET noxtls_efr32)
  project(NoxtlsEfr32Ut LANGUAGES C)
  option(ENABLE_COVERAGE "Enable gcov code coverage instrumentation" OFF)
  get_filename_component(_ut_noxtls_root "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
  if(NOT UTNOX_DIR)
    set(UTNOX_DIR "${_ut_noxtls_root}/../utnox/utnox")
    if(NOT EXISTS "${UTNOX_DIR}/CMakeLists.txt")
      set(UTNOX_DIR "${_ut_noxtls_root}/../bluenox-stack/utnox/utnox")
    endif()
  endif()
  if(NOT EXISTS "${UTNOX_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "UTNox not found (set UTNOX_DIR): ${UTNOX_DIR}")
  endif()
  if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -O0")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
  endif()
  set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
  set(NOXTLS_PROFILE "crypto_only" CACHE STRING "" FORCE)
  set(NOXTLS_CFG_FEATURE_EFR32XG2X_HW_ACCEL ON CACHE BOOL "" FORCE)
  # Small budgets so the timeout, retry, chunking and bounce paths run with short vectors.
  set(NOXTLS_EFR32_EXTRA_DEFINITIONS
    NOXTLS_EFR32_CONFIG_SPINS_PER_US=1U NOXTLS_EFR32_CONFIG_SOFTRST_SPINS=2U NOXTLS_EFR32_CONFIG_IDLE_SPINS=4U
    NOXTLS_EFR32_CONFIG_AES_TIMEOUT_US=40U NOXTLS_EFR32_CONFIG_AES_US_PER_KIB=10U NOXTLS_EFR32_CONFIG_SE_ACQUIRE_TRIES=4U
    NOXTLS_EFR32_CONFIG_SE_ACQUIRE_SPINS=4U NOXTLS_EFR32_CONFIG_SE_TX_TIMEOUT_US=30U NOXTLS_EFR32_CONFIG_SE_TIMEOUT_US=60U
    NOXTLS_EFR32_CONFIG_SE_US_PER_KIB=10U NOXTLS_EFR32_CONFIG_SE_PK_TIMEOUT_US=80U NOXTLS_EFR32_CONFIG_BOUNCE_SIZE=128U
    NOXTLS_EFR32_CONFIG_MAX_CHUNK=256U NOXTLS_EFR32_CONFIG_SE_HASH_MAX_BYTES=256U NOXTLS_EFR32_CONFIG_PTMUL_DOUBLE_CHECK=1 NOXTLS_EFR32_CONFIG_AES_MAX_REQUEST=70000U
    CACHE STRING "" FORCE)
  set(UTNOX_BUILD_SUITE_RUNNER OFF CACHE BOOL "Build utnox_suite" FORCE)
  add_subdirectory("${_ut_noxtls_root}" noxtls)
  add_subdirectory("${UTNOX_DIR}" utnox)
  enable_testing()
endif()

add_executable(noxtls_efr32_ut
  ut_efr32_mock.c
  test_efr32_core.c
  test_efr32_aes.c
  test_efr32_se.c
  test_efr32_port.c
  test_efr32_selftest.c
)
target_include_directories(noxtls_efr32_ut PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(noxtls_efr32_ut PRIVATE NOXTLS_FEATURE_EFR32XG2X_HW_ACCEL=1)
target_link_libraries(noxtls_efr32_ut PRIVATE utnox noxtls_pkc noxtls_drbg noxtls_encryption noxtls_hash noxtls_efr32
                      noxtls_common)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(noxtls_efr32_ut PRIVATE -Wall -Wextra)
endif()
add_test(NAME noxtls_efr32_ut COMMAND noxtls_efr32_ut run_all)
