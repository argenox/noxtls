# NoxTLS nRF54L CRACEN backend: host unit tests (UTNox) against a functional
# CRACEN / KMU register and engine mock (ut_nrf54_mock.c) whose AES / SHA-2 /
# GCM / CCM oracle (ut_nrf54_ref.c) is itself checked against FIPS vectors.
# One executable covers both chips: every test switches the mock and the
# backend instance between the nRF54LM20 (CRACEN Lite) and nRF54L15 models.
#
# Standalone (NoxTLS built here with the nRF54 backend and small poll budgets):
#   export PATH=/c/msys64/mingw64/bin:$PATH
#   cmake -S components/noxtls/ut/nrf54 -B build/noxtls_nrf54_ut -G Ninja -DCMAKE_C_COMPILER=gcc -DENABLE_COVERAGE=ON
#   cmake --build build/noxtls_nrf54_ut && ctest --test-dir build/noxtls_nrf54_ut --output-on-failure
#   gcovr -r components/noxtls --filter '.*vendor/nordic/nrf54x/.*' build/noxtls_nrf54_ut
# UTNOX_DIR selects the UTNox checkout (default: ../../../utnox/utnox, then the
# BlueNox copy in a NoxADK workspace).
cmake_minimum_required(VERSION 3.16)

if(NOT TARGET noxtls_nrf54)
  project(NoxtlsNrf54Ut LANGUAGES C)
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
  set(NOXTLS_CFG_FEATURE_NRF54_HW_ACCEL ON CACHE BOOL "" FORCE)
  # Small budgets so the timeout, chunking and bounce paths run with short vectors.
  set(NOXTLS_NRF54_EXTRA_DEFINITIONS
    NOXTLS_NRF54_CONFIG_SPINS_PER_US=1U NOXTLS_NRF54_CONFIG_SOFTRST_SPINS=2U NOXTLS_NRF54_CONFIG_IDLE_SPINS=4U
    NOXTLS_NRF54_CONFIG_PKE_READY_SPINS=8U NOXTLS_NRF54_CONFIG_KMU_SPINS=8U NOXTLS_NRF54_CONFIG_CM_TIMEOUT_US=40U
    NOXTLS_NRF54_CONFIG_CM_US_PER_KIB=10U NOXTLS_NRF54_CONFIG_PKE_TIMEOUT_US=200U NOXTLS_NRF54_CONFIG_RNG_TIMEOUT_US=300U
    NOXTLS_NRF54_CONFIG_RNG_US_PER_FILL=50U NOXTLS_NRF54_CONFIG_WAIT_SLICE_MS=1U NOXTLS_NRF54_CONFIG_WAIT_WAKES_MAX=8U
    NOXTLS_NRF54_CONFIG_BOUNCE_SIZE=128U NOXTLS_NRF54_CONFIG_MAX_CHUNK=256U
    CACHE STRING "" FORCE)
  set(UTNOX_BUILD_SUITE_RUNNER OFF CACHE BOOL "Build utnox_suite" FORCE)
  add_subdirectory("${_ut_noxtls_root}" noxtls)
  add_subdirectory("${UTNOX_DIR}" utnox)
  enable_testing()
endif()

add_executable(noxtls_nrf54_ut
  ut_nrf54_ref.c
  ut_nrf54_mock.c
  test_ut_ref.c
  test_nrf54_core.c
  test_nrf54_hash.c
  test_nrf54_aes.c
  test_nrf54_aead.c
  test_nrf54_rng.c
  test_nrf54_pke.c
  test_nrf54_kmu.c
)
target_include_directories(noxtls_nrf54_ut PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(noxtls_nrf54_ut PRIVATE utnox noxtls_pkc noxtls_drbg noxtls_encryption noxtls_hash noxtls_nrf54
                      noxtls_common)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(noxtls_nrf54_ut PRIVATE -Wall -Wextra)
endif()
add_test(NAME noxtls_nrf54_ut COMMAND noxtls_nrf54_ut run_all)
