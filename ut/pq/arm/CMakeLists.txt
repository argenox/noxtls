# Bare-metal semihosting test images for NoxTLS: Cortex-M on the QEMU mps2
# machines and RISC-V (RV32 / RV64) on the QEMU "virt" machine.
#
# Standalone project: cross-builds the NoxTLS static libraries with the
# selected features and links one ELF per test suite (PQ KATs plus the
# freestanding classic crypto KATs).  ctest runs every ELF under
# qemu-system-arm / qemu-system-riscv32 / qemu-system-riscv64 through
# CMAKE_CROSSCOMPILING_EMULATOR. The architecture follows the toolchain file
# (cmake/toolchains/arm-none-eabi-cortex-m*.cmake or riscv-none-elf-rv*.cmake).
#
#   cmake -S ut/pq/arm -B build-arm-m4 -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-none-eabi-cortex-m4.cmake \
#         -DCMAKE_BUILD_TYPE=MinSizeRel \
#         -DNOXTLS_CFG_FEATURE_ML_KEM=ON -DNOXTLS_CFG_FEATURE_ML_DSA=ON -DNOXTLS_CFG_FEATURE_FALCON=ON
#   cmake --build build-arm-m4 && ctest --test-dir build-arm-m4 --output-on-failure
#
# scripts/run_arm_tests.sh wraps these steps.

cmake_minimum_required(VERSION 3.13)
project(noxtls_arm_tests C)

get_filename_component(NOXTLS_ARM_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(NOXTLS_ARM_UT_DIR "${NOXTLS_ARM_REPO_ROOT}/ut")
set(NOXTLS_PQ_UT_DIR "${NOXTLS_ARM_UT_DIR}/pq")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv")
    set(_noxtls_target_riscv TRUE)
    set(_noxtls_default_machine "virt")
else()
    set(_noxtls_target_riscv FALSE)
    set(_noxtls_default_machine "mps2-an386")
endif()
set(NOXTLS_ARM_MACHINE "${_noxtls_default_machine}" CACHE STRING
    "QEMU machine: mps2-an386 (M4), mps2-an385 (M3), mps2-an500 (M7), mps2-an505 (M33), virt (RISC-V)")
set(NOXTLS_ARM_STACK_SIZE "0x10000" CACHE STRING "Main stack size of the test images")
set(NOXTLS_ARM_TEST_TIMEOUT "1800" CACHE STRING "Per-test ctest timeout in seconds")
if(_noxtls_target_riscv)
    set(_noxtls_arm_ld "${CMAKE_CURRENT_SOURCE_DIR}/qemu_virt_riscv.ld")
    set(_noxtls_arch_rt "${CMAKE_CURRENT_SOURCE_DIR}/riscv_rt.c")
elseif(NOXTLS_ARM_MACHINE STREQUAL "mps2-an505")
    set(_noxtls_arm_ld "${CMAKE_CURRENT_SOURCE_DIR}/mps2_an505.ld")
    set(_noxtls_arch_rt "${CMAKE_CURRENT_SOURCE_DIR}/arm_rt.c")
else()
    set(_noxtls_arm_ld "${CMAKE_CURRENT_SOURCE_DIR}/mps2_an386.ld")
    set(_noxtls_arch_rt "${CMAKE_CURRENT_SOURCE_DIR}/arm_rt.c")
endif()

# Library configuration: static libraries only, no host tests/applications.
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(BUILD_APPLICATIONS OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_subdirectory("${NOXTLS_ARM_REPO_ROOT}" noxtls)
# The library's NOXTLS_FEATURE_* definitions and include paths are directory
# properties of the NoxTLS root; apply the same ones to the test images.
get_directory_property(_noxtls_root_defs DIRECTORY "${NOXTLS_ARM_REPO_ROOT}" COMPILE_DEFINITIONS)
get_directory_property(_noxtls_root_incs DIRECTORY "${NOXTLS_ARM_REPO_ROOT}" INCLUDE_DIRECTORIES)

# QEMU (PATH, $QEMU / $QEMU_SYSTEM_ARM / $QEMU_SYSTEM_RISCV, or the default
# Windows install location).
if(_noxtls_target_riscv)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_noxtls_qemu_name qemu-system-riscv64)
    else()
        set(_noxtls_qemu_name qemu-system-riscv32)
    endif()
    set(_noxtls_qemu_env QEMU_SYSTEM_RISCV)
    set(_noxtls_qemu_machine_args -M "${NOXTLS_ARM_MACHINE}" -bios none)
else()
    set(_noxtls_qemu_name qemu-system-arm)
    set(_noxtls_qemu_env QEMU_SYSTEM_ARM)
    set(_noxtls_qemu_machine_args -M "${NOXTLS_ARM_MACHINE}")
endif()
set(_noxtls_qemu_hints "")
if(DEFINED ENV{${_noxtls_qemu_env}})
    get_filename_component(_q "$ENV{${_noxtls_qemu_env}}" DIRECTORY)
    list(APPEND _noxtls_qemu_hints "${_q}")
endif()
if(DEFINED ENV{QEMU})
    list(APPEND _noxtls_qemu_hints "$ENV{QEMU}")
endif()
list(APPEND _noxtls_qemu_hints "C:/Program Files/qemu" "/usr/bin" "/usr/local/bin")
find_program(NOXTLS_QEMU_SYSTEM_ARM NAMES ${_noxtls_qemu_name} HINTS ${_noxtls_qemu_hints})
if(NOXTLS_QEMU_SYSTEM_ARM)
    set(_noxtls_arm_emulator "${NOXTLS_QEMU_SYSTEM_ARM}" ${_noxtls_qemu_machine_args} -nographic -monitor none
        -serial none -semihosting-config enable=on,target=native -kernel)
    message(STATUS "NoxTLS ARM tests: running under ${NOXTLS_QEMU_SYSTEM_ARM} -M ${NOXTLS_ARM_MACHINE}")
else()
    set(_noxtls_arm_emulator "")
    message(WARNING "${_noxtls_qemu_name} not found: the test images are built but ctest cannot run them")
endif()

enable_testing()

function(noxtls_add_arm_test name)
    cmake_parse_arguments(T "" "" "SOURCES;LIBS;DEFS" ${ARGN})
    add_executable(${name}.elf ${T_SOURCES} "${CMAKE_CURRENT_SOURCE_DIR}/target_rt.c" "${_noxtls_arch_rt}")
    target_include_directories(${name}.elf PRIVATE
        "${NOXTLS_PQ_UT_DIR}" "${NOXTLS_PQ_UT_DIR}/vectors"
        "${NOXTLS_ARM_REPO_ROOT}" "${NOXTLS_ARM_REPO_ROOT}/noxtls-lib" ${_noxtls_root_incs})
    target_compile_definitions(${name}.elf PRIVATE ${_noxtls_root_defs} NOXTLS_PQ_TEST_QUICK=1 NOXTLS_PQ_TEST_ARM=1 ${T_DEFS})
    target_link_libraries(${name}.elf PRIVATE ${T_LIBS} noxtls_drbg noxtls_hash noxtls_sha3 noxtls_common m)
    target_link_options(${name}.elf PRIVATE
        -nostartfiles
        "-L${CMAKE_CURRENT_SOURCE_DIR}"
        "-T${_noxtls_arm_ld}"
        "-Wl,--defsym=PQ_ARM_STACK_SIZE=${NOXTLS_ARM_STACK_SIZE}"
        "-Wl,--wrap=malloc,--wrap=free,--wrap=calloc,--wrap=realloc"
        "-Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/${name}.map")
    set_target_properties(${name}.elf PROPERTIES CROSSCOMPILING_EMULATOR "${_noxtls_arm_emulator}")
    add_test(NAME arm_${name} COMMAND ${name}.elf)
    set_tests_properties(arm_${name} PROPERTIES TIMEOUT ${NOXTLS_ARM_TEST_TIMEOUT} LABELS "arm"
        PASS_REGULAR_EXPRESSION "\\[arm\\] exit=0 ")
endfunction()

function(noxtls_add_arm_pq_test name source)
    if(EXISTS "${NOXTLS_PQ_UT_DIR}/${source}")
        noxtls_add_arm_test(${name}
            SOURCES "${NOXTLS_PQ_UT_DIR}/${source}" "${NOXTLS_PQ_UT_DIR}/pq_test_common.c"
            LIBS noxtls_pkc)
    endif()
endfunction()

if(NOXTLS_CFG_FEATURE_ML_KEM)
    noxtls_add_arm_pq_test(pq_mlkem_kat mlkem_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_ML_DSA)
    noxtls_add_arm_pq_test(pq_mldsa_kat mldsa_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_FALCON)
    noxtls_add_arm_pq_test(pq_falcon_kat falcon_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_SLH_DSA)
    noxtls_add_arm_pq_test(pq_slhdsa_kat slhdsa_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_LMS_HSS)
    noxtls_add_arm_pq_test(pq_lms_kat lms_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_LMS_HSS OR NOXTLS_CFG_FEATURE_XMSS)
    noxtls_add_arm_pq_test(pq_hbs_api hbs_api_test.c)
endif()
if(NOXTLS_CFG_FEATURE_XMSS)
    noxtls_add_arm_pq_test(pq_xmss_kat xmss_kat_test.c)
endif()

# Freestanding classic crypto KATs from ut/ (same sources as the host ctest).
# Their features default to ON in the root project, so an unset variable means ON.
option(NOXTLS_ARM_CLASSIC_KATS "Also run the freestanding classic crypto KATs on target" ON)
if(NOXTLS_ARM_CLASSIC_KATS)
    if(NOT DEFINED NOXTLS_CFG_FEATURE_ED25519 OR NOXTLS_CFG_FEATURE_ED25519)
        noxtls_add_arm_test(ed25519_rfc8032 SOURCES "${NOXTLS_ARM_UT_DIR}/ed25519_rfc8032_test.c" LIBS noxtls_pkc)
    endif()
    if(NOT DEFINED NOXTLS_CFG_FEATURE_AES_GCM OR NOXTLS_CFG_FEATURE_AES_GCM)
        noxtls_add_arm_test(aes_gcm_nist SOURCES "${NOXTLS_ARM_UT_DIR}/aes_gcm_nist_test.c" LIBS noxtls_encryption)
    endif()
    if(NOT DEFINED NOXTLS_CFG_FEATURE_AES_CMAC OR NOXTLS_CFG_FEATURE_AES_CMAC)
        noxtls_add_arm_test(cmac_rfc4493 SOURCES "${NOXTLS_ARM_UT_DIR}/cmac_rfc4493_test.c" LIBS noxtls_encryption)
    endif()
endif()
