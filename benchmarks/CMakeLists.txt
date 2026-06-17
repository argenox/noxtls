set(NOXTLS_BENCH_TARGET "cortex-m4-nrf52840" CACHE STRING "Benchmark target: cortex-m4-nrf52840 or riscv-esp32c6")
set_property(CACHE NOXTLS_BENCH_TARGET PROPERTY STRINGS cortex-m4-nrf52840 riscv-esp32c6)

set(_bench_sources
    common/benchmark_entry.c
    common/runtime_shim.c
)

set(_bench_linker_script "")
string(TOLOWER "${NOXTLS_BENCH_OPT_LEVEL}" _bench_opt_suffix)
set(_bench_output_name "noxtls_size_${NOXTLS_BENCH_TARGET}_${NOXTLS_SIZE_PROFILE}_${_bench_opt_suffix}")

if(NOXTLS_BENCH_TARGET STREQUAL "cortex-m4-nrf52840")
    list(APPEND _bench_sources
        cortex-m4-nrf52840/startup.c
    )
    set(_bench_linker_script "${CMAKE_CURRENT_SOURCE_DIR}/cortex-m4-nrf52840/linker.ld")
    set(_bench_arch_compile_flags -mcpu=cortex-m4 -mthumb -mfloat-abi=soft)
elseif(NOXTLS_BENCH_TARGET STREQUAL "riscv-esp32c6")
    list(APPEND _bench_sources
        riscv-esp32c6/startup.S
    )
    set(_bench_linker_script "${CMAKE_CURRENT_SOURCE_DIR}/riscv-esp32c6/linker.ld")
    set(_bench_arch_compile_flags -march=rv32imac -mabi=ilp32)
else()
    message(FATAL_ERROR "Unsupported NOXTLS_BENCH_TARGET='${NOXTLS_BENCH_TARGET}'.")
endif()

set(_bench_output_dir "${CMAKE_BINARY_DIR}/benchmarks-artifacts")
file(MAKE_DIRECTORY "${_bench_output_dir}")

add_executable(noxtls_size_benchmark ${_bench_sources})

set_target_properties(noxtls_size_benchmark PROPERTIES
    OUTPUT_NAME "${_bench_output_name}"
    RUNTIME_OUTPUT_DIRECTORY "${_bench_output_dir}"
)

target_compile_options(noxtls_size_benchmark PRIVATE
    ${_bench_arch_compile_flags}
    -ffreestanding
    -fno-builtin
    -ffunction-sections
    -fdata-sections
    -fomit-frame-pointer
)

if(NOXTLS_SIZE_PROFILE STREQUAL "tls12_only")
    target_compile_definitions(noxtls_size_benchmark PRIVATE NOXTLS_BENCH_TLS12_ONLY=1)
elseif(NOXTLS_SIZE_PROFILE STREQUAL "tls13_only")
    target_compile_definitions(noxtls_size_benchmark PRIVATE NOXTLS_BENCH_TLS13_ONLY=1)
elseif(NOXTLS_SIZE_PROFILE STREQUAL "tls12_tls13" OR NOXTLS_SIZE_PROFILE STREQUAL "full_quantum")
    target_compile_definitions(noxtls_size_benchmark PRIVATE NOXTLS_BENCH_TLS12_TLS13=1)
else()
    target_compile_definitions(noxtls_size_benchmark PRIVATE NOXTLS_BENCH_CRYPTO_ONLY=1)
endif()

set(_bench_link_flags
    ${_bench_arch_compile_flags}
    -specs=nosys.specs
    -Wl,--gc-sections
    -Wl,-Map,${_bench_output_dir}/${_bench_output_name}.map
    -Wl,-T,${_bench_linker_script}
    -Wl,--print-memory-usage
)

if(NOXTLS_BENCH_TARGET STREQUAL "riscv-esp32c6")
    list(APPEND _bench_link_flags
        -nostartfiles
        -Wl,--entry=_start
        -Wl,-u,benchmark_entry
    )
endif()

target_link_options(noxtls_size_benchmark PRIVATE ${_bench_link_flags})

set(NOXTLS_SIZE_BENCH_LIBS
    noxtls_common
    noxtls_hash
    noxtls_encryption
    noxtls_drbg
    noxtls_pkc
    noxtls_utility
)

if(TARGET noxtls_mac)
    list(APPEND NOXTLS_SIZE_BENCH_LIBS noxtls_mac)
endif()

if(TARGET noxtls_kdf)
    list(APPEND NOXTLS_SIZE_BENCH_LIBS noxtls_kdf)
endif()

if(TARGET noxtls_certificates)
    list(APPEND NOXTLS_SIZE_BENCH_LIBS noxtls_certificates)
endif()

if(TARGET noxtls_cert)
    list(APPEND NOXTLS_SIZE_BENCH_LIBS noxtls_cert)
endif()

if(TARGET noxtls_tls)
    list(APPEND NOXTLS_SIZE_BENCH_LIBS noxtls_tls)
endif()

target_link_libraries(noxtls_size_benchmark PRIVATE
    -Wl,--whole-archive
    ${NOXTLS_SIZE_BENCH_LIBS}
    -Wl,--no-whole-archive
    -lgcc
)
