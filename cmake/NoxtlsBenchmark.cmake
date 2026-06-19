# Optimization level for cross-compiled size benchmarks (all static libs + benchmark ELF).
function(noxtls_apply_bench_opt_level opt_level)
    string(TOUPPER "${opt_level}" _opt)

    if(_opt STREQUAL "O0")
        set(_flag -O0)
    elseif(_opt STREQUAL "O1")
        set(_flag -O1)
    elseif(_opt STREQUAL "O3")
        set(_flag -O3)
    elseif(_opt STREQUAL "OS")
        set(_flag -Os)
    else()
        message(FATAL_ERROR
            "Unsupported NOXTLS_BENCH_OPT_LEVEL='${opt_level}'. Expected O0, O1, O3, or Os.")
    endif()

    # Benchmark builds use Release so dependent static libs pick up the same -O* as the ELF.
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Benchmark build type" FORCE)

    set(_release_c_flags "${_flag} -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "${_release_c_flags}" CACHE STRING "" FORCE)
    set(CMAKE_ASM_FLAGS_RELEASE "${_release_c_flags}" CACHE STRING "" FORCE)

    add_compile_options(${_flag})
    message(STATUS "NoxTLS benchmark optimization: ${_flag} (NOXTLS_BENCH_OPT_LEVEL=${_opt})")
endfunction()
