# Copyright (c) 2026 Argenox Technologies LLC. All rights reserved.
# Compiler granularity only. The final application owns linker garbage collection.
include_guard(GLOBAL)

function(nox_noxtls_enable_sections target)
    foreach(_nox_language C CXX)
        if(CMAKE_${_nox_language}_COMPILER_ID MATCHES "^(GNU|Clang)$"
           AND NOT CMAKE_${_nox_language}_SIMULATE_ID STREQUAL "MSVC"
           AND NOT APPLE)
            target_compile_options("${target}" PRIVATE
                "$<$<COMPILE_LANGUAGE:${_nox_language}>:-ffunction-sections>"
                "$<$<COMPILE_LANGUAGE:${_nox_language}>:-fdata-sections>")
        endif()
    endforeach()
endfunction()
