# PBKDF2 (RFC 8018), SPAKE2+ (RFC 9383 and Matter draft-01 profile) and Matter
# PASE UTNox tests. Added from ut/CMakeLists.txt when NOXTLS_BUILD_PAKE_TESTS
# is ON; links the library targets of the enclosing NoxTLS build, so enable the
# matching NOXTLS_CFG_FEATURE_* knobs (PBKDF2, SPAKE2P, SPAKE2P_RFC9383,
# SPAKE2P_MATTER, MATTER_PASE, ECJPAKE, DTLS_ECJPAKE). Vectors:
# spake2p_test_vectors.h / ecjpake_test_vectors.h, generated and checked by
# spake2p_reference.py / ecjpake_reference.py.

if(NOT TARGET utnox)
    set(NOXTLS_ERROR_UTNOX "" CACHE PATH "Existing UTNox source checkout")
    if(NOT EXISTS "${NOXTLS_ERROR_UTNOX}/CMakeLists.txt")
        message(FATAL_ERROR "Set NOXTLS_ERROR_UTNOX to an existing UTNox checkout")
    endif()
    add_subdirectory("${NOXTLS_ERROR_UTNOX}" utnox)
endif()

function(noxtls_pake_add_ut target source)
    add_executable(${target} ${source})
    if(MSVC)
        set_source_files_properties(${source} PROPERTIES LANGUAGE CXX)
    endif()
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${NOXTLS_LIB_ROOT}
    )
    target_link_libraries(${target} PRIVATE utnox ${ARGN})
    set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
    add_test(NAME ${target} COMMAND ${target} RUN_ALL)
endfunction()

if(NOXTLS_CFG_FEATURE_PBKDF2)
    noxtls_pake_add_ut(noxtls_pbkdf_ut pbkdf_ut.c noxtls_kdf noxtls_mac noxtls_hash noxtls_common)
endif()

if(NOXTLS_CFG_FEATURE_SPAKE2P)
    noxtls_pake_add_ut(noxtls_spake2p_ut spake2p_ut.c noxtls_pake)
    if(NOXTLS_CFG_FEATURE_CC13XX_P256_ACCEL)
        noxtls_pake_add_ut(noxtls_spake2p_accel_ut spake2p_accel_ut.c noxtls_pake)
    endif()
endif()

if(NOXTLS_CFG_FEATURE_MATTER_PASE)
    noxtls_pake_add_ut(noxtls_matter_pase_ut matter_pase_ut.c noxtls_pake)
endif()

if(NOXTLS_CFG_FEATURE_ECJPAKE)
    noxtls_pake_add_ut(noxtls_ecjpake_ut ecjpake_ut.c noxtls_pake)
endif()

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    if(NOXTLS_CFG_FEATURE_SPAKE2P)
        add_test(NAME noxtls_spake2p_reference_vectors
            COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/spake2p_reference.py" --check)
    endif()
    if(NOXTLS_CFG_FEATURE_ECJPAKE)
        add_test(NAME noxtls_ecjpake_reference_vectors
            COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/ecjpake_reference.py" --check)
    endif()
endif()
