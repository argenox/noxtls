# ut/sym_hardening: regression tests for the symmetric-cipher and digest
# side-channel and memory-hygiene fixes (constant-time AES core, Apple/AES-NI
# backend correctness, length encodings, CCM length limits, context and stack
# wipes). Plain C99 programs using ../crypto_sym/crypto_sym_test_util.h.

set(_sh_dir "${CMAKE_CURRENT_SOURCE_DIR}")

# sym_hardening_add_test(<name> <libs...>)
function(sym_hardening_add_test name)
    add_executable(${name} "${_sh_dir}/${name}.c")
    target_include_directories(${name} PRIVATE
        "${_sh_dir}"
        "${_sh_dir}/../crypto_sym"
        "${_sh_dir}/../.."
        "${_sh_dir}/../../noxtls-lib"
    )
    target_link_libraries(${name} PRIVATE ${ARGN} noxtls_common)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "sym_hardening" TIMEOUT 120)
endfunction()

if(TARGET noxtls_encryption AND NOXTLS_CFG_FEATURE_AES)
    sym_hardening_add_test(sym_aes_ct_test noxtls_encryption)
endif()

if(TARGET noxtls_hash)
    set(_sh_hygiene_libs noxtls_hash)
    if(TARGET noxtls_mac)
        list(APPEND _sh_hygiene_libs noxtls_mac)
    endif()
    if(TARGET noxtls_encryption)
        list(APPEND _sh_hygiene_libs noxtls_encryption)
    endif()
    list(APPEND _sh_hygiene_libs noxtls_hash)
    sym_hardening_add_test(sym_hygiene_test ${_sh_hygiene_libs})
endif()

if(TARGET noxtls_encryption AND NOXTLS_CFG_FEATURE_CHACHA20_POLY1305)
    sym_hardening_add_test(sym_poly1305_splitmul_test noxtls_encryption)
    target_include_directories(sym_poly1305_splitmul_test PRIVATE "${_sh_dir}/../../noxtls-lib/common")
endif()

if(TARGET noxtls_hash AND NOXTLS_CFG_FEATURE_SHA256)
    sym_hardening_add_test(sym_noxv_sha256_release_test noxtls_hash)
    target_include_directories(sym_noxv_sha256_release_test PRIVATE
        "${_sh_dir}/../../noxtls-lib/mdigest"
        "${_sh_dir}/../../noxtls-lib/mdigest/sha256")
endif()

if(TARGET noxtls_encryption)
    sym_hardening_add_test(sym_legacy_kat_test noxtls_encryption)
endif()
