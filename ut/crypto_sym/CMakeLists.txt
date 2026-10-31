# ut/crypto_sym: plain-C regression tests for the symmetric crypto public APIs
# (digests, HMAC/HKDF/PBKDF2, TLS PRFs, AES modes, AEADs, CTR_DRBG,
# ARIA/Camellia, zeroization promises). One executable per area so a failure
# in one area never hides another. Expected values come from the generated
# crypto_sym_*_vectors.h headers (see gen_crypto_sym_vectors.py).
#
# Some sources are built twice with -DCRYPTO_SYM_PART=<n> to split checks that
# fail on the base library (in-place block-mode decryption, protocol-maximum
# TLS 1.3 HkdfLabel) into their own executables, so the main executables stay
# green and keep working as a refactoring safety net.
#
# Every test also builds with reduced feature sets: sections are guarded in C
# by the NOXTLS_FEATURE_* defines and here by the NOXTLS_CFG_FEATURE_* options
# and by the existence of the library targets.

set(_cs_dir "${CMAKE_CURRENT_SOURCE_DIR}")

# crypto_sym_add_test(<test name> <source base name> <part> <libs...>)
function(crypto_sym_add_test name source part)
    add_executable(${name} "${_cs_dir}/${source}.c")
    target_include_directories(${name} PRIVATE
        "${_cs_dir}"
        "${CMAKE_CURRENT_SOURCE_DIR}/../.."
        "${CMAKE_CURRENT_SOURCE_DIR}/../../noxtls-lib"
    )
    target_compile_definitions(${name} PRIVATE CRYPTO_SYM_PART=${part})
    target_link_libraries(${name} PRIVATE ${ARGN} noxtls_common)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${name} PRIVATE -Wall -Wextra)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "crypto_sym" TIMEOUT 60)
endfunction()

if(TARGET noxtls_hash)
    crypto_sym_add_test(crypto_sym_hash_test crypto_sym_hash_test 0 noxtls_hash)
endif()

if(TARGET noxtls_kdf AND TARGET noxtls_mac)
    crypto_sym_add_test(crypto_sym_hmac_kdf_test crypto_sym_hmac_kdf_test 0 noxtls_kdf noxtls_mac noxtls_hash)
endif()

if(TARGET noxtls_tls AND TARGET noxtls_kdf)
    crypto_sym_add_test(crypto_sym_tls_kdf_test crypto_sym_tls_kdf_test 0
        noxtls_tls noxtls_kdf noxtls_mac noxtls_hash)
    # Label and context both at the RFC 8446 maximum (514-byte HkdfLabel).
    crypto_sym_add_test(crypto_sym_tls13_label_limits_test crypto_sym_tls_kdf_test 1
        noxtls_tls noxtls_kdf noxtls_mac noxtls_hash)
endif()

if(TARGET noxtls_encryption AND NOXTLS_CFG_FEATURE_AES)
    crypto_sym_add_test(crypto_sym_aes_test crypto_sym_aes_test 0 noxtls_encryption)
    # ECB/CBC/CTR/CFB/OFB with output == input (one-shot and streaming).
    crypto_sym_add_test(crypto_sym_aes_inplace_test crypto_sym_aes_test 1 noxtls_encryption)
endif()

if(TARGET noxtls_encryption AND TARGET noxtls_mac)
    # AES-GCM, AES-CCM, ChaCha20-Poly1305 vectors, tampering, in-place AEAD.
    crypto_sym_add_test(crypto_sym_aead_test crypto_sym_aead_test 0 noxtls_encryption noxtls_mac noxtls_hash)
    # TLS 1.2 AES-CBC + HMAC record decrypted in place.
    crypto_sym_add_test(crypto_sym_tls_cbc_inplace_test crypto_sym_aead_test 1 noxtls_encryption noxtls_mac noxtls_hash)
endif()

if(TARGET noxtls_drbg AND NOXTLS_CFG_FEATURE_AES)
    crypto_sym_add_test(crypto_sym_drbg_test crypto_sym_drbg_test 0 noxtls_drbg noxtls_encryption)
    # Conformance with NIST SP 800-90A Rev.1 10.2.1 (CTR_DRBG with and without
    # derivation function, prediction resistance): NIST CAVP CTR_DRBG vectors
    # (subset in crypto_sym_drbg_cavp_vectors.h; pass the CAVP .rsp files on the
    # command line to run all of them) and the SP 800-90A limits.
    crypto_sym_add_test(crypto_sym_drbg_sp800_90a_test crypto_sym_drbg_sp800_90a_test 0 noxtls_drbg noxtls_encryption)
    if(TARGET noxtls_pkc)
        # Shared PKC CTR_DRBG: instantiate / periodic reseed / failure handling.
        crypto_sym_add_test(crypto_sym_pkc_rng_test crypto_sym_pkc_rng_test 0 noxtls_pkc noxtls_drbg noxtls_encryption)
    endif()
endif()

if(TARGET noxtls_encryption AND (NOXTLS_CFG_FEATURE_ARIA OR NOXTLS_CFG_FEATURE_CAMELLIA))
    crypto_sym_add_test(crypto_sym_aria_camellia_test crypto_sym_aria_camellia_test 0 noxtls_encryption)
    crypto_sym_add_test(crypto_sym_aria_camellia_inplace_test crypto_sym_aria_camellia_test 1 noxtls_encryption)
endif()

if(TARGET noxtls_mac AND TARGET noxtls_drbg AND TARGET noxtls_encryption)
    set(_cs_wipe_libs noxtls_mac noxtls_hash noxtls_drbg noxtls_encryption)
    if(TARGET noxtls_kdf)
        list(APPEND _cs_wipe_libs noxtls_kdf)
    endif()
    crypto_sym_add_test(crypto_sym_wipe_test crypto_sym_wipe_test 0 ${_cs_wipe_libs})
endif()
