# Password-authenticated key exchange library: SPAKE2+ (RFC 9383) with an
# optional Matter (draft-bar-cfrg-spake2plus-01) profile and Matter PASE helpers,
# and EC-JPAKE (RFC 8236 / RFC 8235, draft-cragie-tls-ecjpake-01).

set(NOXTLS_PAKE_SOURCES)
if(NOXTLS_CFG_FEATURE_SPAKE2P)
    list(APPEND NOXTLS_PAKE_SOURCES
        noxtls_spake2p.c
        noxtls_spake2p_group.c
        noxtls_spake2p_transcript.c
    )
    if(NOXTLS_CFG_FEATURE_SPAKE2P_RFC9383)
        list(APPEND NOXTLS_PAKE_SOURCES noxtls_spake2p_rfc9383.c)
    endif()
    if(NOXTLS_CFG_FEATURE_SPAKE2P_MATTER)
        list(APPEND NOXTLS_PAKE_SOURCES noxtls_spake2p_matter.c)
    endif()
endif()
if(NOXTLS_CFG_FEATURE_ECJPAKE)
    list(APPEND NOXTLS_PAKE_SOURCES
        noxtls_ecjpake.c
        noxtls_ecjpake_group.c
        noxtls_ecjpake_scalar.c
        noxtls_ecjpake_zkp.c
    )
endif()
if(NOXTLS_CFG_FEATURE_MATTER_PASE)
    list(APPEND NOXTLS_PAKE_SOURCES noxtls_matter_pase.c)
endif()

add_library(noxtls_pake STATIC ${NOXTLS_PAKE_SOURCES})

if(MSVC)
    target_compile_options(noxtls_pake PRIVATE /wd5045)
endif()

get_filename_component(_noxtls_pake_project_root "${NOXTLS_LIB_ROOT}/.." ABSOLUTE)
target_include_directories(noxtls_pake PUBLIC
    ${_noxtls_pake_project_root}
    ${NOXTLS_LIB_ROOT}
    ${NOXTLS_LIB_ROOT}/pake
    ${NOXTLS_LIB_ROOT}/mdigest
)

if(NOXTLS_CFG_FEATURE_SPAKE2P)
    target_link_libraries(noxtls_pake PUBLIC
        noxtls_kdf
        noxtls_mac
    )
endif()
target_link_libraries(noxtls_pake PUBLIC
    noxtls_pkc
    noxtls_drbg
    noxtls_hash
    noxtls_common
)
