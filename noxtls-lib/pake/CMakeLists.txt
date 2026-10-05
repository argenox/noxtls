# Password-authenticated key exchange library: SPAKE2+ (RFC 9383) with an
# optional Matter (draft-bar-cfrg-spake2plus-01) profile.

set(NOXTLS_PAKE_SOURCES
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

target_link_libraries(noxtls_pake PUBLIC
    noxtls_kdf
    noxtls_mac
    noxtls_pkc
    noxtls_drbg
    noxtls_hash
    noxtls_common
)
