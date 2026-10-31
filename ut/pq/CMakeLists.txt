# Post-quantum known-answer / round-trip tests (host ctest).
#
# Each suite is built and registered only when its NOXTLS_CFG_FEATURE_* option
# is ON.  The same sources are linked into the Cortex-M semihosting image under
# ut/pq/arm/ (see scripts/run_arm_tests.sh).
#
# Vector headers under ut/pq/vectors/ are generated from official NIST data by
# the scripts in ut/pq/tools/ (provenance is recorded in each header).

set(NOXTLS_PQ_UT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

function(noxtls_add_pq_test name source)
    if(NOT EXISTS "${NOXTLS_PQ_UT_DIR}/${source}")
        return()
    endif()
    add_executable(${name}
        "${NOXTLS_PQ_UT_DIR}/${source}"
        "${NOXTLS_PQ_UT_DIR}/pq_test_common.c")
    target_include_directories(${name} PRIVATE
        "${NOXTLS_PQ_UT_DIR}"
        "${NOXTLS_PQ_UT_DIR}/vectors")
    target_link_libraries(${name} PRIVATE
        noxtls_pkc
        noxtls_drbg
        noxtls_hash
        noxtls_sha3
        noxtls_common)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 300 LABELS "pq")
endfunction()

if(NOXTLS_CFG_FEATURE_ML_KEM)
    noxtls_add_pq_test(pq_mlkem_kat mlkem_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_ML_DSA)
    noxtls_add_pq_test(pq_mldsa_kat mldsa_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_FALCON)
    noxtls_add_pq_test(pq_falcon_kat falcon_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_SLH_DSA)
    noxtls_add_pq_test(pq_slhdsa_kat slhdsa_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_LMS_HSS)
    noxtls_add_pq_test(pq_lms_kat lms_kat_test.c)
endif()
if(NOXTLS_CFG_FEATURE_LMS_HSS OR NOXTLS_CFG_FEATURE_XMSS)
    noxtls_add_pq_test(pq_hbs_api hbs_api_test.c)
endif()

# XMSS / XMSS^MT (RFC 8391, SP 800-208).  pq_xmss_kat (~1 min) runs the h/d = 5
# sets and one vector of each SHA-256 XMSS h = 10 set; NOXTLS_PQ_SLOW_TESTS=ON
# adds pq_xmss_kat_slow (label "slow", ~1 h: all h/d <= 10 vectors, the SHA-256
# h = 16 vectors and a full-lifetime traversal run).
option(NOXTLS_PQ_SLOW_TESTS "Register the slow PQ tests (ctest -L slow)" OFF)
if(NOXTLS_CFG_FEATURE_XMSS)
    noxtls_add_pq_test(pq_xmss_kat xmss_kat_test.c)
    set_tests_properties(pq_xmss_kat PROPERTIES TIMEOUT 900)
    if(NOXTLS_PQ_SLOW_TESTS)
        noxtls_add_pq_test(pq_xmss_kat_slow xmss_kat_test.c)
        target_compile_definitions(pq_xmss_kat_slow PRIVATE XMSS_T_SLOW=1)
        set_tests_properties(pq_xmss_kat_slow PROPERTIES TIMEOUT 14400 LABELS "pq;slow")
    endif()
endif()
