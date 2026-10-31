# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# RAM budget gate: TLS 1.3 / TLS 1.2 handshake + 16 KB exchange heap accounting and
# structure sizes, checked against NOXTLS_RAM_BUDGET_<metric> cache variables.
#
# Defaults are the values measured on the default host configuration (x86_64,
# clang/MinGW, default noxtls_config.h, NOXTLS_TLS_MAX_RECORD_SIZE 16384) plus ~10%.
# Tighten them as RAM reductions land; set a budget to 0 to stop checking it, or
# -DNOXTLS_RAM_BUDGET_ENFORCE=OFF to only report.
#
# The budgets are calibrated for the default feature set only. When the build enables
# non-default features that change the measured structures (PQ algorithms), disables a
# default protocol, or passes -DNOXTLS_* overrides in CMAKE_C_FLAGS (e.g. a different
# NOXTLS_TLS_MAX_RECORD_SIZE), the test runs report-only (every budget 0, the table is
# still printed). -DNOXTLS_RAM_BUDGET_ENFORCE_ANY_CONFIG=ON enforces the default
# budgets anyway (pass per-metric -DNOXTLS_RAM_BUDGET_<metric>=N to re-calibrate).

option(NOXTLS_RAM_BUDGET_ENFORCE "Fail ram_budget when a metric exceeds its budget" ON)
option(NOXTLS_RAM_BUDGET_ENFORCE_ANY_CONFIG
       "Enforce the default-configuration budgets in non-default feature sets too" OFF)

set(_noxtls_ram_budget_nondefault "")
foreach(_opt NOXTLS_CFG_FEATURE_ML_KEM NOXTLS_CFG_FEATURE_ML_DSA NOXTLS_CFG_FEATURE_FALCON
             NOXTLS_CFG_FEATURE_SLH_DSA NOXTLS_CFG_FEATURE_LMS_HSS NOXTLS_CFG_FEATURE_XMSS
             NOXTLS_CFG_FEATURE_TLS10 NOXTLS_CFG_FEATURE_TLS11)
    if(${_opt})
        list(APPEND _noxtls_ram_budget_nondefault "${_opt}=ON")
    endif()
endforeach()
foreach(_opt NOXTLS_CFG_FEATURE_TLS12 NOXTLS_CFG_FEATURE_TLS13 NOXTLS_CFG_FEATURE_DTLS)
    if(DEFINED ${_opt} AND NOT ${_opt})
        list(APPEND _noxtls_ram_budget_nondefault "${_opt}=OFF")
    endif()
endforeach()
if(CMAKE_C_FLAGS MATCHES "-DNOXTLS_")
    list(APPEND _noxtls_ram_budget_nondefault "CMAKE_C_FLAGS -DNOXTLS_* overrides")
endif()
set(_noxtls_ram_budget_enforce ${NOXTLS_RAM_BUDGET_ENFORCE})
if(_noxtls_ram_budget_nondefault AND NOT NOXTLS_RAM_BUDGET_ENFORCE_ANY_CONFIG)
    set(_noxtls_ram_budget_enforce OFF)
    message(STATUS "ram_budget: report-only, budgets are calibrated for the default feature set "
                   "(non-default: ${_noxtls_ram_budget_nondefault})")
endif()

# metric;default-budget pairs (bytes, or allocation counts for *_ALLOCS).
set(_noxtls_ram_budget_defaults
    SIZEOF_TLS13_CONTEXT 3309
    SIZEOF_TLS12_CONTEXT 3028
    SIZEOF_TLS_CONNECTION 3644
    SIZEOF_X509_CERTIFICATE 282
    TRUST_STORE_1_ANCHOR 805
    TLS13_CLIENT_INIT_LIVE 12963
    TLS13_CLIENT_HS_PEAK 35975
    TLS13_CLIENT_HS_ALLOCS 58
    TLS13_CLIENT_STEADY 18719
    TLS13_CLIENT_DATA_PEAK 36760
    TLS13_SERVER_INIT_LIVE 12963
    TLS13_SERVER_HS_PEAK 33806
    TLS13_SERVER_HS_ALLOCS 38
    TLS13_SERVER_STEADY 18125
    TLS13_SERVER_DATA_PEAK 36166
    TLS13_TOTAL_POOL_PEAK 59726
    TLS12_CLIENT_INIT_LIVE 9012
    TLS12_CLIENT_HS_PEAK 32037
    TLS12_CLIENT_HS_ALLOCS 68
    TLS12_CLIENT_STEADY 18772
    TLS12_CLIENT_DATA_PEAK 36821
    TLS12_SERVER_INIT_LIVE 9012
    TLS12_SERVER_HS_PEAK 32359
    TLS12_SERVER_HS_ALLOCS 44
    TLS12_SERVER_STEADY 18178
    TLS12_SERVER_DATA_PEAK 36227
    TLS12_TOTAL_POOL_PEAK 59902
    TLS12_MTLS_CLIENT_HS_PEAK 32743
    TLS12_MTLS_SERVER_HS_PEAK 33874
)

add_executable(ram_budget_test ram_budget_test.c "${NOXTLS_LB_DIR}/lb_alloc.c")
target_link_libraries(ram_budget_test PRIVATE noxtls_lb_fixture)

list(LENGTH _noxtls_ram_budget_defaults _n)
math(EXPR _last "${_n} - 1")
foreach(_i RANGE 0 ${_last} 2)
    math(EXPR _j "${_i} + 1")
    list(GET _noxtls_ram_budget_defaults ${_i} _metric)
    list(GET _noxtls_ram_budget_defaults ${_j} _default)
    # Plain variable unless overridden with -DNOXTLS_RAM_BUDGET_<metric>=N, so updated
    # defaults here take effect in existing build directories.
    if(NOT DEFINED NOXTLS_RAM_BUDGET_${_metric})
        set(NOXTLS_RAM_BUDGET_${_metric} ${_default})
    endif()
    if(_noxtls_ram_budget_enforce)
        target_compile_definitions(ram_budget_test PRIVATE
            NOXTLS_RAM_BUDGET_${_metric}=${NOXTLS_RAM_BUDGET_${_metric}})
    else()
        target_compile_definitions(ram_budget_test PRIVATE NOXTLS_RAM_BUDGET_${_metric}=0)
    endif()
endforeach()

add_test(NAME ram_budget COMMAND ram_budget_test ram_budget)
set_tests_properties(ram_budget PROPERTIES TIMEOUT 120 LABELS "ram_budget")
