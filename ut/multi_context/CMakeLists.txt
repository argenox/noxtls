# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
# Several TLS 1.3 / DTLS 1.3 PSK connections in one process (docs/static-memory.md,
# "Several connections"). Registered in the heap and the static memory configurations.
# Static builds with GNU ld wrap the C library allocator and assert zero calls.

if(NOT NOXTLS_CFG_FEATURE_DTLS)
    return()
endif()

set(_noxtls_mc_cases
    mc_concurrent_server_client
    mc_cross_identity_refused
    mc_interleaved_handshakes
    mc_release_per_context
    mc_shared_handshake_region
    mc_foreign_scope_isolation
    mc_many_psk_clients
    mc_noxlink_frame_records
    mc_leader_mqtt_rsa
    mc_leader_mqtt_ecdsa
    mc_leader_mqtt_rsa_rotated
    mc_leader_mqtt_rsa_max_chain
    mc_leader_topology
    mc_leader_budget_limits
)
noxtls_lb_add_suite(multi_context_test "${CMAKE_CURRENT_SOURCE_DIR}/multi_context_test.c" ${_noxtls_mc_cases})
# Broker and device PKI of the leader cases (gen_leader_pki.py).
target_sources(multi_context_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/leader_pki.c")
target_include_directories(multi_context_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
set_tests_properties(${_noxtls_mc_cases} PROPERTIES LABELS "multi_context")
if(NOXTLS_CONFIG_STATIC_MEMORY AND NOT MSVC AND NOT APPLE)
    target_compile_definitions(multi_context_test PRIVATE MC_WRAP_HEAP=1)
    target_link_options(multi_context_test PRIVATE
        "-Wl,--wrap=malloc" "-Wl,--wrap=calloc" "-Wl,--wrap=realloc" "-Wl,--wrap=free")
endif()
