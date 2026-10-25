# SPDX-License-Identifier: GPL-2.0-or-later OR NoxTLS-Commercial
#
# PKC memory-reduction gates (added from ut/CMakeLists.txt when noxtls_pkc exists):
#   pkc_mem_vectors  correctness: ECDSA/ECDH/RSA/X25519/X448/Ed25519/FFDHE known answers
#                    and negative cases, against the normal library build.
#   pkc_mem_heap     heap-peak / held / leak gate per operation (thresholds in the source;
#                    `pkc_mem_heap --print-thresholds` prints regenerated rows).
# Features and curves that are compiled out are skipped inside the sources.

add_executable(pkc_mem_vectors
    pkc_mem_vectors.c
    pkc_mem_data.c
    pkc_mem_util.c)
target_link_libraries(pkc_mem_vectors PRIVATE noxtls_pkc noxtls_hash noxtls_common)
add_test(NAME pkc_mem_vectors COMMAND pkc_mem_vectors)

# pkc_mem_heap compiles its own copy of noxtls_memory.c with the static LEGACY pool and the
# allocation entry points renamed to pkc_mem_pool_*; pkc_mem_heap.c defines the noxtls_*
# allocation functions as wrappers that track a per-operation high-water mark. The library
# objects are the normal ones (nothing in them depends on NOXTLS_USE_STATIC_BUFFERS), and the
# archived noxtls_memory object of noxtls_common is never pulled in.
get_filename_component(_pkc_mem_pool_src "${CMAKE_CURRENT_SOURCE_DIR}/../../noxtls-lib/common/noxtls_memory.c" ABSOLUTE)
set(_pkc_mem_pool_renames
    noxtls_malloc_at=pkc_mem_pool_malloc_at
    noxtls_malloc=pkc_mem_pool_malloc
    noxtls_calloc_at=pkc_mem_pool_calloc_at
    noxtls_calloc=pkc_mem_pool_calloc
    noxtls_realloc_at=pkc_mem_pool_realloc_at
    noxtls_realloc=pkc_mem_pool_realloc
    noxtls_free=pkc_mem_pool_free)
add_executable(pkc_mem_heap
    pkc_mem_heap.c
    pkc_mem_data.c
    pkc_mem_util.c
    "${_pkc_mem_pool_src}")
target_compile_definitions(pkc_mem_heap PRIVATE
    NOXTLS_USE_STATIC_BUFFERS=1
    NOXTLS_STATIC_ALLOCATOR_MODE=0)
set_source_files_properties("${_pkc_mem_pool_src}" PROPERTIES COMPILE_DEFINITIONS "${_pkc_mem_pool_renames}")
if(NOT MSVC)
    # The static-pool build of noxtls_memory.c has an unused system-heap helper.
    set_source_files_properties("${_pkc_mem_pool_src}" PROPERTIES COMPILE_OPTIONS "-Wno-unused-function")
endif()
target_link_libraries(pkc_mem_heap PRIVATE noxtls_pkc noxtls_hash noxtls_common)
add_test(NAME pkc_mem_heap COMMAND pkc_mem_heap)
