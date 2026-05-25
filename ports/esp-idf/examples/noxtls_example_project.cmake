# SPDX-License-Identifier: Apache-2.0
# Shared prelude for NoxTLS ESP-IDF examples. Include before project().

set(NOXTLS_APPLICATION_CONFIG_DIR "${CMAKE_CURRENT_LIST_DIR}/main" CACHE INTERNAL "")

# In-repo layout: examples/<name>/../.. -> ports/esp-idf (single ESP-IDF port, no duplicate tree).
# Standalone copy / release zip: no local port; main/idf_component.yml pulls argenox/noxtls.
get_filename_component(_noxtls_esp_port "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
if(EXISTS "${_noxtls_esp_port}/CMakeLists.txt" AND
   EXISTS "${_noxtls_esp_port}/idf_component.yml" AND
   EXISTS "${_noxtls_esp_port}/src/noxtls_esp_idf_glue.c")
  message(STATUS "NoxTLS example: using in-tree ESP-IDF port at ${_noxtls_esp_port}")
  list(APPEND EXTRA_COMPONENT_DIRS "${_noxtls_esp_port}")
  set(NOXTLS_ESP_EXAMPLE_USES_LOCAL_PORT TRUE CACHE INTERNAL "")
else()
  message(STATUS "NoxTLS example: using Component Registry (argenox/noxtls via main/idf_component.yml)")
  set(NOXTLS_ESP_EXAMPLE_USES_LOCAL_PORT FALSE CACHE INTERNAL "")
endif()
