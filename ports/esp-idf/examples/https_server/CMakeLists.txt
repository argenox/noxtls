# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

# Project-local noxtls_config.h (main/noxtls_config.h), not the repo-root header.
set(NOXTLS_APPLICATION_CONFIG_DIR "${CMAKE_CURRENT_LIST_DIR}/main" CACHE INTERNAL "")

list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../..")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(noxtls_https_server)
