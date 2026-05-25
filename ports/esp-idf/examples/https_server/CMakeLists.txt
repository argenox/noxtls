# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

include(${CMAKE_CURRENT_LIST_DIR}/../noxtls_example_project.cmake)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(noxtls_https_server)
