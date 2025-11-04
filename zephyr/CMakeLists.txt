# Copyright (c) 2025 Golioth, Inc.
#
# SPDX-License-Identifier: Apache-2.0

if(NOT CONFIG_SIGNY)
    return()
endif()

zephyr_include_directories("${ZEPHYR_CURRENT_MODULE_DIR}/include")

zephyr_library()

set(signy_src "${ZEPHYR_CURRENT_MODULE_DIR}/src")

zephyr_library_sources(
    # SDK
    "${signy_src}/base64.c"
    "${signy_src}/signy.c"
)

zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)
zephyr_library_include_directories_ifdef(CONFIG_BUILD_WITH_TFM
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
)
