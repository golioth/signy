# Copyright (C) 2025 Golioth, Inc.
#
# SPDX-License-Identifier: Apache-2.0

set(signy_root ../../)
set(signy_src ${signy_root}/src)

idf_component_register(SRCS "${signy_src}/signy.c" "${signy_src}/base64.c"
                    PRIV_REQUIRES mbedtls
                    INCLUDE_DIRS "${signy_root}/include")
