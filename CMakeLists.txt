# Copyright (c) 2025 Golioth, Inc.
#
# SPDX-License-Identifier: Apache-2.0

if(ESP_PLATFORM)
  include (${COMPONENT_DIR}/esp-idf/signy/CMakeLists.txt)
  return()
endif()
