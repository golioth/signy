# Copyright (C) 2025 Golioth, Inc.
#
# SPDX-License-Identifier: Apache-2.0

idf_component_register(SRCS "main.c"
                    PRIV_REQUIRES esp_http_client app_update esp_https_ota
                                  esp_netif mbedtls nvs_flash esp_wifi esp_psram
				  EMBED_TXTFILES server.ca.cert.pem
)

