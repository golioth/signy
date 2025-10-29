/*
 * Copyright (c) 2025 Golioth
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "freertos/FreeRTOS.h"
#include <string.h>
#include <time.h>
#include "esp_log.h"
#include <psa/crypto.h>
#include <signy/signy.h>

#include "device_key_der.inc"
#include "device_cert_der.inc"

static const char *TAG = "signy_basic";

static char signed_url[CONFIG_SIGNY_EXAMPLE_SIGNED_URL_MAX_SIZE];

void app_main(void)
{
    int err;
    psa_status_t status;

    struct timespec ts;

    ts.tv_sec = CONFIG_SIGNY_EXAMPLE_CURRENT_UNIX_TIMESTAMP;
    err = clock_settime(CLOCK_REALTIME, &ts);
    if (err < 0)
    {
        ESP_LOGE(TAG, "Failed to set time");
    }

    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    psa_key_id_t priv_key;

    status = psa_import_key(&attributes, device_key_der, device_key_der_len, &priv_key);
    if (status != PSA_SUCCESS)
    {
        return;
    }

    psa_reset_key_attributes(&attributes);

    err = signy_init(priv_key, device_crt_der, device_crt_der_len);
    if (err != 0)
    {
        return;
    }

    size_t signed_url_len;
    err = signy_sign_url(CONFIG_SIGNY_EXAMPLE_BASE_URL,
                         strlen(CONFIG_SIGNY_EXAMPLE_BASE_URL),
                         signed_url,
                         sizeof(signed_url),
                         &signed_url_len);
    if (err != 0)
    {
        ESP_LOGW(TAG, "error signing URL");
        return;
    }

    ESP_LOGI(TAG, "Signed URL: %s", signed_url);
}
