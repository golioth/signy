/*
 * Copyright (c) 2025 Golioth
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "esp_heap_caps.h"
#include "esp_log_level.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_log.h"
#include <time.h>
#include "esp_log.h"
#include <psa/crypto.h>
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include <signy/signy.h>

#include "device_key_bin.inc"
#include "device_cert_der.inc"

static const char *TAG = "signy_ota";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define WIFI_MAX_RETRIES 5

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;
const char *_ssid;
const char *_password;

extern const uint8_t server_cert_pem_start[] asm("_binary_server_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_server_ca_cert_pem_end");

static char signed_url[CONFIG_SIGNY_EXAMPLE_SIGNED_URL_MAX_SIZE];

static void event_handler(void *arg,
                          esp_event_base_t event_base,
                          int32_t event_id,
                          void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        if (s_retry_num < WIFI_MAX_RETRIES)
        {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry to connect to the AP");
        }
        else
        {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "Connect to the AP fail");
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "WiFi Connected. Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init(const char *ssid, const char *password)
{
    _ssid = ssid;
    _password = password;

    esp_log_level_set("wifi", ESP_LOG_WARN);

    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    wifi_config_t wifi_config = {};
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    strncpy((char *) wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *) wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);

    ESP_ERROR_CHECK(esp_wifi_start());
}

static bool wifi_wait_for_connected_internal(TickType_t timeout_ticks)
{
    assert(_ssid);
    assert(_password);
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           timeout_ticks);
    bool connected = false;
    if (bits & WIFI_CONNECTED_BIT)
    {
        ESP_LOGI(TAG, "Connected to SSID: %s", _ssid);
        connected = true;
    }
    else if (bits & WIFI_FAIL_BIT)
    {
        ESP_LOGE(TAG, "Failed to connect to SSID: %s", _ssid);
    }
    else
    {
        ESP_LOGE(TAG, "Timeout waiting for Wi-Fi to connect");
    }
    return connected;
}

bool wifi_wait_for_connected_with_timeout(uint32_t timeout_s)
{
    return wifi_wait_for_connected_internal((timeout_s * 1000) / portTICK_PERIOD_MS);
}

void wifi_wait_for_connected(void)
{
    wifi_wait_for_connected_internal(portMAX_DELAY);
}


esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id)
    {
        case HTTP_EVENT_ERROR:
            ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG,
                     "HTTP_EVENT_ON_HEADER, key=%s, value=%s",
                     evt->header_key,
                     evt->header_value);
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGI(TAG, "HTTP_EVENT_REDIRECT");
            break;
        default:
            break;
    }
    return ESP_OK;
}

void app_main(void)
{
    int err;
    esp_err_t ret;
    struct timespec ts;
    psa_status_t status;

    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

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

    status = psa_import_key(&attributes, device_key_bin, device_key_bin_len, &priv_key);
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

    wifi_init(CONFIG_SIGNY_EXAMPLE_WIFI_SSID, CONFIG_SIGNY_EXAMPLE_WIFI_PASSWORD);
    wifi_wait_for_connected();

    size_t signed_url_len;
    err = signy_sign_url(CONFIG_SIGNY_EXAMPLE_BASE_URL,
                         strlen(CONFIG_SIGNY_EXAMPLE_BASE_URL),
                         signed_url,
                         sizeof(signed_url),
                         &signed_url_len);
    if (err != 0)
    {
        ESP_LOGE(TAG, "Error signing URL");
        return;
    }

    esp_http_client_config_t config = {
        .url = signed_url,
        .cert_pem = (char *) server_cert_pem_start,
        .event_handler = _http_event_handler,
        .keep_alive_enable = true,
        .buffer_size_tx = 10240,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };

    ESP_LOGI(TAG, "Performing update using signed url: %s", config.url);
    ret = esp_https_ota(&ota_config);
    if (ret == ESP_OK)
    {
        ESP_LOGI(TAG, "Completed artifact download. Attempting firmware update...");
        esp_restart();
    }
    else
    {
        ESP_LOGE(TAG, "Failed to download artifact");
    }
}
