#include <zephyr/kernel.h>
#include <zephyr/posix/time.h>
#include <zephyr/logging/log.h>
#include <psa/crypto.h>
#include <signy/signy.h>

#include "device_cert.inc"
#include "device_key.inc"

LOG_MODULE_REGISTER(signy_basic, LOG_LEVEL_DBG);

static char signed_url[CONFIG_SIGNED_URL_MAX_SIZE];

int main(void)
{
    int err;
    psa_status_t status;
    size_t signed_url_len;
    struct timespec ts = {.tv_sec = CONFIG_CURRENT_UNIX_TIMESTAMP};

    err = clock_settime(CLOCK_REALTIME, &ts);
    if (err != 0)
    {
        LOG_ERR("Failed to set time: %d", err);
        return -1;
    }


    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("Failed to initialize PSA crypto: %d", status);
        return -1;
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
        LOG_ERR("Failed to import private key: %d", status);
        return -1;
    }

    psa_reset_key_attributes(&attributes);

    err = signy_init(priv_key, device_crt_der, device_crt_der_len);
    if (err != 0)
    {
        LOG_ERR("Failed to initialize signy: %d", err);
        return -1;
    }

    err = signy_sign_url(CONFIG_BASE_URL,
                         strlen(CONFIG_BASE_URL),
                         signed_url,
                         sizeof(signed_url),
                         &signed_url_len);
    if (err != 0)
    {
        LOG_ERR("Failed to sign URL: %d", err);
        return -1;
    }

    LOG_INF("Signed URL (len: %d): %s", signed_url_len, signed_url);
}
