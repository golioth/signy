/*
 * Copyright (c) 2025 Golioth, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/posix/time.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/base64.h>
#include <psa/crypto.h>

LOG_MODULE_REGISTER(signy, LOG_LEVEL_DBG);

#define SIGNY_URL_FMT "%.*s?nb=%lld&na=%lld&cert=%.*s"
#define SIGNY_SIGNED_URL_FMT "%s&sig=%.*s"

#define SIGNY_KEY_BITS 256
#define SIGNY_HASH_BITS 256

#define SIGNY_SIG_SIZE 64
#define SIGNY_SIG_B64_SIZE (SIGNY_SIG_SIZE / 3 + (SIGNY_SIG_SIZE % 3 != 0)) * 4 + 1

static psa_key_id_t signy_key;
static uint8_t b64_cert[CONFIG_SIGNY_MAX_CERT_SIZE];
static size_t b64_cert_len;

int signy_init(psa_key_id_t priv, const uint8_t *cert, size_t cert_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    status = psa_get_key_attributes(priv, &attributes);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("Failed to get key attributes: %d", status);
        return -EINVAL;
    }

    if (psa_get_key_type(&attributes) != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1))
    {
        LOG_ERR("Wrong key type provided");
        return -EINVAL;
    }

    if (psa_get_key_bits(&attributes) != SIGNY_KEY_BITS)
    {
        LOG_ERR("Wrong key bits provided");
        return -EINVAL;
    }

    if (psa_get_key_algorithm(&attributes) != PSA_ALG_ECDSA(PSA_ALG_SHA_256))
    {
        LOG_ERR("Wrong key algorithm provided");
        return -EINVAL;
    }

    psa_reset_key_attributes(&attributes);

    int ret = base64_encode(b64_cert, sizeof(b64_cert), &b64_cert_len, cert, cert_len);
    if (ret != 0)
    {
        LOG_ERR("Failed to base64 encode certificate: %d", ret);
        return -EINVAL;
    }

    signy_key = priv;
    return 0;
}

int signy_sign_url(const char *url,
                   size_t url_len,
                   char *signed_url,
                   size_t signed_url_len,
                   size_t *olen)
{
    static uint8_t hash[SIGNY_HASH_BITS / 8];
    static uint8_t sig[SIGNY_SIG_SIZE];
    static char sig_b64_buf[SIGNY_SIG_B64_SIZE];
    static char url_buf[CONFIG_SIGNY_MAX_URL_SIZE];

    size_t hash_len;
    size_t sig_len;
    size_t sig_b64_len;

    int err = 0;
    int ret;
    psa_status_t status;
    struct timespec ts;

    ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (ret != 0)
    {
        LOG_ERR("Failed getting current time: %d", ret);
        return -EINVAL;
    }

    /* Attach parameters to URL for signing */
    ret = snprintf(url_buf,
                   sizeof(url_buf),
                   SIGNY_URL_FMT,
                   url_len,
                   url,
                   ts.tv_sec,
                   ts.tv_sec + CONFIG_SIGNY_URL_VALIDITY_DURATION,
                   b64_cert_len,
                   b64_cert);
    if (ret < 0 || ret >= sizeof(url_buf))
    {
        LOG_ERR("Failed formatting URL for signing: %d", ret);
        return -ENOMEM;
    }

    /* Compute the SHA256 hash of the URL */
    status = psa_hash_compute(PSA_ALG_SHA_256, url_buf, ret, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("Failed computing hash: %d", status);
        return -EINVAL;
    }

    /* Sign the hash */
    status = psa_sign_hash(signy_key,
                           PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                           hash,
                           sizeof(hash),
                           sig,
                           sizeof(sig),
                           &sig_len);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("Failed signing: %d", status);
        err = -EINVAL;
        goto cleanup;
    }

    /* Encode signature as base64 */
    ret = base64_encode(sig_b64_buf, sizeof(sig_b64_buf), &sig_b64_len, sig, sig_len);
    if (ret != 0)
    {
        LOG_INF("Failed encoding signature as base64: %d", ret);
        err = -ENOMEM;
        goto cleanup;
    }

    /* Construct final signed URL */
    ret = snprintf(signed_url,
                   signed_url_len,
                   SIGNY_SIGNED_URL_FMT,
                   url_buf,
                   sig_b64_len,
                   sig_b64_buf);
    if (ret < 0 || ret >= signed_url_len)
    {
        LOG_ERR("Failed to construct signed URL: %d", ret);
        err = -ENOMEM;
        goto cleanup;
    }

    *olen = ret;

cleanup:
    /* Clear any written sensitive data */
    memset(sig, 0, sizeof(sig));
    memset(sig_b64_buf, 0, sizeof(sig_b64_buf));
    return err;
}
