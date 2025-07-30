/*
 * Copyright (c) 2025 Golioth, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <psa/crypto.h>

/**
 * Initialize signy with private key and certificate.
 *
 * @param priv The PSA key ID for private key used for signing.
 * @param cert The DER encoded certificate.
 * @param cert_len The length of the DER encoded cerficicate.
 *
 * @return 0 on success or a negative error code on failure.
 */
int signy_init(psa_key_id_t priv, const uint8_t *cert, size_t cert_len);

/**
 * Sign the provided URL.
 *
 * @param url The base URL to be signed.
 * @param url_len The length of the base URL.
 * @param signed_url The buffer that the signed URL should be written to.
 * @param signed_url_len The length of the signed URL buffer.
 * @param olen The length of the written signed URL.
 *
 * @return 0 on success or a negative error code on failure.
 */
int signy_sign_url(const char *url,
                   size_t url_len,
                   char *signed_url,
                   size_t signed_url_len,
                   size_t *olen);
