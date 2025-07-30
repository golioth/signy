/*
 * Copyright (c) 2025 Golioth, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* This mirrors the standard padded base64_encode in Zephyr v4.1.0 */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief          Encode a buffer into base64 URL format without padding
 *
 * @param dst      destination buffer
 * @param dlen     size of the destination buffer
 * @param olen     number of bytes written
 * @param src      source buffer
 * @param slen     amount of data to be encoded
 *
 * @return         0 if successful, or -ENOMEM if the buffer is too small.
 *                 *olen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *                 If that length cannot be represented, then no data is
 *                 written to the buffer and *olen is set to the maximum
 *                 length representable as a size_t.
 *
 * @note           Call this function with dlen = 0 to obtain the
 *                 required buffer size in *olen
 */
int base64_url_encode_raw(uint8_t *dst, size_t dlen, size_t *olen, const uint8_t *src, size_t slen);
