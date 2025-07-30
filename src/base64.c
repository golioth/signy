/*
 * Copyright (c) 2025 Golioth, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* This mirrors the standard padded base64_encode in Zephyr v4.1.0 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

static const uint8_t base64_url_enc_map[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};

#define BASE64_SIZE_T_MAX ((size_t) -1)

int base64_url_encode_raw(uint8_t *dst, size_t dlen, size_t *olen, const uint8_t *src, size_t slen)
{
    size_t i, n, t;
    int C1, C2, C3;
    uint8_t *p;

    if (slen == 0)
    {
        *olen = 0;
        return 0;
    }

    /**
     * The following calculation is used for base64 unpadded URL encoded length to
     * allow for checking for overflow before checking destination length. The
     * trailing bytes account for the implicit floor operation when performing integer
     * division, plus an additional byte if the input is not divisble by 3. This
     * is semantically equivalent to rounding the input length down to the
     * nearest multiple of 3, calculating the base64 length, then adding the
     * base64 length of the remaining 0-2 bytes (e.g b64_len(64) = b64_len(63) +
     * b64_len(1)).
     *
     * len = (n / 3 * 4) + (n % 3) + (n % 3 != 0)
     */
    n = slen / 3;
    t = slen % 3 + (slen % 3 != 0);
    if (n > (BASE64_SIZE_T_MAX - 1 - t) / 4)
    {
        *olen = BASE64_SIZE_T_MAX;
        return -ENOMEM;
    }

    n = n * 4 + t;

    if ((dlen < n + 1) || (!dst))
    {
        *olen = n + 1;
        return -ENOMEM;
    }

    n = (slen / 3) * 3;

    for (i = 0, p = dst; i < n; i += 3)
    {
        C1 = *src++;
        C2 = *src++;
        C3 = *src++;

        *p++ = base64_url_enc_map[(C1 >> 2) & 0x3F];
        *p++ = base64_url_enc_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];
        *p++ = base64_url_enc_map[(((C2 & 15) << 2) + (C3 >> 6)) & 0x3F];
        *p++ = base64_url_enc_map[C3 & 0x3F];
    }

    if (i < slen)
    {
        C1 = *src++;
        C2 = ((i + 1) < slen) ? *src++ : 0;

        *p++ = base64_url_enc_map[(C1 >> 2) & 0x3F];
        *p++ = base64_url_enc_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];

        if ((i + 1) < slen)
        {
            *p++ = base64_url_enc_map[((C2 & 15) << 2) & 0x3F];
        }
    }

    *olen = p - dst;
    *p = 0U;

    return 0;
}
