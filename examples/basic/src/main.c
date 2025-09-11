/*
 * Copyright (c) 2025 Golioth
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/fs/fs.h>
#include <zephyr/shell/shell.h>
#include <psa/crypto.h>
#include <signy/signy.h>

LOG_MODULE_REGISTER(signy_basic, LOG_LEVEL_DBG);

static char signed_url[CONFIG_EXAMPLE_SIGNED_URL_MAX_SIZE];

#define CERT_DIR "/lfs1/credentials"
#define CERT_FILE CERT_DIR "/crt.der"
#define KEY_FILE CERT_DIR "/key.der"

static void ensure_credentials_dir(void)
{
    struct fs_dirent dirent;

    int err = fs_stat(CERT_DIR, &dirent);
    if (err == -ENOENT)
    {
        err = fs_mkdir(CERT_DIR);
    }

    if (err)
    {
        LOG_ERR("Failed to create credentials dir: %d", err);
    }
}

static ssize_t get_file_size(const char *path)
{
    struct fs_dirent dirent;

    int err = fs_stat(path, &dirent);

    if (err < 0)
    {
        return err;
    }
    if (dirent.type != FS_DIR_ENTRY_FILE)
    {
        return -EISDIR;
    }

    return dirent.size;
}

static ssize_t read_file(const char *path, uint8_t **out)
{
    // Ensure that the credentials directory exists, so the user doesn't have to
    ensure_credentials_dir();

    ssize_t size = get_file_size(path);
    if (size <= 0)
    {
        return size;
    }

    uint8_t *buf = malloc(size);
    if (buf == NULL)
    {
        return -ENOMEM;
    }

    struct fs_file_t file;
    fs_file_t_init(&file);

    int err = fs_open(&file, path, FS_O_READ);
    if (err)
    {
        LOG_ERR("Could not open %s, err: %d", path, err);
        free(buf);
        return err;
    }

    size = fs_read(&file, buf, size);
    if (size < 0)
    {
        LOG_ERR("Could not read %s, err: %d", path, size);
        free(buf);
        goto finish;
    }

    LOG_DBG("Read %d bytes from %s", size, path);

    *out = buf;

finish:
    fs_close(&file);
    return size;
}

static int cmd_signy_sign(const struct shell *shell, size_t argc, char *argv[])
{
    size_t signed_url_len;
    int err =
        signy_sign_url(argv[1], strlen(argv[1]), signed_url, sizeof(signed_url), &signed_url_len);
    if (err != 0)
    {
        shell_error(shell, "Failed to sign URL: %d", err);
        return -1;
    }

    shell_print(shell, "Signed URL (len: %d): %s", signed_url_len, signed_url);

    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
    sub_signy,
    SHELL_CMD_ARG(sign, NULL, "Generate signed URL.", cmd_signy_sign, 2, 0),
    SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(signy, &sub_signy, "signy commands", NULL);

int main(void)
{
    int err;
    psa_status_t status;

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

    uint8_t *device_key_der;
    ssize_t device_key_der_len = read_file(KEY_FILE, &device_key_der);
    if (device_key_der_len < 0)
    {
        LOG_ERR("Failed to read device key file: %d", device_key_der_len);
        return -1;
    }

    status = psa_import_key(&attributes, device_key_der, device_key_der_len, &priv_key);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("Failed to import private key: %d", status);
        return -1;
    }

    free(device_key_der);
    psa_reset_key_attributes(&attributes);

    uint8_t *device_crt_der;
    ssize_t device_crt_der_len = read_file(CERT_FILE, &device_crt_der);
    if (device_crt_der_len < 0)
    {
        LOG_ERR("Failed to read device certificate file: %d", device_crt_der_len);
        return -1;
    }

    err = signy_init(priv_key, device_crt_der, device_crt_der_len);
    if (err != 0)
    {
        LOG_ERR("Failed to initialize signy: %d", err);
        return -1;
    }
}
