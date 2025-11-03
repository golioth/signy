# Over-the-Air (OTA) Update Example

The OTA update example demonstrates how to use `signy` with the ESP-IDF
[`esp_https_ota`](https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32s3/api-reference/system/esp_https_ota.html)
component.

## Setup

In addition to the [common setup steps](../README.md#common-setup) required for
all ESP-IDF examples, this example also requires configuring Wi-Fi credentials
and may require providing an alternate server CA certificate.

### Configuring Wi-Fi Credentials

An SSID and password is required to connect to a Wi-Fi access point for
downloading artifacts for OTA firmware update. They can be set using the
following options in `sdkconfig.defaults`.

```
CONFIG_SIGNY_EXAMPLE_WIFI_SSID="your-wifi-ssid"
```

```
CONFIG_SIGNY_EXAMPLE_WIFI_PASSWORD="your-wifi-password"
```

### Configuring Server CA Certificate

By default, this example includes the [Let's Encrypt](https://letsencrypt.org/)
[ISRG Root X1](https://letsencrypt.org/certificates/#root-cas) CA certificate
(`server.ca.cert.pem`) to verify the server's certificate when using the
generated signed URL to download an artifact. If updating to a different server
by setting `CONFIG_SIGNY_EXAMPLE_BASE_URL` in `sdkconfig.defaults`, you may need
to supply a different CA certificate.

## Building & Programming

The OTA example can be built using the following command.

```
idf.py build
```

The example can be programmed on a device using the following command.

```
idf.py flash
```

To view the generated signed URL, monitor the console output using the following
command.

```
idf.py monitor
```
