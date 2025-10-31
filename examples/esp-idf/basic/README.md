# Basic Signing Example

The basic signing example demonstrates how to use `signy` to generate a signed
URL using an imported
[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
private key.

## Setup

In order to successfully generate signed URLs, valid credentials must be
configured, and the device system time must be updated.

### Configuring Credentials

In a production scenario, private keys should always be generated and stored in
a secure location on a device, and certificates should be issued using [Public
Key Infrastructure (PKI)](https://docs.golioth.io/connectivity/credentials/pki).

For demonstration purposes, keys and certificates can be generated locally, then
included in the firmware build. `signy` requires the use of a `secp256r1`
elliptic curve key pair. If using `signy` with Golioth, see the [relevant
documentation](https://docs.golioth.io/connectivity/credentials/pki#establishing-pki)
for establishing a Certificate Authority (CA) and issuing device certificates.

After acquiring DER-encoded private key and certificate, `.inc` files that will
be included in the firmware build can be generated using the following commands.


Generate the device certificate `.inc` file.

```
xxd -i device.crt.der > src/device_cert_der.inc
```

Extract the device private key to `device.key.bin` in the [format
expected](https://datatracker.ietf.org/doc/html/rfc5915.html) by
`psa_import_key()` for a [Weierstrass Elliptic curve key
pair](https://arm-software.github.io/psa-api/crypto/1.1/api/keys/management.html#key-formats).
How the private key is extracted will depend on how the key was generated, but
the the result should always be 32 bytes.

> [!NOTE]
> The following command works for private keys generated using `openssl ecparam
> -name prime256v1 -genkey`, but may not be suitable for all DER-encoded private
> keys.

```
xxd -i -s 7 -l 32 device.key.der > src/device_key_bin.inc
```

### Configuring Time

In order to generate a valid signed URL with `signy`, a device must have access
to an accurate time source. In a production scenario, [Network Time Protocol
(NTP)](https://en.wikipedia.org/wiki/Network_Time_Protocol) or other clock
synchronization mechanisms may be employed.

For demonstration purposes, the device system time can be set using the
`CONFIG_SIGNY_EXAMPLE_CURRENT_UNIX_TIMESTAMP` option in `sdkconfig.defaults`.

```
CONFIG_SIGNY_EXAMPLE_CURRENT_UNIX_TIMESTAMP=1761746813
```
Because the time is configured during build, it will be reset every time the
device reboots. The generated signed URL will be valid from the configured
timestamp to the time `CONFIG_SIGNY_URL_VALIDITY_DURATION` seconds after.

## Building & Programming

The basic signing example can be built using the following command.

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
