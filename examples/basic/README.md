# Basic Signing Example

The basic signing example demonstrates how to use `signy` to generate a signed
URL using an imported
[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
private key.

## Building & Programming

The basic signing example can be built using the following command.

```
west build -p -b <board>
```

The example can be programmed on a device using the following command.

```
west flash
```

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

After acquiring DER-encoded private key and certificate, use the following
[`mcumgr`](https://github.com/apache/mynewt-mcumgr) or
[`smpmgr`](https://github.com/intercreate/smpmgr) commands on your local machine
to load them into the filesystem on the device.

Load the device certificate.

```
mcumgr --conntype serial --connstring /dev/ttyACM0 fs upload device.crt.der /lfs1/credentials/crt.der
```

**or**

```
smpmgr --port /dev/ttyACM0 --mtu 128 file upload device.crt.der /lfs1/credentials/crt.der
```

Extract the device private key to `device.key.bin` in the [format
expected](https://datatracker.ietf.org/doc/html/rfc5915.html) by
`psa_import_key()` for a [Weierstrass Elliptic curve key
pair](https://arm-software.github.io/psa-api/crypto/1.1/api/keys/management.html#key-formats).
How the private key is extracted will depend on how the key was generated, but
the the result should always be 32 bytes.

Load the device private key.

```
mcumgr --conntype serial --connstring /dev/ttyACM0 fs upload device.key.bin /lfs1/credentials/key.bin
```

**or**

```
smpmgr --port /dev/ttyACM0 --mtu 128 file upload device.key.bin /lfs1/credentials/key.bin
```

After configuring credentials, reboot the device to initialize `signy` with them.

### Configuring Time

In order to generate a valid signed URL with `signy`, a device must have access
to an accurate time source. In a production scenario, [Network Time Protocol
(NTP)](https://en.wikipedia.org/wiki/Network_Time_Protocol) or other clock
synchronization mechanisms may be employed.

For demonstration purposes, the device system time can be set in the basic
signing example using the `date set` shell command after establishing a serial
connection to the device. The date and time must be provided as UTC in the
following format.

```
[Y-m-d] <H:M:S>
```

For example, the following command would set the device system time to
Septemeber 10th, 2025 at 6:32 PM UTC.

```
date set 2025-09-10 18:32:00
```

## Generating Signed URLs

After credentials and time are configured, signed URLs can be generated on the
device using the `signy sign` shell command over a serial connection. For
example, if using `signy` with Golioth, a signed URL can be generated for the
`main@1.0.0` OTA artifact in your project using the following command.

```
signy sign https://gw.golioth.io/.u/c/main@1.0.0
```

The generated signed URL will be valid for the duration specified in
`CONFIG_SIGNY_URL_VALIDITY_DURATION`.
