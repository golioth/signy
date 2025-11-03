# Basic Signing Example

The basic signing example demonstrates how to use `signy` to generate a signed
URL using an imported
[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
private key.

## Setup

The basic signing example does not require any additional setup other than the
[common setup steps](../README.md#common-setup) required for all ESP-IDF
examples.

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
