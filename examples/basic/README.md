# Basic Signing Example

```
xxd -i device.crt.der > src/device_cert.h
```

```
xxd -i -s 7 -l 32 device.key.der > src/device_key.h
```

```
west build -p -b nrf9160dk/nrf9160/ns ./signy/examples/basic/
```
