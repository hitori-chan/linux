# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_APPLE_SEP) += sep.o

# the Touch ID sensor's SPI side, which sep.rs drives (a driver of its own: it binds the sensor's SPI device)
obj-$(CONFIG_APPLE_SEP) += apple-sep-sensor.o
apple-sep-sensor-y = sensor.o

# the xART store's disk writes at stage 13 (the .gl file's extents on the iBoot System Container, in place)
obj-$(CONFIG_APPLE_SEP) += apple-sep-disk.o
apple-sep-disk-y = disk.o

# the FIDO2 authenticator's HID device and ciphers (sep/fido.rs)
obj-$(CONFIG_APPLE_SEP) += apple-sep-fido.o
apple-sep-fido-y = fido.o

# the SEP's entropy as a hwrng
obj-$(CONFIG_APPLE_SEP) += apple-sep-rng.o
apple-sep-rng-y = rng.o
