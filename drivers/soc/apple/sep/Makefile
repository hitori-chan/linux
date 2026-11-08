# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_APPLE_SEP) += sep.o

# the Touch ID sensor's SPI side, which sep.rs drives (a driver of its own: it binds the sensor's SPI device)
obj-$(CONFIG_APPLE_SEP) += apple-sep-sensor.o
apple-sep-sensor-y = sensor.o
