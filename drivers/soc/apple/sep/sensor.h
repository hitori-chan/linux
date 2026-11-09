/* SPDX-License-Identifier: GPL-2.0-only */
/* The Touch ID sensor's SPI side for sep.rs's stage 9 (sensor.c); sep/mesa.rs declares the same. */
#ifndef _APPLE_SEP_SENSOR_H
#define _APPLE_SEP_SENSOR_H

#include <linux/types.h>

int apple_mesa_lab_present(void);
int apple_mesa_lab_wait_present(unsigned int ms);
int apple_mesa_lab_power(int on);
int apple_mesa_lab_xfer(const u8 *tx, size_t tx_len, u8 *rx, size_t len);
int apple_mesa_lab_read(u8 *rx, size_t len);
int apple_mesa_lab_patch(const u8 *buf, size_t len);
int apple_mesa_lab_capture_arm(int on);
int apple_mesa_lab_read_image(u8 *rx, size_t len);
u64 apple_mesa_lab_ticks(void);

#endif
