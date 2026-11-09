// SPDX-License-Identifier: GPL-2.0-only
/*
 * The Touch ID sensor's SPI side for sep.rs's stage 9 (the lab's relay).
 *
 * Binds the sensor node "apple,mesa-lab" that spi2-on.ko adds at runtime under spi2 (mode 1, CS 0), takes its
 * power switch (enable-gpios, pinctrl_nub 53, active high) at its off level, and gives sep.rs five calls: whether a
 * sensor is bound, its power, a full-duplex transfer, a reply's read and the sensor's patch. There is one sensor; a mutex orders
 * the calls. The power goes off at unbind and after any refused or failed transfer.
 *
 * What may reach the sensor is fixed here, below sep.rs's own checks (work/scratch/agents/sep-step9-relay.md sec. 5):
 * a command frame 80 TYPE 00 LEN_LO LEN_HI 00 00 whose type, declared length and transfer length are one of
 * mesa_shapes[], the bring-up's, or the raw patch once, after a 0x60 (SetupPatchEnable) frame and only status
 * reads since. The shapes keep out the frames the bring-up never sends: the production, key and provisioning
 * types, and the encrypted CalibrateAndUpdateNVM, whose 80 55 00 40 frame goes in a 0x12B transfer where the
 * set-parameter frame's goes in 0x40. The module serial number's 80 55 00 49 frame has the shape of the factory
 * clear's and the dev GID's: sep.rs sends it only with the blob that answers SBIO 0x31.
 *
 * Stage 11 (Touch ID step 10a, the capture alone) arms two more frames, StartCapture 80 40 and Idle 80 30, each a
 * 7-byte transfer as BS272 _handleCMD sends them (cases 6 and 1), and one image read of 0x7200 or 0x4800 bytes
 * (AppleSandDollar's two lengths for the 0x3352 sensor; handleStateMachine reads exactly one of them) into a buffer
 * of its own. The image is handed to sep.rs for its slice checks and never kept. Stage 12 (step 10c) uses the same
 * frames and read, and sep.rs relays the image to the SEP (SBIO 0x65) before it zeroes it.
 *
 * The sensor's interrupt (irq-gpios when spi2-on.ko names it: pinctrl_ap pin 34, level high in the ADT) is only
 * counted, while the power is on: each assertion is noted against the transfers before it and masked until the
 * next transfer, which may be what clears it, so a line left high cannot storm; the notes are logged at power off.
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/unaligned.h>
#include <linux/wait.h>

#include <asm/arch_timer.h>

#include "sensor.h"

/* the sensor's power-on and power-off delays (the ADT's power-on-delay 7, power-off-delay 10) */
#define MESA_ON_MS 7
#define MESA_OFF_MS 10
/* the largest transfer: the encrypted command frame is 0x12B bytes; the patch is checked on its own */
#define MESA_XFER_MAX 0x200
#define MESA_PATCH_MAX 0x40000
/* stage 11: the image's two lengths (BS272 AppleSandDollar::start, 0x3352: 12 slices) */
#define MESA_IMAGE_MAX 0x7200
#define MESA_IMAGE_MIN 0x4800

/* the bring-up's frames: type, declared length, transfer length */
static const struct {
	u8 type;
	u16 len, xfer;
} mesa_shapes[] = {
	{ 0x10, 0x07, 0x17 },	/* the status, 16 bytes in at 7 */
	{ 0x70, 0x07, 0x07 },	/* GetSerialNumber */
	{ 0x60, 0x07, 0x07 },	/* SetupPatchEnable */
	{ 0x72, 0x2f, 0x2f },	/* the key exchange's share (SBIO 0x15's 40 bytes) */
	{ 0x73, 0x47, 0x47 },	/* the sequence counter's challenge (SBIO 0x42's 64 bytes) */
	{ 0x55, 0x40, 0x40 },	/* SetEncryptedParameters (SBIO 0x5D's, 0x5C's blob) */
	{ 0x55, 0x4d, 0x12b },	/* the sensor-specific command 0x82 (SBIO 0x6A's blob) */
	{ 0x55, 0x49, 0x12b },	/* EncryptedGetModuleSerialNumber (SBIO 0x31's 64 bytes) */
};

/* stage 11's frames, allowed only while the capture is armed */
static const struct {
	u8 type;
	u16 len, xfer;
} mesa_capture_shapes[] = {
	{ 0x40, 0x07, 0x07 },	/* StartCapture (_handleCMD case 6) */
	{ 0x30, 0x07, 0x07 },	/* Idle (_handleCMD case 1) */
	{ 0x41, 0x07, 0x07 },	/* PauseCapture (_handleCMD case 0xA), the finger still on after an image */
	{ 0x31, 0x07, 0x07 },	/* Sleep, macOS's force-Idle before a StartCapture */
};

static DEFINE_MUTEX(mesa_lock);
/* woken when a sensor binds: the SEP driver may probe first at boot (apple_mesa_lab_wait_present) */
static DECLARE_WAIT_QUEUE_HEAD(mesa_bound_wq);
static struct spi_device *mesa_spi;
static struct gpio_desc *mesa_power;
static bool mesa_on;
static bool mesa_patch_armed;
static bool mesa_capture_armed;
static u8 *mesa_tx, *mesa_rx, *mesa_image;

/* the interrupt's count (above); mesa_irq_slock orders the unmasked flag with the IRQ's own disable and enable */
#define MESA_IRQ_NOTES 24
static int mesa_irq;
static bool mesa_irq_unmasked;
static DEFINE_SPINLOCK(mesa_irq_slock);
static atomic_t mesa_irqs;
static ktime_t mesa_on_at;
static u32 mesa_xfers;
static u8 mesa_last_type;
static struct {
	u32 us, xfer;
	u8 type;
} mesa_irq_notes[MESA_IRQ_NOTES];

static irqreturn_t mesa_irq_thread(int irq, void *data)
{
	int n = atomic_inc_return(&mesa_irqs) - 1;
	unsigned long flags;

	if (n < MESA_IRQ_NOTES) {
		mesa_irq_notes[n].us = ktime_us_delta(ktime_get(), mesa_on_at);
		mesa_irq_notes[n].xfer = READ_ONCE(mesa_xfers);
		mesa_irq_notes[n].type = READ_ONCE(mesa_last_type);
	}
	spin_lock_irqsave(&mesa_irq_slock, flags);
	if (mesa_irq_unmasked) {
		mesa_irq_unmasked = false;
		disable_irq_nosync(irq);
	}
	spin_unlock_irqrestore(&mesa_irq_slock, flags);
	return IRQ_HANDLED;
}

/* called with mesa_lock held, the power on: unmask the interrupt if a note masked it */
static void mesa_irq_unmask(void)
{
	unsigned long flags;

	if (!mesa_irq)
		return;
	spin_lock_irqsave(&mesa_irq_slock, flags);
	if (!mesa_irq_unmasked) {
		mesa_irq_unmasked = true;
		enable_irq(mesa_irq);
	}
	spin_unlock_irqrestore(&mesa_irq_slock, flags);
}

/* called with mesa_lock held, after a transfer: the frame's type (the tx's second byte) noted, the interrupt unmasked */
static void mesa_xfer_done(void)
{
	WRITE_ONCE(mesa_xfers, mesa_xfers + 1);
	WRITE_ONCE(mesa_last_type, mesa_tx ? mesa_tx[1] : 0);
	if (mesa_on)
		mesa_irq_unmask();
}

/* called with mesa_lock held, at power off: mask it and log the notes */
static void mesa_irq_report(void)
{
	unsigned long flags;
	bool was;
	int n, i;

	if (!mesa_irq)
		return;
	spin_lock_irqsave(&mesa_irq_slock, flags);
	was = mesa_irq_unmasked;
	if (was) {
		mesa_irq_unmasked = false;
		disable_irq_nosync(mesa_irq);
	}
	spin_unlock_irqrestore(&mesa_irq_slock, flags);
	synchronize_irq(mesa_irq);
	n = atomic_read(&mesa_irqs);
	dev_info(&mesa_spi->dev, "[sep2] mesa: the interrupt: %d while on, over %u transfers in %lld ms\n", n, mesa_xfers,
		 ktime_ms_delta(ktime_get(), mesa_on_at));
	for (i = 0; i < min(n, MESA_IRQ_NOTES); i++)
		dev_info(&mesa_spi->dev, "[sep2] mesa: the interrupt %d at %u us, after transfer %u (type %#04x)\n", i,
			 mesa_irq_notes[i].us, mesa_irq_notes[i].xfer, mesa_irq_notes[i].type);
}

static bool mesa_shape_allowed(u8 type, size_t len, size_t xfer)
{
	for (int i = 0; i < ARRAY_SIZE(mesa_shapes); i++)
		if (mesa_shapes[i].type == type && mesa_shapes[i].len == len && mesa_shapes[i].xfer == xfer)
			return true;
	if (mesa_capture_armed)
		for (int i = 0; i < ARRAY_SIZE(mesa_capture_shapes); i++)
			if (mesa_capture_shapes[i].type == type && mesa_capture_shapes[i].len == len &&
			    mesa_capture_shapes[i].xfer == xfer)
				return true;
	return false;
}

/* called with mesa_lock held */
static void mesa_power_set(bool on)
{
	if (!mesa_power)
		return;
	if (!on && mesa_on)
		mesa_irq_report();
	gpiod_set_value_cansleep(mesa_power, on);
	mesa_on = on;
	mesa_patch_armed = false;
	msleep(on ? MESA_ON_MS : MESA_OFF_MS);
	if (on) {
		atomic_set(&mesa_irqs, 0);
		mesa_xfers = 0;
		mesa_last_type = 0;
		mesa_on_at = ktime_get();
		mesa_irq_unmask();
	}
}

/* called with mesa_lock held: one full-duplex transfer of len bytes from mesa_tx into mesa_rx */
static int mesa_sync(size_t len)
{
	struct spi_transfer t = {
		.tx_buf = mesa_tx,
		.rx_buf = mesa_rx,
		.len = len,
	};

	int ret = spi_sync_transfer(mesa_spi, &t, 1);

	mesa_xfer_done();
	return ret;
}

/* 1 when a sensor is bound and its power switch taken, else 0 */
int apple_mesa_lab_present(void)
{
	int ret;

	mutex_lock(&mesa_lock);
	ret = mesa_spi && mesa_power;
	mutex_unlock(&mesa_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_present);

/*
 * 1 once a sensor is bound, waiting up to ms for it: at boot the SPI controller's driver and this one may bind after
 * the SEP's bring-up reaches the sensor. The condition reads without the lock (wait_event's condition must not
 * sleep); the locked check decides.
 */
int apple_mesa_lab_wait_present(unsigned int ms)
{
	wait_event_timeout(mesa_bound_wq, READ_ONCE(mesa_spi) && READ_ONCE(mesa_power), msecs_to_jiffies(ms));
	return apple_mesa_lab_present();
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_wait_present);

/* the power switch on (1) or off (0), each followed by its delay; -ENODEV with no sensor */
int apple_mesa_lab_power(int on)
{
	int ret = 0;

	mutex_lock(&mesa_lock);
	if (!mesa_spi || !mesa_power)
		ret = -ENODEV;
	else
		mesa_power_set(on);
	mutex_unlock(&mesa_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_power);

/*
 * One full-duplex transfer of len bytes: tx_len bytes of tx, then 0xFF (as the controller pads), into rx (len
 * bytes). tx must be a command frame whose length field is tx_len, of one of mesa_shapes[] with len. -EPERM for any other frame
 * (the power goes off), -EIO and the power off for a failed transfer. A 0x60 frame arms the patch.
 */
int apple_mesa_lab_xfer(const u8 *tx, size_t tx_len, u8 *rx, size_t len)
{
	int ret;

	if (tx_len < 7 || tx_len > len || len > MESA_XFER_MAX)
		return -EINVAL;
	mutex_lock(&mesa_lock);
	if (!mesa_spi || !mesa_on) {
		ret = -ENODEV;
		goto out;
	}
	if (tx[0] != 0x80 || tx[2] != 0 || tx[5] != 0 || tx[6] != 0 || (tx[3] | tx[4] << 8) != tx_len ||
	    !mesa_shape_allowed(tx[1], tx_len, len)) {
		dev_err(&mesa_spi->dev, "[sep2] mesa: frame %*ph refused; the power goes off\n", 7, tx);
		mesa_power_set(false);
		ret = -EPERM;
		goto out;
	}
	memcpy(mesa_tx, tx, tx_len);
	memset(mesa_tx + tx_len, 0xff, len - tx_len);
	ret = mesa_sync(len);
	if (ret) {
		dev_err(&mesa_spi->dev, "[sep2] mesa: a type %#x transfer failed (%d); the power goes off\n", tx[1], ret);
		mesa_power_set(false);
		ret = -EIO;
		goto out;
	}
	memcpy(rx, mesa_rx, len);
	/* the status reads that wait for state 0 keep it armed; anything else disarms it */
	if (tx[1] == 0x60)
		mesa_patch_armed = true;
	else if (tx[1] != 0x10)
		mesa_patch_armed = false;
out:
	mutex_unlock(&mesa_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_xfer);

/*
 * A reply's read (BS272 readSensorData): the read command 80 13 00 0b 00 00 00 and the u32 length, then len bytes
 * in, as one message, the chip select held between. Only that command; it disarms the patch.
 */
int apple_mesa_lab_read(u8 *rx, size_t len)
{
	static const u8 cmd[7] = { 0x80, 0x13, 0x00, 0x0b, 0x00, 0x00, 0x00 };
	struct spi_transfer t[2] = {};
	int ret;

	if (!len || 11 + len > MESA_XFER_MAX)
		return -EINVAL;
	mutex_lock(&mesa_lock);
	if (!mesa_spi || !mesa_on) {
		ret = -ENODEV;
		goto out;
	}
	memcpy(mesa_tx, cmd, sizeof(cmd));
	put_unaligned_le32(len, mesa_tx + 7);
	t[0].tx_buf = mesa_tx;
	t[0].len = 11;
	t[1].rx_buf = mesa_rx;
	t[1].len = len;
	mesa_patch_armed = false;
	ret = spi_sync_transfer(mesa_spi, t, 2);
	mesa_xfer_done();
	if (ret) {
		dev_err(&mesa_spi->dev, "[sep2] mesa: a read of %zu bytes failed (%d); the power goes off\n", len, ret);
		mesa_power_set(false);
		ret = -EIO;
		goto out;
	}
	memcpy(rx, mesa_rx, len);
out:
	mutex_unlock(&mesa_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_read);

/* stage 11: arm (1) or disarm (0) the capture's frames and the image read; -ENODEV with no sensor */
int apple_mesa_lab_capture_arm(int on)
{
	int ret = 0;

	mutex_lock(&mesa_lock);
	if (!mesa_spi || !mesa_image)
		ret = -ENODEV;
	else
		mesa_capture_armed = on;
	mutex_unlock(&mesa_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_capture_arm);

/*
 * Stage 11: the image's read, as apple_mesa_lab_read (80 13 00 0b 00 00 00 and the u32 length, then len bytes in, one
 * message), of exactly 0x7200 or 0x4800 bytes, only while the capture is armed. -EPERM otherwise.
 */
int apple_mesa_lab_read_image(u8 *rx, size_t len)
{
	static const u8 cmd[7] = { 0x80, 0x13, 0x00, 0x0b, 0x00, 0x00, 0x00 };
	struct spi_transfer t[2] = {};
	int ret;

	if (len != MESA_IMAGE_MAX && len != MESA_IMAGE_MIN)
		return -EINVAL;
	mutex_lock(&mesa_lock);
	if (!mesa_spi || !mesa_on || !mesa_image) {
		ret = -ENODEV;
		goto out;
	}
	if (!mesa_capture_armed) {
		dev_err(&mesa_spi->dev, "[sep2] mesa: an image read with the capture not armed refused\n");
		ret = -EPERM;
		goto out;
	}
	memcpy(mesa_tx, cmd, sizeof(cmd));
	put_unaligned_le32(len, mesa_tx + 7);
	t[0].tx_buf = mesa_tx;
	t[0].len = 11;
	t[1].rx_buf = mesa_image;
	t[1].len = len;
	mesa_patch_armed = false;
	ret = spi_sync_transfer(mesa_spi, t, 2);
	mesa_xfer_done();
	if (ret) {
		dev_err(&mesa_spi->dev, "[sep2] mesa: the image read of %zu bytes failed (%d); the power goes off\n", len, ret);
		mesa_power_set(false);
		ret = -EIO;
		goto out;
	}
	memcpy(rx, mesa_image, len);
	memzero_explicit(mesa_image, len);
out:
	mutex_unlock(&mesa_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_read_image);

/*
 * The capture's time for SBIO 0x06, in the ticks of the 24 MHz counter macOS's mach_absolute_time reads: the
 * virtual counter, as the capture data's +0x20 holds it.
 */
u64 apple_mesa_lab_ticks(void)
{
	return __arch_counter_get_cntvct();
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_ticks);

/*
 * The sensor's patch, raw, as one transfer (BS272 PatchGated), only after a 0x60 frame with nothing but status
 * reads since: any other frame, a power change or the patch itself disarms it. What comes back is not kept.
 */
int apple_mesa_lab_patch(const u8 *buf, size_t len)
{
	struct spi_transfer t = { .len = len };
	u8 *p;
	int ret;

	if (!len || len > MESA_PATCH_MAX)
		return -EINVAL;
	p = kmemdup(buf, len, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	t.tx_buf = p;
	mutex_lock(&mesa_lock);
	if (!mesa_spi || !mesa_on) {
		ret = -ENODEV;
	} else if (!mesa_patch_armed) {
		dev_err(&mesa_spi->dev, "[sep2] mesa: a patch with no 0x60 before it refused; the power goes off\n");
		mesa_power_set(false);
		ret = -EPERM;
	} else {
		mesa_patch_armed = false;
		ret = spi_sync_transfer(mesa_spi, &t, 1);
		mesa_xfer_done();
		if (ret) {
			dev_err(&mesa_spi->dev, "[sep2] mesa: the patch's transfer failed (%d); the power goes off\n", ret);
			mesa_power_set(false);
			ret = -EIO;
		}
	}
	mutex_unlock(&mesa_lock);
	kfree(p);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_lab_patch);

static int mesa_probe(struct spi_device *spi)
{
	struct gpio_desc *g, *ig;
	u8 *tx, *rx, *img;
	int irq = 0, ret;

	/* at its off level: iBoot leaves pin 53 an output at 0, so nothing changes */
	g = devm_gpiod_get(&spi->dev, "enable", GPIOD_OUT_LOW);
	if (IS_ERR(g))
		return dev_err_probe(&spi->dev, PTR_ERR(g), "[sep2] mesa: no power switch\n");
	/* masked until the power goes on (IRQF_NO_AUTOEN); low with the sensor off (iBoot: an input, pulled down) */
	ig = devm_gpiod_get_optional(&spi->dev, "irq", GPIOD_IN);
	if (IS_ERR(ig))
		return dev_err_probe(&spi->dev, PTR_ERR(ig), "[sep2] mesa: the interrupt's pin\n");
	if (ig) {
		irq = gpiod_to_irq(ig);
		if (irq <= 0)
			return dev_err_probe(&spi->dev, irq ?: -EINVAL, "[sep2] mesa: the interrupt's pin has no IRQ\n");
		ret = devm_request_threaded_irq(&spi->dev, irq, NULL, mesa_irq_thread,
						IRQF_ONESHOT | IRQF_TRIGGER_HIGH | IRQF_NO_AUTOEN, "apple-mesa-lab", NULL);
		if (ret)
			return dev_err_probe(&spi->dev, ret, "[sep2] mesa: the interrupt\n");
	}
	tx = devm_kmalloc(&spi->dev, MESA_XFER_MAX, GFP_KERNEL);
	rx = devm_kmalloc(&spi->dev, MESA_XFER_MAX, GFP_KERNEL);
	/* DMA-able: the controller may move the image by DMA */
	img = devm_kzalloc(&spi->dev, MESA_IMAGE_MAX, GFP_KERNEL);
	if (!tx || !rx || !img)
		return -ENOMEM;
	mutex_lock(&mesa_lock);
	if (mesa_spi) {
		mutex_unlock(&mesa_lock);
		return -EBUSY;
	}
	mesa_spi = spi;
	mesa_power = g;
	mesa_on = false;
	mesa_patch_armed = false;
	mesa_capture_armed = false;
	mesa_tx = tx;
	mesa_rx = rx;
	mesa_image = img;
	mesa_irq = irq;
	mesa_irq_unmasked = false;
	mutex_unlock(&mesa_lock);
	wake_up_all(&mesa_bound_wq);
	dev_info(&spi->dev, "[sep2] mesa: bound, mode %#x, %u Hz, the power off, the interrupt %s\n", spi->mode,
		 spi->max_speed_hz, irq ? "counted" : "not named");
	return 0;
}

static void mesa_remove(struct spi_device *spi)
{
	mutex_lock(&mesa_lock);
	if (mesa_spi == spi) {
		if (mesa_on)
			mesa_power_set(false);
		mesa_spi = NULL;
		mesa_power = NULL;
		mesa_irq = 0;
		mesa_capture_armed = false;
		mesa_tx = mesa_rx = mesa_image = NULL;
	}
	mutex_unlock(&mesa_lock);
}

static void mesa_shutdown(struct spi_device *spi)
{
	mesa_remove(spi);
}

static const struct of_device_id mesa_of_match[] = {
	{ .compatible = "apple,mesa" },
	{ .compatible = "apple,mesa-lab" },
	{}
};
MODULE_DEVICE_TABLE(of, mesa_of_match);

static const struct spi_device_id mesa_spi_ids[] = {
	{ "mesa-lab" },
	{}
};
MODULE_DEVICE_TABLE(spi, mesa_spi_ids);

static struct spi_driver mesa_driver = {
	.driver = {
		.name = "apple-mesa-lab",
		.of_match_table = mesa_of_match,
	},
	.id_table = mesa_spi_ids,
	.probe = mesa_probe,
	.remove = mesa_remove,
	.shutdown = mesa_shutdown,
};
module_spi_driver(mesa_driver);

MODULE_DESCRIPTION("The Touch ID sensor's SPI side for the SEP driver's lab stage");
MODULE_LICENSE("GPL");
