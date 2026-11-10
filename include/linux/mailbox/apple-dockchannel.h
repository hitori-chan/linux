/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Apple DockChannel mailbox message format.
 *
 * Copyright The Asahi Linux Contributors
 */

#ifndef _LINUX_MAILBOX_APPLE_DOCKCHANNEL_H_
#define _LINUX_MAILBOX_APPLE_DOCKCHANNEL_H_

#include <linux/types.h>

struct mbox_chan;

/* A TX message carries at most this many bytes: the FIFO's size. */
#define APPLE_DOCKCHANNEL_FIFO_SIZE	0x800

/**
 * struct apple_dockchannel_msg - DockChannel mailbox payload
 * @data: Pointer to the byte stream payload
 * @len: Number of payload bytes
 * @wake: RX only: the data arrived while the system slept with wake on
 *	  (apple_dockchannel_set_wake()); the client reports its wakeup event
 *
 * For TX, @data must remain valid until mbox_send_message() completes or the
 * client receives tx_done in non-blocking mode.
 *
 * For RX, @data is owned by the controller and is valid only for the duration
 * of the rx_callback.
 */
struct apple_dockchannel_msg {
	void *data;
	size_t len;
	bool wake;
};

int apple_dockchannel_set_wake(struct mbox_chan *chan, bool enable);

#endif /* _LINUX_MAILBOX_APPLE_DOCKCHANNEL_H_ */
