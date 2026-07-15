// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef __ASHEN_H__
#define __ASHEN_H__

#include <linux/kfifo.h>
#include <linux/workqueue.h>
#include "framing.h"
#include "noise.h"

enum ashen_connstate {
	CONN_DISCONNECTED,
	CONN_HANDSHAKE,
	CONN_CONNECTED,
};

#define ASHEN_TX_MAX_PAYLOAD 16
#define ASHEN_TX_QUEUE_LEN 8

struct ashen_tx_req {
	u8 payload[ASHEN_TX_MAX_PAYLOAD];
	size_t len;
};

struct ashen_tamper {
	struct hrtimer hb_timer;
	struct hrtimer refresh_timer;
	struct serdev_device *serdev;
	struct noise_state noise_st;
	enum ashen_connstate conn_st;
	struct completion connection_ready;
	struct completion packet_ready;
	ktime_t refresh_ivl;
	ktime_t timeout;
	bool autostart;
	struct ashen_framer *framer;

	struct work_struct tx_work;
	struct workqueue_struct *tx_wq;
	spinlock_t tx_queue_lock;
	DECLARE_KFIFO(tx_queue, struct ashen_tx_req, ASHEN_TX_QUEUE_LEN);

	struct mutex tx_lock; /* serialises noise send state + serdev write */
	unsigned char tx_buf[256];
};

#endif /* __ASHEN_H__ */
