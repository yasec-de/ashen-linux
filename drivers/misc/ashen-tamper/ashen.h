/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef __ASHEN_H__
#define __ASHEN_H__

#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include "framing.h"
#include "noise.h"
#include "proto.h"

enum ashen_connstate {
	CONN_DISCONNECTED,
	CONN_RESET_WAIT, /* reset sent, draining the responder's null reply */
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
	struct hrtimer restart_timer;
	struct serdev_device *serdev;
	struct noise_state noise_st;
	struct noise_keypair loc_static;
	bool peer_keyed;
	bool peer_trusts_us;
	bool have_status;
	enum ashen_connstate conn_st;
	struct completion connection_ready;
	ktime_t refresh_ivl;
	ktime_t timeout;
	bool autostart;
	bool armed;
	struct ashen_framer *framer;

	struct work_struct tx_work;
	struct work_struct restart_work;
	struct workqueue_struct *tx_wq;
	spinlock_t tx_queue_lock;
	DECLARE_KFIFO(tx_queue, struct ashen_tx_req, ASHEN_TX_QUEUE_LEN);

	struct mutex tx_lock;
	struct mutex rx_lock;
	unsigned char tx_buf[ASHEN_MAX_PAYLOAD_LEN];
	u8 tx_wire[ASHEN_MAX_FRAME_LEN];

	u8 log_buf[512];
	size_t log_buf_pos;

	/* Hexdump of the wire, flushed a line at a time: on 16 bytes, on a
	 * direction change, or 100 ms after the last byte.
	 */
#define ASHEN_TRACE_LINE 16
	spinlock_t trace_lock;
	struct hrtimer trace_timer;
	char trace_dir; /* 'T', 'R', or 0 when the line buffer is empty */
	size_t trace_len;
	u8 trace_buf[ASHEN_TRACE_LINE];
};

#endif /* __ASHEN_H__ */
