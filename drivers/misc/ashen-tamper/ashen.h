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
	struct noise_keypair loc_static; /* persistent local identity */
	bool peer_keyed;    /* cached is_keyed from last status response */
	bool peer_trusts_us; /* cached peer_trusted from last status response */
	bool have_status;   /* a status response has been seen */
	enum ashen_connstate conn_st;
	struct completion connection_ready;
	ktime_t refresh_ivl;
	ktime_t timeout;
	bool autostart;
	bool armed;
	size_t reset_nulls_seen; /* null-reply bytes drained in CONN_RESET_WAIT */
	struct ashen_framer *framer;

	struct work_struct tx_work;
	struct work_struct restart_work;
	struct workqueue_struct *tx_wq;
	spinlock_t tx_queue_lock;
	DECLARE_KFIFO(tx_queue, struct ashen_tx_req, ASHEN_TX_QUEUE_LEN);

	struct mutex tx_lock;
	struct mutex rx_lock;
	unsigned char tx_buf[256];

#define ASHEN_TRACE_LEN 8192
	spinlock_t trace_lock;
	bool trace_active;
	size_t trace_head;
	size_t trace_count;
	u8 trace_buf[ASHEN_TRACE_LEN]; /* high bit of each byte = TX, low 8 held below */
	u8 trace_dir[ASHEN_TRACE_LEN]; /* 'T' or 'R' */
};

#endif /* __ASHEN_H__ */
