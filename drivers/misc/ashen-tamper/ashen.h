// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef __ASHEN_H__
#define __ASHEN_H__

#include "framing.h"

enum ashen_connstate {
	CONN_DISCONNECTED,
	CONN_HANDSHAKE,
	CONN_CONNECTED,
};

struct ashen_tamper {
	struct hrtimer hb_timer;
	struct hrtimer refresh_timer;
	struct serdev_device *serdev;
	spinlock_t noise_lock; /* noise state machine lock */
	struct noise_state noise_st;
	enum ashen_connstate conn_st;
	struct completion connection_ready;
	struct completion packet_ready;
	ktime_t refresh_ivl;
	ktime_t timeout;
	bool autostart;
	struct ashen_framer *framer;
	struct mutex tx_lock;
	unsigned char tx_buf[256];
};

#endif /* __ASHEN_H__ */
