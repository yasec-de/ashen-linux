/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef _ASHEN_FRAMING_H
#define _ASHEN_FRAMING_H

#include <linux/types.h>

#define FRAMER_SYNC_NULLS 24

struct ashen_framer {
	size_t rx_len;
	bool sync;
	size_t null_run; 
	void (*on_frame)(void *ctx, const u8 *frame, size_t len);
	void (*on_reset)(void *ctx);
	void *ctx;
	size_t bufsize;
	u8 buf[];
};

size_t ashen_framer_push(struct ashen_framer *f, const u8 *buf, size_t size);
void ashen_framer_reset(struct ashen_framer *f);

#endif /* _ASHEN_FRAMING_H */
