// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include "cobs.h"
#include "framing.h"

static size_t ashen_framer_chunk(struct ashen_framer *f,
		const u8 *buf, size_t size)
{
	ssize_t len;
	size_t null_pos = strnlen(buf, size);
	bool found_null = null_pos < size;

	if (f->rx_len + null_pos > f->bufsize) {
		ashen_framer_reset(f);
		pr_warn("ashen-tamper: receive buffer overrun\n");
		/* drop this chunk; also skip the delimiter if we saw one */
		return null_pos + found_null;
	}

	memcpy(f->buf + f->rx_len, buf, null_pos);
	f->rx_len += null_pos;

	if (!found_null)
		return size;

	len = cobs_decode(f->buf, f->rx_len, f->buf, f->bufsize);
	if (len >= 0) {
		f->on_frame(f->ctx, f->buf, len);
	} else if (len == -EINTR) {
		pr_warn("ashen-tamper: truncated frame received\n");
	}/* else: consecutive null bytes received. ignore. */
	f->rx_len = 0;
	return null_pos + 1; /* consume the delimiter too */
}

void ashen_framer_reset(struct ashen_framer *f) {
	f->null_run = 0;
	f->sync = false;
	f->rx_len = 0;
}

size_t ashen_framer_push(struct ashen_framer *f, const u8 *buf, size_t size)
{
	size_t consumed = 0;
	size_t chunk;

	while (size && !f->sync) {
		while (size && *buf == 0x00) {
			buf++;
			size--;
			consumed++;
			f->null_run ++;
		}

		if (f->null_run >= FRAMER_SYNC_NULLS) {
			f->sync = true;
			f->on_reset(f->ctx);
			break;
		}

		while (size && *buf != 0x00) {
			buf++;
			size--;
			consumed++;
			f->null_run = 0;
		}
	}

	while (size && (chunk = ashen_framer_chunk(f, buf, size))) {
		buf += chunk;
		size -= chunk;
		consumed += chunk;
	}

	return consumed;
}
