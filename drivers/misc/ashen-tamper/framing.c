// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include "cobs.h"
#include "framing.h"

#define FRAMER_SYNC_NULLS 8

static size_t ashen_framer_chunk(struct ashen_framer *f,
		const u8 *buf, size_t size)
{
	ssize_t len;
	size_t null_pos = strnlen(buf, size);
	bool found_null = null_pos < size;

	if (f->len + null_pos > f->cap) {
		f->sync = false;
		f->len = 0;
		pr_warn("ashen-tamper: receive buffer overrun\n");
		/* drop this chunk; also skip the delimiter if we saw one */
		return null_pos + found_null;
	}

	memcpy(f->buf + f->len, buf, null_pos);
	f->len += null_pos;

	if (!found_null)
		return size;

	if (f->sync < FRAMER_SYNC_NULLS) {
		if (f->len != 1) {
			f->sync = 0;
		} else {
			f->sync ++;
		}
		f->len = 0;
		return null_pos + 1;
	}

	/* frame complete. decode in place. */
	len = cobs_decode(f->buf, f->len, f->buf, f->cap);
	if (len >= 0) {
		f->on_frame(f->ctx, f->buf, len);
	} else if (len == -EINTR) {
		pr_warn("ashen-tamper: truncated frame received\n");
	}/* else: consecutive null bytes received. ignore. */
	f->len = 0;
	return null_pos + 1; /* consume the delimiter too */
}

size_t ashen_framer_push(struct ashen_framer *f, const u8 *buf, size_t size)
{
	size_t consumed = 0;
	size_t chunk;

	while (size && (chunk = ashen_framer_chunk(f, buf, size))) {
		buf += chunk;
		size -= chunk;
		consumed += chunk;
	}
	return consumed;
}
