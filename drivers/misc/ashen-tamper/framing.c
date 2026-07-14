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
	size_t nul_pos = strnlen(buf, size);
	bool found_null = nul_pos < size;

	if (f->len + nul_pos > f->cap) {
		f->sync = false;
		f->len = 0;
		pr_warn("ashen-tamper: receive buffer overrun\n");
		/* drop this chunk; also skip the delimiter if we saw one */
		return nul_pos + found_null;
	}

	memcpy(f->buf + f->len, buf, nul_pos);
	f->len += nul_pos;

	if (!found_null)
		return size;

	/* frame complete. decode in place. */
	len = cobs_decode(f->buf, f->len, f->buf, f->cap);
	if (len >= 0) {
		f->on_frame(f->ctx, f->buf, len);
	} else if (len == -EINTR) {
		pr_warn("ashen-tamper: truncated frame received\n");
		/* no point in resetting f->sync here since we already
		 * received the next null byte, so we are synced. */
	}/* else: consecutive null bytes received. Technically, a valid empty
	     frame is [0x01 0x00], not just [0x00]. We ignore this here since
	     runs of null bytes are useful for initial sync. */
	f->len = 0;
	return nul_pos + 1; /* consume the delimiter too */
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
