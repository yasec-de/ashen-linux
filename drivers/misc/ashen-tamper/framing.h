/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef _ASHEN_FRAMING_H
#define _ASHEN_FRAMING_H

#include <linux/types.h>

/*
 * COBS frame reassembler. Accumulates bytes from a serial-style byte stream,
 * splits on the NUL delimiter, and COBS-decodes complete frames in place.
 * Decoded frames are handed to on_frame(). No serdev dependency, so this is
 * unit-testable on its own.
 *
 * Allocate with struct_size(f, buf, cap) and set cap/on_frame/ctx before use.
 */
struct ashen_framer {
	size_t cap;	/* usable size of buf[] */
	size_t len;
	bool sync;
	void (*on_frame)(void *ctx, const u8 *frame, size_t len);
	void *ctx;
	u8 buf[];	/* flexible array member, must stay last */
};

/* Feed 'size' bytes; returns the number of bytes consumed. */
size_t ashen_framer_push(struct ashen_framer *f, const u8 *buf, size_t size);

#endif /* _ASHEN_FRAMING_H */
