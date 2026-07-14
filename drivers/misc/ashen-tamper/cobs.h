/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef _ASHEN_COBS_H
#define _ASHEN_COBS_H

#include <linux/types.h>

ssize_t cobs_encode(const u8 *input, size_t input_len, u8 *output, size_t output_len);
ssize_t cobs_decode(const u8 *input, size_t input_len, u8 *output, size_t output_len);

#endif /* _ASHEN_COBS_H */
