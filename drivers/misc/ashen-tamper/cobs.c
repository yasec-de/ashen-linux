// SPDX-License-Identifier: GPL-2.0-only                                                                                                                        
/*                                                                                                                                                              
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */   

#include <linux/types.h>


ssize_t cobs_encode(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
	size_t idx_pos = 0;
	size_t out_pos = 1;
	size_t in_pos = 0;

	while (in_pos < input_len) {
		if (out_pos >= output_len)
			return -1;

		uint8_t inbyte = input[in_pos];
		in_pos += 1;

		if (out_pos - idx_pos >= 255) {
			output[idx_pos] = 255;
			idx_pos = out_pos;
			out_pos += 1;

			if (out_pos >= output_len)
				return -1;
		}

		if (inbyte) {
			output[out_pos] = inbyte;
			out_pos += 1;
		} else {
			output[idx_pos] = out_pos - idx_pos;
			idx_pos = out_pos;
			out_pos += 1;
		}
	}

	if (out_pos >= output_len)
		return -1;
	output[idx_pos] = out_pos - idx_pos;
	output[out_pos] = 0x00;

	return out_pos + 1;
}

/* input and output may overlap. */
ssize_t cobs_decode(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
	size_t out_pos = 0;
	size_t in_pos = 0;

	if (input_len == 0)
		return -1;

	while (in_pos < input_len) {
		size_t len = input[in_pos];
		in_pos += 1;

		for (size_t i=0; i<len-1; i++) {
			if (in_pos >= input_len)
				break;
			output[out_pos] = input[in_pos];
			in_pos += 1;
			out_pos += 1;
		}

		if (in_pos < input_len && len < 255) {
			output[out_pos] = 0;
			out_pos += 1;
		}
	}
	
	return out_pos;
}
