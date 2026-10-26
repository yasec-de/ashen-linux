/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef _ASHEN_PROTO_H
#define _ASHEN_PROTO_H

#include <linux/types.h>

enum ashen_msg_type {
	ASHEN_MSG_NONE = 0,
	ASHEN_MSG_LOG = 1,
	ASHEN_MSG_ERASE = 2,
	ASHEN_MSG_PAIR_REQUEST = 3,
	ASHEN_MSG_PAIR_RESPONSE = 4,
	ASHEN_MSG_STATUS_REQUEST = 5,
	ASHEN_MSG_STATUS_RESPONSE = 6,
	ASHEN_MSG_DISCONNECT = 7,
	ASHEN_MSG_ECHO_REQUEST = 8,
	ASHEN_MSG_ECHO_RESPONSE = 9,
	ASHEN_MSG_TPM_COMMAND = 10,
	ASHEN_MSG_TPM_RESPONSE = 11,
};

#define ASHEN_MAX_PAYLOAD_LEN 512
#define ASHEN_MAX_FRAME_LEN (ASHEN_MAX_PAYLOAD_LEN + ASHEN_MAX_PAYLOAD_LEN / 254 + 2)

#define ASHEN_TPM_FLAG_MORE 0x01
#define ASHEN_TPM_CHUNK_LEN (ASHEN_MAX_PAYLOAD_LEN - 16 - 2)

/* Wire packet format */
struct ashen_msg_log {
	u8 type;
	u8 data[];
} __packed;

struct ashen_msg_pair_response {
	u8 type;
	u8 success;
} __packed;

struct ashen_msg_status_response {
	u8 type;
	u8 peer_trusted;
	u8 is_keyed;
} __packed;

struct ashen_msg_echo {
	u8 type; /* ASHEN_MSG_ECHO_REQUEST or ASHEN_MSG_ECHO_RESPONSE */
	__be64 value;
} __packed;

struct ashen_msg_tpm {
	u8 type;
	u8 flags;
	u8 data[];
} __packed;

#endif /* _ASHEN_PROTO_H */
