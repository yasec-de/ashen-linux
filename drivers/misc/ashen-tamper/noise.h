/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef _ASHEN_NOISE_H
#define _ASHEN_NOISE_H

#include <linux/types.h>
#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/poly1305.h>
#include <crypto/sha2.h>

enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_PRIVATE_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_HASH_LEN = SHA256_DIGEST_SIZE,
	NOISE_MAC_LEN = POLY1305_DIGEST_SIZE,
	NOISE_MAX_HS_MSG_LEN = 2 * NOISE_PUBLIC_KEY_LEN + 2 * NOISE_MAC_LEN,
};

struct noise_keypair {
	u8 public[NOISE_PUBLIC_KEY_LEN];
	u8 private[NOISE_PRIVATE_KEY_LEN];
	bool has_key;
};

struct noise_pubkey {
	u8 public[NOISE_PUBLIC_KEY_LEN];
	bool has_key;
};

struct noise_cipher_state {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u64 counter;
	bool has_key;
};

struct noise_symmetric_state {
	struct noise_cipher_state cs;
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash[NOISE_HASH_LEN];
};

struct noise_handshake_state {
	struct noise_symmetric_state ss;
	struct noise_keypair loc_static;
	struct noise_keypair loc_ephem;
	struct noise_pubkey rem_static;
	struct noise_pubkey rem_ephem;
	bool i_am_the_initiator;
	int message_count;
};

struct noise_state {
	struct noise_handshake_state hs;
	struct noise_symmetric_state send;
	struct noise_symmetric_state recv;
};

void noise_init(struct noise_state *st, bool i_am_the_initiator);
bool noise_keypair_generate(struct noise_keypair *kp);

ssize_t noise_handshake_write_msg_a(struct noise_handshake_state *st,
		u8 out[static NOISE_PUBLIC_KEY_LEN]);
bool noise_handshake_read_msg_a(struct noise_handshake_state *st,
		const u8 in[static NOISE_PUBLIC_KEY_LEN]);

ssize_t noise_handshake_write_msg_b(struct noise_handshake_state *st,
		u8 out[static 2 * NOISE_PUBLIC_KEY_LEN + 2 * NOISE_MAC_LEN]);
bool noise_handshake_read_msg_b(struct noise_handshake_state *st,
		const u8 in[static 2 * NOISE_PUBLIC_KEY_LEN + 2 * NOISE_MAC_LEN]);

ssize_t noise_handshake_write_msg_c(struct noise_handshake_state *st,
		u8 out[static NOISE_PUBLIC_KEY_LEN + 2 * NOISE_MAC_LEN]);
bool noise_handshake_read_msg_c(struct noise_handshake_state *st,
		const u8 in[static NOISE_PUBLIC_KEY_LEN + 2 * NOISE_MAC_LEN]);

ssize_t noise_handshake(struct noise_state *st, const u8 *in, size_t in_len,
		u8 out[static NOISE_MAX_HS_MSG_LEN], bool *done);

bool noise_decrypt_transport_message(struct noise_state *st,
		const u8 *in, size_t in_len,
		u8 *out);
void noise_encrypt_transport_message(struct noise_state *st,
		const u8 *in, size_t in_len,
		u8 *out);

#endif /* _ASHEN_NOISE_H */
