// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <crypto/utils.h>
#include "noise.h"

/* This implements Noise_XX:
 *
 * -> e				message "a"
 * <- e, ee, s, es	message "b"
 * -> s, se			message "c"
 */

static const u8 handshake_name[37] __nonstring = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[34] __nonstring = "Ashen v1 jaseg jan@yasec.de";

static void mix_hash(struct noise_handshake_state *st, const u8 *src, size_t src_len)
{
	struct blake2s_ctx blake;

	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, st->ss.hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, st->ss.hash);
}

void noise_init(struct noise_state *st, bool i_am_the_initiator)
{
	memzero_explicit(st, sizeof(*st));
	st->hs.i_am_the_initiator = i_am_the_initiator;

	blake2s(NULL, 0, handshake_name, sizeof(handshake_name),
		st->hs.ss.chaining_key, NOISE_HASH_LEN);
	memcpy(st->hs.ss.hash, st->hs.ss.chaining_key, NOISE_HASH_LEN);
	mix_hash(&st->hs, identifier_name, sizeof(identifier_name));
}

bool noise_keypair_generate(struct noise_keypair *kp)
{
	BUG_ON(kp->has_key);

	if (!curve25519_generate_secret(kp->private))
		return false;
	if (!curve25519_generate_public(kp->public, kp->private))
		return false;
	kp->has_key = true;
	return true;
}

static void hmac(u8 out[static NOISE_HASH_LEN], const u8 *in, size_t inlen,
		const u8 key[static NOISE_HASH_LEN])
{
	struct blake2s_ctx blake;
	u8 x_key[BLAKE2S_BLOCK_SIZE] __aligned(__alignof__(u32)) = {0};
	int i;

	memcpy(x_key, key, NOISE_HASH_LEN);
	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x36;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&blake, in, inlen);
	blake2s_final(&blake, out);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x5c ^ 0x36; /* remove ipad, add opad */

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&blake, out, NOISE_HASH_LEN);
	blake2s_final(&blake, out);

	memzero_explicit(x_key, sizeof(x_key));
}

static void hkdf2(u8 output1[static NOISE_HASH_LEN], u8 output2[static NOISE_HASH_LEN],
		const u8 *input, size_t input_len,
		const u8 chaining_key[static NOISE_HASH_LEN])
{
	u8 output[NOISE_HASH_LEN + 1];
	u8 temp_key[NOISE_HASH_LEN];

	/* Extract */
	hmac(temp_key, input, input_len, chaining_key);

	/* Expand output1 = hmac(0x01) */
	output[0] = 1;
	hmac(output, output, 1, temp_key);
	memcpy(output1, output, NOISE_HASH_LEN);

	/* Expand output2 = hmac(output1 || 0x02) */
	output[NOISE_HASH_LEN] = 2;
	hmac(output2, output, NOISE_HASH_LEN + 1, temp_key);

	memzero_explicit(temp_key, sizeof(temp_key));
	memzero_explicit(output, sizeof(output));
}

static void __maybe_unused hkdf3(u8 output1[static NOISE_HASH_LEN], u8 output2[static NOISE_HASH_LEN],
		u8 output3[static NOISE_HASH_LEN],
		const u8 *input, size_t input_len,
		const u8 chaining_key[static NOISE_HASH_LEN])
{
	u8 output[NOISE_HASH_LEN + 1];
	u8 temp_key[NOISE_HASH_LEN];

	/* Extract */
	hmac(temp_key, input, input_len, chaining_key);

	/* Expand output1 = hmac(0x01) */
	output[0] = 1;
	hmac(output, output, 1, temp_key);
	memcpy(output1, output, NOISE_HASH_LEN);

	/* Expand output2 = hmac(output1 || 0x02) */
	output[NOISE_HASH_LEN] = 2;
	hmac(output, output, NOISE_HASH_LEN + 1, temp_key);
	memcpy(output2, output, NOISE_HASH_LEN);

	/* Expand output3 = hmac(output2 || 0x03) */
	output[NOISE_HASH_LEN] = 3;
	hmac(output3, output, NOISE_HASH_LEN + 1, temp_key);

	memzero_explicit(temp_key, sizeof(temp_key));
	memzero_explicit(output, sizeof(output));
}

static bool __must_check mix_key_dh(struct noise_handshake_state *st,
		const struct noise_keypair *local, const struct noise_pubkey *remote)
{
	u8 dh_out[NOISE_PUBLIC_KEY_LEN];

	BUG_ON(!local->has_key);
	BUG_ON(!remote->has_key);

	if (unlikely(!curve25519(dh_out, local->private, remote->public))) {
		memzero_explicit(dh_out, sizeof(dh_out));
		return false;
	}

	static_assert(NOISE_SYMMETRIC_KEY_LEN == NOISE_HASH_LEN);
	hkdf2(st->ss.chaining_key, st->ss.cs.key,
			dh_out, sizeof(dh_out), st->ss.chaining_key);
	st->ss.cs.counter = 0;
	st->ss.cs.has_key = true;

	memzero_explicit(dh_out, sizeof(dh_out));
	return true;
}

static void encrypt_and_hash(struct noise_handshake_state *st, u8 *data, size_t plain_len)
{
	chacha20poly1305_encrypt(data, data, plain_len, st->ss.hash, NOISE_HASH_LEN,
			0 /* nonce is zero during the handshake */, st->ss.cs.key);
	mix_hash(st, data, plain_len + NOISE_MAC_LEN);
}

static bool __must_check decrypt_and_hash(struct noise_handshake_state *st,
		u8 *out, const u8 *in, size_t cipher_len)
{
	if (!chacha20poly1305_decrypt(out, in, cipher_len, st->ss.hash, NOISE_HASH_LEN,
			0 /* nonce is zero during the handshake */, st->ss.cs.key))
		return false;
	mix_hash(st, in, cipher_len);
	return true;
}

ssize_t noise_handshake_write_msg_a(struct noise_handshake_state *st,
		u8 out[static NOISE_PUBLIC_KEY_LEN])
{
	if (!noise_keypair_generate(&st->loc_ephem))
		return -EINVAL;

	memcpy(out, st->loc_ephem.public, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, out, NOISE_PUBLIC_KEY_LEN);
	/* We still need to advance the hash ratchet even if we have no data to
	 * mix in */
	mix_hash(st, NULL, 0);
	return NOISE_PUBLIC_KEY_LEN;
}

bool noise_handshake_read_msg_a(struct noise_handshake_state *st,
		const u8 in[static NOISE_PUBLIC_KEY_LEN])
{
	memcpy(st->rem_ephem.public, in, NOISE_PUBLIC_KEY_LEN);
	st->rem_ephem.has_key = true;

	mix_hash(st, in, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, NULL, 0);
	return true;
}

ssize_t noise_handshake_write_msg_b(struct noise_handshake_state *st,
		u8 out[static 2 * NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN])
{
	BUG_ON(!st->rem_ephem.has_key);
	BUG_ON(!st->loc_static.has_key);

	if (!noise_keypair_generate(&st->loc_ephem))
		return -EIO;

	/* e */
	memcpy(out, st->loc_ephem.public, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, out, NOISE_PUBLIC_KEY_LEN);

	/* ee */
	if (!mix_key_dh(st, &st->loc_ephem, &st->rem_ephem))
		return -EINVAL;

	/* s */
	memcpy(out + NOISE_PUBLIC_KEY_LEN, st->loc_static.public, NOISE_PUBLIC_KEY_LEN);
	encrypt_and_hash(st, out + NOISE_PUBLIC_KEY_LEN, NOISE_PUBLIC_KEY_LEN);

	/* es */
	if (!mix_key_dh(st, &st->loc_static, &st->rem_ephem))
		return -EINVAL;
	return 2 * NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN;
}

bool noise_handshake_read_msg_b(struct noise_handshake_state *st,
		const u8 in[static 2 * NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN])
{
	/* e */
	memcpy(st->rem_ephem.public, in, NOISE_PUBLIC_KEY_LEN);
	st->rem_ephem.has_key = true;
	mix_hash(st, in, NOISE_PUBLIC_KEY_LEN);

	/* ee */
	if (!mix_key_dh(st, &st->loc_ephem, &st->rem_ephem))
		return false;

	/* s */
	if (!decrypt_and_hash(st, st->rem_static.public, in + NOISE_PUBLIC_KEY_LEN,
			NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN))
		return false;
	st->rem_static.has_key = true;

	/* es */
	if (!mix_key_dh(st, &st->loc_ephem, &st->rem_static))
		return false;
	return true;
}

ssize_t noise_handshake_write_msg_c(struct noise_handshake_state *st,
		u8 out[static NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN])
{
	BUG_ON(!st->loc_static.has_key);
	BUG_ON(!st->rem_ephem.has_key);

	/* s */
	memcpy(out, st->loc_static.public, NOISE_PUBLIC_KEY_LEN);
	encrypt_and_hash(st, out, NOISE_PUBLIC_KEY_LEN);

	/* se */
	if (!mix_key_dh(st, &st->loc_static, &st->rem_ephem))
		return -EINVAL;
	return NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN;
}

bool noise_handshake_read_msg_c(struct noise_handshake_state *st,
		const u8 in[static NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN])
{
	/* s */
	if (!decrypt_and_hash(st, st->rem_static.public, in,
			NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN))
		return false;
	st->rem_static.has_key = true;

	/* se */
	if (!mix_key_dh(st, &st->loc_ephem, &st->rem_static))
		return false;
	return true;
}

static void noise_handshake_split(struct noise_state *st)
{
	if (st->hs.i_am_the_initiator)
		hkdf2(st->send.cs.key, st->recv.cs.key, NULL, 0, st->hs.ss.chaining_key);
	else
		hkdf2(st->recv.cs.key, st->send.cs.key, NULL, 0, st->hs.ss.chaining_key);

	st->send.cs.counter = 0;
	st->send.cs.has_key = true;
	st->recv.cs.counter = 0;
	st->recv.cs.has_key = true;

	memzero_explicit(&st->hs.ss, sizeof(st->hs.ss));
	memzero_explicit(&st->hs.loc_ephem, sizeof(st->hs.loc_ephem));
	memzero_explicit(&st->hs.rem_ephem, sizeof(st->hs.rem_ephem));
}

static void rekey(struct noise_cipher_state *cs)
{
	u8 ciphertext[NOISE_SYMMETRIC_KEY_LEN + NOISE_MAC_LEN];
	u8 zeros[32] = {0};

	chacha20poly1305_encrypt(ciphertext, zeros, sizeof(zeros), NULL, 0,
			U64_MAX, cs->key);
	memcpy(cs->key, ciphertext, NOISE_SYMMETRIC_KEY_LEN);
}

bool noise_decrypt_transport_message(struct noise_state *st,
		const u8 *in, size_t in_len, u8 *out)
{
	BUG_ON(!st->recv.cs.has_key);
	if (!chacha20poly1305_decrypt(out, in, in_len, NULL, 0,
				st->recv.cs.counter, st->recv.cs.key))
		return false;
	st->recv.cs.counter ++;
	rekey(&st->recv.cs);
	return true;
}

void noise_encrypt_transport_message(struct noise_state *st,
		const u8 *in, size_t in_len, u8 *out)
{
	BUG_ON(!st->recv.cs.has_key);
	chacha20poly1305_encrypt(out, in, in_len, NULL, 0,
			st->send.cs.counter, st->send.cs.key);
	st->send.cs.counter ++;
	rekey(&st->send.cs);
}

static ssize_t noise_handshake_initiator(struct noise_state *st,
	const u8 *in, size_t in_len, u8 out[static NOISE_MAX_HS_MSG_LEN])
{
	switch(st->hs.message_count) {
		case 0:
			return noise_handshake_write_msg_a(&st->hs, out);
		case 1:
			if (in_len != 2 * NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN)
				return -EINVAL;
			noise_handshake_read_msg_b(&st->hs, in);
			return noise_handshake_write_msg_c(&st->hs, out);
		case 2:
			noise_handshake_split(st);
			return 0;
		default:
			return -EINVAL;
	}
}

static ssize_t noise_handshake_responder(struct noise_state *st,
	const u8 *in, size_t in_len, u8 out[static NOISE_MAX_HS_MSG_LEN])
{
	switch(st->hs.message_count) {
	case 0:
		if (in_len != NOISE_PUBLIC_KEY_LEN)
			return -EINVAL;
		noise_handshake_read_msg_a(&st->hs, in);
		return noise_handshake_write_msg_b(&st->hs, out);
	case 1:
		if (in_len != NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN)
			return -EINVAL;
		noise_handshake_read_msg_c(&st->hs, in);
		return noise_handshake_write_msg_c(&st->hs, out);
	case 2:
		noise_handshake_split(st);
		return 0;
	default:
		return -EINVAL;
	}
}

ssize_t noise_handshake(struct noise_state *st, const u8 *in, size_t in_len,
		u8 out[static NOISE_MAX_HS_MSG_LEN])
{
	ssize_t ret = -EINVAL;
	if (st->hs.i_am_the_initiator)
		ret = noise_handshake_initiator(st, in, in_len, out);
	else
		ret = noise_handshake_responder(st, in, in_len, out);

	if (ret < 0) {
		memzero_explicit(&st->hs.ss, sizeof(st->hs.ss));
		memzero_explicit(&st->hs.loc_ephem, sizeof(st->hs.loc_ephem));
		memzero_explicit(&st->hs.rem_static, sizeof(st->hs.rem_static));
		memzero_explicit(&st->hs.rem_ephem, sizeof(st->hs.rem_ephem));
		st->hs.message_count = 0;
	} else {
		st->hs.message_count ++;
	}
	return ret;
}
