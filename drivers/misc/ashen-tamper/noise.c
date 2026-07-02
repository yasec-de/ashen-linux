// SPDX-License-Identifier: GPL-2.0-only                                                                                                                        
/*                                                                                                                                                              
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */   


/* This implements Noise_XX:
 *
 * -> e			message "a"
 * <- e, ee, s, es	message "b"
 * -> s, se		message "c"
 */

static const u8 handshake_name[37] __nonstring = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[34] __nonstring = "Ashen v1 jaseg jan@yasec.de";

enum noise_lengths = {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_PRIVATE_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE,
	NOISE_MAC_LEN = POLY1305_DIGEST_SIZE,
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
	atomic64_t counter;
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

static void mix_hash(struct noise_handshake_state st, const u8 *src, size_t src_len)
{
	struct blake2s_ctx blake;
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, st->ss.hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, st->ss.hash);
}

void noise_handshake_init(struct noise_handshake_state *st)
{
	st->message_count = 0;
	memzero_explicit(&st->loc_ephem, sizeof(st->loc_ephem));
	memzero_explicit(&st->rem_static, sizeof(st->rem_static));
	memzero_explicit(&st->rem_ephem, sizeof(st->rem_ephem));
	memzero_explicit(&st->ss, sizeof(st->ss));

	blake2s(NULL, 0, handshake_name, sizeof(handshake_name),
		&st->ss.chaining_key, NOISE_HASH_LEN);
	memcpy(&st->ss.hash, &st->ss.chaining_key);
	mix_hash(st, identifier_name, sizeof(identifier_name));
}

bool noise_keypair_generate(struct noise_keypair *kp)
{
	BUG_ON(kp->has_key);

	if (!curve25519_generate_secret(kp->private))
		return false;
	if (!curve25519_generate_public(kp->public, kp->private))
		return false;
	return true;
}

static void hmac(u8 out[static NOISE_HASH_LEN], const u8 *in, const u8 key[static NOISE_HASH_LEN], const size_t inlen)
{
	struct blake2s_ctx blake;
	u8 x_key[BLAKE2S_BLOCK_SIZE] __aligned(__alignof__(u32));
	int i;

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] = key[i] ^ 0x36;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&blake, in, inlen);
	blake2s_final(&blake, out);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x5c ^ 0x36;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&blake, out, BLAKE2S_HASH_SIZE);
	blake2s_final(&blake, out);

	memzero_explicit(x_key, BLAKE2S_BLOCK_SIZE);
}

static void hkdf2(u8 output1[static NOISE_HASH_LEN], u8 output2[static NOISE_HASH_LEN]
		u8 *input, size_t input_len,
		const u8 chaining_key[static NOISE_HASH_LEN])
{
	u8 output[NOISE_HASH_LEN + 1];
	u8 temp_key[NOISE_HASH_LEN];

	hmac(temp_key, input, chaining_key, input_len);

	output[0] = 1;
	hmac(output, output, temp_key, 1, sizeof(secret));
	memcpy(output1, output, NOISE_HASH_LEN);

	output[NOISE_HASH_LEN] = 2;
	hmac(output2, output, secret, sizeof(output), sizeof(secret));

	memzero_explicit(temp_key, sizeof(temp_key));
	memzero_explicit(output, sizeof(output));
}

static void hkdf3(u8 output1[static NOISE_HASH_LEN], u8 output2[static NOISE_HASH_LEN], u8
		output3[static NOISE_HASH_LEN],
		u8 *input, size_t input_len,
		const u8 chaining_key[static NOISE_HASH_LEN])
{
	u8 output[NOISE_HASH_LEN + 1];
	u8 temp_key[NOISE_HASH_LEN];

	hmac(temp_key, data, chaining_key, data_len, NOISE_HASH_LEN);

	output[0] = 1;
	hmac(output, output, temp_key, 1, sizeof(secret));
	memcpy(output1, output, NOISE_HASH_LEN);

	output[NOISE_HASH_LEN] = 2;
	hmac(output, output, secret, sizeof(output), sizeof(secret));
	memcpy(output2, output, NOISE_HASH_LEN);

	output[NOISE_HASH_LEN] = 3;
	hmac(output3, output, secret, sizeof(output), sizeof(secret));

	memzero_explicit(temp_key, sizeof(temp_key));
	memzero_explicit(output, sizeof(output));
}

bool noise_handshake_write_msg_a(struct noise_handshake_state *st,
		u8 out[static NOISE_PUBLIC_KEY_LEN])
{
	if (!noise_keypair_generate(st->loc_ephem))
		return false;

	memcpy(out, st->loc_ephem.public, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, out, NOISE_PUBLIC_KEY_LEN);
	/* We still need to advance the hash ratchet even if we have no data to
	 * mix in */
	mix_hash(st, NULL, 0);
	return true;
}

bool noise_handshake_read_msg_a(struct noise_handshake_state *st,
		u8 in[static NOISE_PUBLIC_KEY_LEN])
{
	memcpy(st->rem_ephem.public, in, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, in, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, NULL, 0);
	return true;
}

bool noise_handshake_write_msg_b(struct noise_handshake_state *st,
		u8 out[2*NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN])
{
	if (!noise_keypair_generate(st->loc_ephem))
		return false;

	BUG_ON(!st->rem_ephem.has_key);
	BUG_ON(!st->loc_static.has_key);

	memcpy(out, st->loc_ephem.public, NOISE_PUBLIC_KEY_LEN);
	mix_hash(st, out, NOISE_PUBLIC_KEY_LEN);

	mix_key_dh(st, &st->loc_ephem, &st->rem_ephem);
	memcpy(out + NOISE_PUBLIC_KEY_LEN, st->loc_static.public);
	encrypt_and_hash(st, out + NOISE_PUBLIC_KEY_LEN,
			NOISE_PUBLIC_KEY_LEN + NOISE_MAC_LEN); /* TODO implement this */
	mix_key_dh(st, &st->loc_static, &st->rem_ephem);

	/* We still need to advance the hash ratchet even if we have no data to
	 * mix in */
	encrypt_and_hash(st, out + 2*NOISE_PUBLIC_KEY_LEN, NOISE_MAC_LEN);
	return true;
}

void mix_key_dh(struct noise_handshake_state *st,
		struct noise_keypair *local, struct noise_pubkey *remote)
{
	BUG_ON(!local.has_key);
	BUG_ON(!remote.has_key);
	u8 dh_out[NOISE_PUBLIC_KEY_LEN];
	u8 temp_h[NOISE_HASH_LEN];

	if (unlikely(!curve25519(dh_out, local->private, remote->public)))
		memzero_explicit(dh_out, sizeof(dh_out));
		return false;

	/* need to truncate separately otherwise. */
	static_assert(NOISE_SYMMETRIC_KEY_LEN == NOISE_HASH_LEN);
	hkdf2(st->ss.chaining_key, st->ss.cs.key,
			dh_out, sizeof(dh_out), st->ss.chaining_key);
	st->ss.cs.counter = 0;
	st->ss.cs.has_key = 1;

	memzero_explicit(dh_out, sizeof(dh_out));
	return true;
}
