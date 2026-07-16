// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <kunit/test.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include "cobs.h"
#include "noise.h"
#include "framing.h"

/* ---- COBS ---- */

static void test_cobs_roundtrip(struct kunit *test)
{
	static const struct {
		const char *name;
		u8 data[300];
		size_t len;
	} vecs[] = {
		{ "empty",       {},               0 },
		{ "single-zero", { 0 },         1 },
		{ "all-zeros",   { 0 },            8 }, /* 8 zero bytes */
		{ "no-zeros",    { 1, 2, 3, 4, 5 }, 5 },
		{ "mixed",       { 0, 1, 0, 2, 3, 0, 0, 4 }, 8 },
	};
	u8 enc[512];
	u8 dec[512];
	int i;

	for (i = 0; i < ARRAY_SIZE(vecs); i++) {
		ssize_t elen = cobs_encode(vecs[i].data, vecs[i].len,
				enc, sizeof(enc));
		ssize_t dlen;

		KUNIT_ASSERT_GE_MSG(test, elen, 0, "%s: encode failed",
				vecs[i].name);
		KUNIT_ASSERT_EQ(test, enc[elen - 1], 0); /* remove null */
		dlen = cobs_decode(enc, elen - 1, dec, sizeof(dec));
		KUNIT_ASSERT_GE_MSG(test, dlen, 0, "%s: decode failed",
				vecs[i].name);
		KUNIT_EXPECT_EQ_MSG(test, dlen, vecs[i].len,
				"%s: length mismatch", vecs[i].name);
		KUNIT_EXPECT_MEMEQ_MSG(test, dec, vecs[i].data, vecs[i].len,
				"%s: payload mismatch", vecs[i].name);
	}
}

/* 254-byte non-zero run forces a 0xFF index block in the encoder. */
static void test_cobs_long_run(struct kunit *test)
{
	u8 data[300];
	u8 enc[512];
	u8 dec[512];
	ssize_t elen, dlen;
	int i;

	for (i = 0; i < 254; i++)
		data[i] = (i % 255) + 1; /* never zero */

	elen = cobs_encode(data, 254, enc, sizeof(enc));
	KUNIT_ASSERT_GE(test, elen, 0);
	dlen = cobs_decode(enc, elen - 1, dec, sizeof(dec));
	KUNIT_ASSERT_EQ(test, dlen, 254);
	KUNIT_EXPECT_MEMEQ(test, dec, data, 254);
}

static void test_cobs_decode_errors(struct kunit *test)
{
	u8 out[64];

	/* empty input */
	KUNIT_EXPECT_EQ(test, cobs_decode(out, 0, out, sizeof(out)), -EINVAL);

	{
		/* index byte promises 5 payload bytes but only 2 follow */
		u8 trunc[] = { 6, 1, 2 };
		KUNIT_EXPECT_EQ(test,
				cobs_decode(trunc, sizeof(trunc), out, sizeof(out)),
				-EINTR);
	}
}

static void test_cobs_encode_overflow(struct kunit *test)
{
	u8 data[] = { 1, 2, 3, 4, 5 };
	u8 tiny[3];

	KUNIT_EXPECT_EQ(test, cobs_encode(data, sizeof(data), tiny, sizeof(tiny)),
			-1);
}

/* ---- Noise ---- */

static void do_handshake(struct kunit *test, struct noise_state *ini,
		struct noise_state *resp)
{
	u8 msg_a[NOISE_MAX_HS_MSG_LEN];
	u8 msg_b[NOISE_MAX_HS_MSG_LEN];
	u8 msg_c[NOISE_MAX_HS_MSG_LEN];
	ssize_t la, lb, lc, lr;
	bool done;

	noise_init(ini, true);
	noise_init(resp, false);

	KUNIT_ASSERT_TRUE(test, noise_keypair_generate(&ini->hs.loc_static));
	KUNIT_ASSERT_TRUE(test, noise_keypair_generate(&resp->hs.loc_static));

	/* -> e (msg a), initiator writes, ignores input */
	la = noise_handshake(ini, NULL, 0, msg_a, &done);
	KUNIT_ASSERT_GT(test, la, 0);
	KUNIT_ASSERT_FALSE(test, done);

	/* responder reads a, writes b */
	lb = noise_handshake(resp, msg_a, la, msg_b, &done);
	KUNIT_ASSERT_GT(test, lb, 0);
	KUNIT_ASSERT_FALSE(test, done);

	/* initiator reads b, writes c, and is done */
	lc = noise_handshake(ini, msg_b, lb, msg_c, &done);
	KUNIT_ASSERT_GT(test, lc, 0);
	KUNIT_ASSERT_TRUE(test, done);

	/* responder reads c, is done, no reply */
	lr = noise_handshake(resp, msg_c, lc, msg_b, &done);
	KUNIT_ASSERT_EQ(test, lr, 0);
	KUNIT_ASSERT_TRUE(test, done);
}

static void test_handshake_completes(struct kunit *test)
{
	struct noise_state *ini = kunit_kzalloc(test, sizeof(*ini), GFP_KERNEL);
	struct noise_state *resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, ini);
	KUNIT_ASSERT_NOT_NULL(test, resp);

	do_handshake(test, ini, resp);

	KUNIT_EXPECT_TRUE(test, ini->send.cs.has_key);
	KUNIT_EXPECT_TRUE(test, ini->recv.cs.has_key);
	KUNIT_EXPECT_TRUE(test, resp->send.cs.has_key);
	KUNIT_EXPECT_TRUE(test, resp->recv.cs.has_key);
}

static void test_transport_roundtrip(struct kunit *test)
{
	struct noise_state *ini = kunit_kzalloc(test, sizeof(*ini), GFP_KERNEL);
	struct noise_state *resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	u8 pt[32], ct[32 + NOISE_MAC_LEN], out[32];
	int i;

	KUNIT_ASSERT_NOT_NULL(test, ini);
	KUNIT_ASSERT_NOT_NULL(test, resp);
	do_handshake(test, ini, resp);

	for (i = 0; i < 4; i++) {
		memset(pt, 0xA0 + i, sizeof(pt));

		/* initiator -> responder */
		noise_encrypt_transport_message(ini, pt, sizeof(pt), ct);
		KUNIT_ASSERT_TRUE(test,
			noise_decrypt_transport_message(resp, ct, sizeof(ct), out));
		KUNIT_EXPECT_MEMEQ(test, out, pt, sizeof(pt));

		/* responder -> initiator */
		memset(pt, 0x50 + i, sizeof(pt));
		noise_encrypt_transport_message(resp, pt, sizeof(pt), ct);
		KUNIT_ASSERT_TRUE(test,
			noise_decrypt_transport_message(ini, ct, sizeof(ct), out));
		KUNIT_EXPECT_MEMEQ(test, out, pt, sizeof(pt));
	}
}

static void test_transport_tamper(struct kunit *test)
{
	struct noise_state *ini = kunit_kzalloc(test, sizeof(*ini), GFP_KERNEL);
	struct noise_state *resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	u8 pt[16], ct[16 + NOISE_MAC_LEN], out[16];

	KUNIT_ASSERT_NOT_NULL(test, ini);
	KUNIT_ASSERT_NOT_NULL(test, resp);
	do_handshake(test, ini, resp);

	memset(pt, 0x42, sizeof(pt));
	noise_encrypt_transport_message(ini, pt, sizeof(pt), ct);
	ct[0] ^= 0x01; /* flip a ciphertext bit */
	KUNIT_EXPECT_FALSE(test,
		noise_decrypt_transport_message(resp, ct, sizeof(ct), out));
}

static void test_handshake_rejects_bad_msg(struct kunit *test)
{
	struct noise_state *ini = kunit_kzalloc(test, sizeof(*ini), GFP_KERNEL);
	struct noise_state *resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	u8 msg_a[NOISE_MAX_HS_MSG_LEN];
	u8 msg_b[NOISE_MAX_HS_MSG_LEN];
	u8 msg_c[NOISE_MAX_HS_MSG_LEN];
	ssize_t la, lb;
	bool done;

	KUNIT_ASSERT_NOT_NULL(test, ini);
	KUNIT_ASSERT_NOT_NULL(test, resp);

	noise_init(ini, true);
	noise_init(resp, false);
	KUNIT_ASSERT_TRUE(test, noise_keypair_generate(&ini->hs.loc_static));
	KUNIT_ASSERT_TRUE(test, noise_keypair_generate(&resp->hs.loc_static));

	la = noise_handshake(ini, NULL, 0, msg_a, &done);
	KUNIT_ASSERT_GT(test, la, 0);
	lb = noise_handshake(resp, msg_a, la, msg_b, &done);
	KUNIT_ASSERT_GT(test, lb, 0);

	/* corrupt the encrypted static-key part of msg b: auth must fail */
	msg_b[NOISE_PUBLIC_KEY_LEN] ^= 0x01;
	KUNIT_EXPECT_LT(test, noise_handshake(ini, msg_b, lb, msg_c, &done), 0);
	KUNIT_EXPECT_EQ(test, ini->hs.message_count, 0);
}

/* ---- Framing ---- */

#define FRAMER_CAP 256

struct captured {
	struct kunit *test;
	int count;
	size_t len[8];
	u8 data[8][FRAMER_CAP];
};

static void capture_frame(void *ctx, const u8 *frame, size_t len)
{
	struct captured *c = ctx;

	if (c->count >= ARRAY_SIZE(c->len)) {
		KUNIT_FAIL(c->test, "too many frames captured");
		return;
	}
	KUNIT_ASSERT_LE(c->test, len, (size_t)FRAMER_CAP);
	c->len[c->count] = len;
	memcpy(c->data[c->count], frame, len);
	c->count++;
}

static struct ashen_framer *make_framer(struct kunit *test, struct captured *cap)
{
	struct ashen_framer *f = kunit_kzalloc(test,
			struct_size(f, buf, FRAMER_CAP), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, f);
	f->cap = FRAMER_CAP;
	f->on_frame = capture_frame;
	f->ctx = cap;
	return f;
}

static void sync_framer(struct ashen_framer *f)
{
	u8 nulls[FRAMER_SYNC_NULLS] = {0};

	ashen_framer_push(f, nulls, sizeof(nulls));
}

/* COBS-encode payload into wire (delimiter-terminated), return wire length. */
static size_t make_wire(struct kunit *test, const u8 *payload, size_t plen,
		u8 *wire, size_t wire_cap)
{
	ssize_t n = cobs_encode(payload, plen, wire, wire_cap);

	KUNIT_ASSERT_GE(test, n, 0);
	return n; /* includes the trailing 0x00 delimiter */
}

static void test_framer_single_frame(struct kunit *test)
{
	struct captured *cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	struct ashen_framer *f;
	u8 payload[] = { 1, 0, 2, 3, 0, 4 };
	u8 wire[64];
	size_t wlen;

	KUNIT_ASSERT_NOT_NULL(test, cap);
	cap->test = test;
	f = make_framer(test, cap);
	sync_framer(f);
	wlen = make_wire(test, payload, sizeof(payload), wire, sizeof(wire));

	KUNIT_EXPECT_EQ(test, ashen_framer_push(f, wire, wlen), wlen);
	KUNIT_ASSERT_EQ(test, cap->count, 1);
	KUNIT_EXPECT_EQ(test, cap->len[0], sizeof(payload));
	KUNIT_EXPECT_MEMEQ(test, cap->data[0], payload, sizeof(payload));
}

static void test_framer_chunked(struct kunit *test)
{
	struct captured *cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	struct ashen_framer *f;
	u8 p1[] = { 5, 6, 0, 7 };
	u8 p2[] = { 0, 8, 9 };
	u8 wire[128];
	size_t w1, w2, total, i;

	KUNIT_ASSERT_NOT_NULL(test, cap);
	cap->test = test;
	f = make_framer(test, cap);
	sync_framer(f);

	/* two frames back to back in one buffer */
	w1 = make_wire(test, p1, sizeof(p1), wire, sizeof(wire));
	w2 = make_wire(test, p2, sizeof(p2), wire + w1, sizeof(wire) - w1);
	total = w1 + w2;

	/* test reassembly by pushing byte by byte */
	for (i = 0; i < total; i++)
		KUNIT_EXPECT_EQ(test, ashen_framer_push(f, wire + i, 1), 1);

	KUNIT_ASSERT_EQ(test, cap->count, 2);
	KUNIT_EXPECT_EQ(test, cap->len[0], sizeof(p1));
	KUNIT_EXPECT_MEMEQ(test, cap->data[0], p1, sizeof(p1));
	KUNIT_EXPECT_EQ(test, cap->len[1], sizeof(p2));
	KUNIT_EXPECT_MEMEQ(test, cap->data[1], p2, sizeof(p2));
}

static void test_framer_overrun(struct kunit *test)
{
	struct captured *cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	struct ashen_framer *f;
	u8 junk[FRAMER_CAP + 16];
	u8 payload[] = { 1, 2, 3 };
	u8 wire[32];
	size_t wlen;

	KUNIT_ASSERT_NOT_NULL(test, cap);
	cap->test = test;
	f = make_framer(test, cap);
	sync_framer(f);

	/* junk with no delimiter fills the buffer past cap: overrun drops it
	 * and knocks the framer back out of sync */
	memset(junk, 0xFF, sizeof(junk));
	ashen_framer_push(f, junk, sizeof(junk));
	KUNIT_EXPECT_EQ(test, cap->count, 0);
	KUNIT_EXPECT_FALSE(test, f->sync);

	sync_framer(f);
	wlen = make_wire(test, payload, sizeof(payload), wire, sizeof(wire));
	ashen_framer_push(f, wire, wlen);
	KUNIT_ASSERT_EQ(test, cap->count, 1);
	KUNIT_EXPECT_MEMEQ(test, cap->data[0], payload, sizeof(payload));
}

static void test_framer_truncated(struct kunit *test)
{
	struct captured *cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	struct ashen_framer *f;
	/* index byte claims 6 payload bytes, only 2 present, then delimiter */
	u8 wire[] = { 6, 1, 2, 0x00 };

	KUNIT_ASSERT_NOT_NULL(test, cap);
	cap->test = test;
	f = make_framer(test, cap);
	sync_framer(f);

	ashen_framer_push(f, wire, sizeof(wire));
	KUNIT_EXPECT_EQ(test, cap->count, 0); /* dropped, no frame delivered */
}

/* The device answers our 32-null reset with >= 8 nulls of its own. Pushing that
 * run must not deliver bogus frames, and must leave the framer aligned for the
 * device's first real frame -- even with garbage buffered from the dead session. */
static void test_framer_resync_on_null_run(struct kunit *test)
{
	struct captured *cap = kunit_kzalloc(test, sizeof(*cap), GFP_KERNEL);
	struct ashen_framer *f;
	u8 garbage[] = { 9, 0xAA, 0xBB }; /* partial frame, no delimiter */
	u8 nulls[8] = {0};
	u8 payload[] = { 1, 2, 3, 0, 4 };
	u8 wire[32];
	size_t wlen;

	KUNIT_ASSERT_NOT_NULL(test, cap);
	cap->test = test;
	f = make_framer(test, cap);

	ashen_framer_push(f, garbage, sizeof(garbage));
	ashen_framer_push(f, nulls, sizeof(nulls));

	/* the truncated garbage is dropped, and the null run itself is not a frame */
	KUNIT_EXPECT_EQ(test, cap->count, 0);
	KUNIT_EXPECT_EQ(test, f->len, (size_t)0);

	wlen = make_wire(test, payload, sizeof(payload), wire, sizeof(wire));
	ashen_framer_push(f, wire, wlen);

	KUNIT_ASSERT_EQ(test, cap->count, 1);
	KUNIT_EXPECT_EQ(test, cap->len[0], sizeof(payload));
	KUNIT_EXPECT_MEMEQ(test, cap->data[0], payload, sizeof(payload));
}

/* A restart re-runs noise_init() + keygen on an already-keyed state. Getting the
 * order wrong trips BUG_ON(kp->has_key) in noise_keypair_generate() and takes the
 * kernel down, so pin the sequence the driver's restart path uses. */
static void test_handshake_restart_rekeys(struct kunit *test)
{
	struct noise_state *ini = kunit_kzalloc(test, sizeof(*ini), GFP_KERNEL);
	struct noise_state *resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	u8 first_static[NOISE_PUBLIC_KEY_LEN];

	KUNIT_ASSERT_NOT_NULL(test, ini);
	KUNIT_ASSERT_NOT_NULL(test, resp);

	do_handshake(test, ini, resp);
	memcpy(first_static, ini->hs.loc_static.public, sizeof(first_static));

	/* Restart on the same, already-keyed states. */
	do_handshake(test, ini, resp);

	KUNIT_EXPECT_TRUE(test, ini->send.cs.has_key);
	KUNIT_EXPECT_TRUE(test, resp->recv.cs.has_key);
	/* fresh static keypair per handshake is intentional here */
	KUNIT_EXPECT_MEMNEQ(test, ini->hs.loc_static.public, first_static,
			sizeof(first_static));
}

/* ---- end to end ---- */

static void test_e2e_two_instances(struct kunit *test)
{
	struct noise_state *ini = kunit_kzalloc(test, sizeof(*ini), GFP_KERNEL);
	struct noise_state *resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	struct captured *cap_r = kunit_kzalloc(test, sizeof(*cap_r), GFP_KERNEL);
	struct captured *cap_i = kunit_kzalloc(test, sizeof(*cap_i), GFP_KERNEL);
	struct ashen_framer *f_resp, *f_ini;
	u8 pt[24], ct[24 + NOISE_MAC_LEN], wire[64];
	size_t wlen;
	int i;

	KUNIT_ASSERT_NOT_NULL(test, ini);
	KUNIT_ASSERT_NOT_NULL(test, resp);
	KUNIT_ASSERT_NOT_NULL(test, cap_r);
	KUNIT_ASSERT_NOT_NULL(test, cap_i);
	cap_r->test = test;
	cap_i->test = test;
	f_resp = make_framer(test, cap_r); /* receives on the responder side */
	f_ini = make_framer(test, cap_i);  /* receives on the initiator side */
	sync_framer(f_resp);
	sync_framer(f_ini);

	do_handshake(test, ini, resp);

	for (i = 0; i < 3; i++) {
		/* initiator sends: encrypt -> cobs -> responder's framer */
		memset(pt, 0x10 + i, sizeof(pt));
		noise_encrypt_transport_message(ini, pt, sizeof(pt), ct);
		wlen = make_wire(test, ct, sizeof(ct), wire, sizeof(wire));
		ashen_framer_push(f_resp, wire, wlen);

		KUNIT_ASSERT_EQ(test, cap_r->count, i + 1);
		/* decrypt the decoded frame on the responder */
		{
			u8 out[sizeof(pt)];
			size_t clen = cap_r->len[i];

			KUNIT_ASSERT_EQ(test, clen, sizeof(ct));
			KUNIT_ASSERT_TRUE(test,
				noise_decrypt_transport_message(resp,
					cap_r->data[i], clen, out));
			KUNIT_EXPECT_MEMEQ(test, out, pt, sizeof(pt));
		}

		/* responder replies, initiator receives */
		memset(pt, 0x90 + i, sizeof(pt));
		noise_encrypt_transport_message(resp, pt, sizeof(pt), ct);
		wlen = make_wire(test, ct, sizeof(ct), wire, sizeof(wire));
		ashen_framer_push(f_ini, wire, wlen);

		KUNIT_ASSERT_EQ(test, cap_i->count, i + 1);
		{
			u8 out[sizeof(pt)];
			size_t clen = cap_i->len[i];

			KUNIT_ASSERT_EQ(test, clen, sizeof(ct));
			KUNIT_ASSERT_TRUE(test,
				noise_decrypt_transport_message(ini,
					cap_i->data[i], clen, out));
			KUNIT_EXPECT_MEMEQ(test, out, pt, sizeof(pt));
		}
	}
}

static struct kunit_case ashen_protocol_test_cases[] = {
	KUNIT_CASE(test_cobs_roundtrip),
	KUNIT_CASE(test_cobs_long_run),
	KUNIT_CASE(test_cobs_decode_errors),
	KUNIT_CASE(test_cobs_encode_overflow),
	KUNIT_CASE(test_handshake_completes),
	KUNIT_CASE(test_transport_roundtrip),
	KUNIT_CASE(test_transport_tamper),
	KUNIT_CASE(test_handshake_rejects_bad_msg),
	KUNIT_CASE(test_handshake_restart_rekeys),
	KUNIT_CASE(test_framer_single_frame),
	KUNIT_CASE(test_framer_chunked),
	KUNIT_CASE(test_framer_overrun),
	KUNIT_CASE(test_framer_truncated),
	KUNIT_CASE(test_framer_resync_on_null_run),
	KUNIT_CASE(test_e2e_two_instances),
	{},
};

static struct kunit_suite ashen_protocol_suite = {
	.name = "ashen-protocol",
	.test_cases = ashen_protocol_test_cases,
};
kunit_test_suite(ashen_protocol_suite);

MODULE_DESCRIPTION("KUnit tests for ashen-tamper protocol");
MODULE_LICENSE("GPL");
