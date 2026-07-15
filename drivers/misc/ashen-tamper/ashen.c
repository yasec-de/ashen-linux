// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/serdev.h>
#include <linux/sysfs.h>
#include <linux/overflow.h>
#include "cobs.h"
#include "noise.h"
#include "framing.h"
#include "proto.h"
#include "ashen.h"

#define ASHEN_TAMPER_DEFAULT_BAUDRATE 1000000
#define ASHEN_TAMPER_MAX_BUF_SIZE 8192
#define ASHEN_TAMPER_DEFAULT_TIMEOUT_US 10000
#define ASHEN_TAMPER_DEFAULT_REFRESH_IVL_US 5000
#define ASHEN_TAMPER_SERDEV_TIMEOUT 100 /* jiffies */
#define ASHEN_TAMPER_RX_BUF_SIZE 256

static bool panic_on_error;

/* Encrypt, frame and write one queued request. Sleeps: process context only. */
static int ash_tx_one(struct ashen_tamper *ash, const struct ashen_tx_req *req)
{
	u8 wire[sizeof(ash->tx_buf)];
	size_t clen;
	ssize_t encoded;
	ssize_t ret;

	mutex_lock(&ash->tx_lock);

	if (req->raw) {
		ret = serdev_device_write(ash->serdev, req->payload, req->len,
				ASHEN_TAMPER_SERDEV_TIMEOUT);
		if (ret != req->len)
			ret = ret < 0 ? ret : -EIO;
		else
			ret = 0;
		goto out;
	}

	clen = req->len + NOISE_MAC_LEN;
	if (clen + clen / 254 + 2 > sizeof(wire)) {
		ret = -EMSGSIZE;
		goto out;
	}

	noise_encrypt_transport_message(&ash->noise_st, req->payload, req->len,
			ash->tx_buf);
	encoded = cobs_encode(ash->tx_buf, clen, wire, sizeof(wire));
	if (encoded < 0) {
		ret = -EMSGSIZE;
		goto out;
	}

	ret = serdev_device_write(ash->serdev, wire, encoded,
			ASHEN_TAMPER_SERDEV_TIMEOUT);
	if (ret != encoded)
		ret = ret < 0 ? ret : -EIO;
	else
		ret = 0;

out:
	mutex_unlock(&ash->tx_lock);
	return ret;
}

static void ash_tx_work_fn(struct work_struct *w)
{
	struct ashen_tamper *ash = container_of(w, struct ashen_tamper, tx_work);
	struct ashen_tx_req req;
	unsigned long flags;
	int ret;

	for (;;) {
		spin_lock_irqsave(&ash->tx_queue_lock, flags);
		if (ash->tx_head == ash->tx_tail) {
			spin_unlock_irqrestore(&ash->tx_queue_lock, flags);
			return;
		}
		req = ash->tx_queue[ash->tx_tail % ASHEN_TX_QUEUE_LEN];
		ash->tx_tail++;
		spin_unlock_irqrestore(&ash->tx_queue_lock, flags);

		ret = ash_tx_one(ash, &req);
		if (ret)
			pr_err("ashen-tamper: tx failed: %d\n", ret);
	}
}

/* Queue a message for transmission. Safe from atomic context. */
static int ash_send_req(struct ashen_tamper *ash, const void *msg, size_t len,
		bool raw)
{
	struct ashen_tx_req *slot;
	unsigned long flags;
	int ret = 0;

	if (len > ASHEN_TX_MAX_PAYLOAD)
		return -EMSGSIZE;

	spin_lock_irqsave(&ash->tx_queue_lock, flags);
	if (ash->tx_head - ash->tx_tail >= ASHEN_TX_QUEUE_LEN) {
		ret = -ENOSPC;
		goto out;
	}
	slot = &ash->tx_queue[ash->tx_head % ASHEN_TX_QUEUE_LEN];
	memcpy(slot->payload, msg, len);
	slot->len = len;
	slot->raw = raw;
	ash->tx_head++;
out:
	spin_unlock_irqrestore(&ash->tx_queue_lock, flags);

	if (!ret)
		queue_work(ash->tx_wq, &ash->tx_work);
	return ret;
}

static int ash_send_envelope(struct ashen_tamper *ash,
		const void *msg, size_t len)
{
	return ash_send_req(ash, msg, len, false);
}

static void ashen_continue_handshake(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	u8 hs_msg[NOISE_MAX_HS_MSG_LEN];
	ssize_t ret;
	ssize_t to_write;
	bool done = false;
	u8 type;

	ret = noise_handshake(&ash->noise_st, buf, len, hs_msg, &done);
	if (ret < 0) {
		pr_err("ashen-tamper: noise handshake error\n");
		ash->conn_st = CONN_DISCONNECTED;
		return;
	}
	to_write = ret;

	if (to_write) {
		ret = ash_send_req(ash, hs_msg, to_write, true);
		if (ret) {
			pr_err("ashen-tamper: failed to queue handshake message: %zd\n",
					ret);
			ash->conn_st = CONN_DISCONNECTED;
			return;
		}
	}

	if (done) {
		ash->conn_st = CONN_CONNECTED;
		complete(&ash->connection_ready);
		
		if (ash->autostart) {
			hrtimer_start(&ash->refresh_timer, ash->refresh_ivl, HRTIMER_MODE_REL_HARD);
			hrtimer_start(&ash->hb_timer, ash->refresh_ivl + ash->timeout, HRTIMER_MODE_REL_HARD);
		}

		type = ASHEN_MSG_STATUS_REQUEST;
		ret = ash_send_envelope(ash, &type, sizeof(type));
		if (ret)
			pr_err("ashen-tamper: failed to send status request: %zd\n",
					ret);
	}
}

static void ashen_handle_packet(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	u64 delta_ns;
	if (len < 1) {
		pr_warn("ashen-tamper: empty message\n");
		return;
	}

	switch (buf[0]) {
	case ASHEN_MSG_LOG: {
		const struct ashen_msg_log *msg = (const void *)buf;
		/* msg->data, len - 1 bytes of defmt frame -- TODO */
		(void)msg;
		break;
	}
	case ASHEN_MSG_PAIR_RESPONSE: {
		const struct ashen_msg_pair_response *msg = (const void *)buf;
		u8 type;

		if (len != sizeof(*msg))
			goto malformed;
		pr_info("ashen-tamper: pairing successful\n");

		type = ASHEN_MSG_STATUS_REQUEST;
		ash_send_envelope(ash, &type, sizeof(type));
		break;
	}
	case ASHEN_MSG_STATUS_RESPONSE: {
		const struct ashen_msg_status_response *msg = (const void *)buf;

		if (len != sizeof(*msg))
			goto malformed;
		pr_info("ashen-tamper: status: peer_trusted=%d is_keyed=%d\n",
				msg->peer_trusted, msg->is_keyed);
		break;
	}
	case ASHEN_MSG_ECHO_RESPONSE: {
		const struct ashen_msg_echo *msg = (const void *)buf;

		if (len != sizeof(*msg))
			goto malformed;

		delta_ns = ktime_get_ns() - be64_to_cpu(msg->value);
		if (delta_ns > ktime_to_ns(ash->timeout)) {
			pr_warn("ashen-tamper: received echo response stale by %llu ns", delta_ns);
		} else {
			/* Push the deadline out. hrtimer_forward_now() only
			 * adjusts the expiry of a timer from inside its own
			 * callback; re-arming from here needs hrtimer_start(). */
			hrtimer_start(&ash->hb_timer, ash->timeout,
					HRTIMER_MODE_REL_HARD);
		}
		break;
	}
	case ASHEN_MSG_DISCONNECT:
		if (len != 1)
			goto malformed;
		
		hrtimer_cancel(&ash->refresh_timer);
		hrtimer_cancel(&ash->hb_timer);
		ash->conn_st = CONN_DISCONNECTED;
		break;
	default:
		pr_warn("ashen-tamper: unexpected message type %d\n", buf[0]);
		break;
	}

	complete(&ash->packet_ready);
	return;

malformed:
	pr_warn("ashen-tamper: malformed message type %d\n", buf[0]);
}

static void ashen_receive_packet(void *ctx,
		const u8 *buf, size_t len)
{
	struct ashen_tamper *ash = (struct ashen_tamper *)ctx;
	u8 *frame = (u8 *)buf; /* framer buffer, in-place decrypt is fine */

	switch (ash->conn_st) {
	case CONN_DISCONNECTED:
		pr_warn("ashen-tamper: received out-of-order message from device\n");
		break;
	case CONN_HANDSHAKE:
		ashen_continue_handshake(ash, buf, len);
		break;
	case CONN_CONNECTED:
		if (len < NOISE_MAC_LEN)
			break;
		if (!noise_decrypt_transport_message(&ash->noise_st,
					frame, len, frame))
			break;

		ashen_handle_packet(ash, frame, len - NOISE_MAC_LEN);
		break;
	}
}

static size_t ashen_serdev_receive(struct serdev_device *serdev,
		const u8 *buf, size_t size)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);
	return ashen_framer_push(ash->framer, buf, size);
}

static const struct serdev_device_ops ashen_serdev_ops = {
	.receive_buf = ashen_serdev_receive,
	.write_wakeup = serdev_device_write_wakeup,
};

static const struct of_device_id ashen_tamper_of_match[] = {
	{
	 .compatible = "ashen,hbv1",
	},
	{}
};
MODULE_DEVICE_TABLE(of, ashen_tamper_of_match);

/* Reaching this means no valid echo response re-armed the timer within the
 * timeout, i.e. the heartbeat link to the tamper sensor is gone. */
static enum hrtimer_restart
ash_hb_timer_fn(struct hrtimer *t)
{
	panic("Timeout on ashen tamper alarm heartbeat link");
	return HRTIMER_NORESTART; /* unreachable */
}

static enum hrtimer_restart
ash_refresh_timer_fn(struct hrtimer *t)
{
	struct ashen_tamper *ash = container_of(t, struct ashen_tamper, refresh_timer);
	struct ashen_msg_echo msg = {
		.type = ASHEN_MSG_ECHO_REQUEST,
		.value = cpu_to_be64(ktime_get_ns()),
	};
	ash_send_envelope(ash, &msg, sizeof(msg));
	return HRTIMER_RESTART;
}

static ssize_t timeout_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%lld\n", ktime_to_us(ash->timeout));
}

static DEVICE_ATTR_RO(timeout);

static ssize_t refresh_ivl_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%lld\n", ktime_to_us(ash->refresh_ivl));
}

static DEVICE_ATTR_RO(refresh_ivl);

static ssize_t armed_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%d\n", hrtimer_active(&ash->hb_timer));
}

static DEVICE_ATTR_RO(armed);

static ssize_t connected_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%d\n", ash->conn_st == CONN_CONNECTED);
}

static DEVICE_ATTR_RO(connected);

static ssize_t action_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	int ret;
	u8 msg;

	if (ash->conn_st != CONN_CONNECTED)
		return -ENOTCONN;

	if (sysfs_streq(buf, "erase")) {
		msg = ASHEN_MSG_ERASE;
		ret = ash_send_envelope(ash, &msg, sizeof(msg));
	} else if (sysfs_streq(buf, "pair")) {
		msg = ASHEN_MSG_PAIR_REQUEST;
		ret = ash_send_envelope(ash, &msg, sizeof(msg));
	} else {
		return -EINVAL;
	}

	return ret ? ret : count;
}

static DEVICE_ATTR_WO(action);

static struct attribute *ashen_attrs[] = {
	&dev_attr_timeout.attr,
	&dev_attr_refresh_ivl.attr,
	&dev_attr_armed.attr,
	&dev_attr_connected.attr,
	&dev_attr_action.attr,
	NULL,
};

ATTRIBUTE_GROUPS(ashen);

static int ashen_tamper_probe(struct serdev_device *serdev)
{
	int ret;
	u32 baudrate = ASHEN_TAMPER_DEFAULT_BAUDRATE;
	u32 val;

	struct ashen_tamper *ash = devm_kzalloc(&serdev->dev,
			sizeof(*ash), GFP_KERNEL);

	if (!ash) {
		ret = -ENOMEM;
		goto error;
	}

	ash->serdev = serdev;
	serdev_device_set_drvdata(serdev, ash);
	serdev_device_set_client_ops(serdev, &ashen_serdev_ops);

	ash->framer = devm_kzalloc(&serdev->dev,
			struct_size(ash->framer, buf, ASHEN_TAMPER_RX_BUF_SIZE),
			GFP_KERNEL);
	if (!ash->framer) {
		ret = -ENOMEM;
		goto error;
	}
	ash->framer->cap = ASHEN_TAMPER_RX_BUF_SIZE;
	ash->framer->on_frame = ashen_receive_packet;
	ash->framer->ctx = ash;

	of_property_read_u32(serdev->dev.of_node, "baudrate", &baudrate);

	ash->autostart = !of_property_read_bool(serdev->dev.of_node, "no-autostart");

	val = ASHEN_TAMPER_DEFAULT_TIMEOUT_US;
	of_property_read_u32(serdev->dev.of_node, "timeout-us", &val);
	ash->timeout = us_to_ktime(val);

	val = ASHEN_TAMPER_DEFAULT_REFRESH_IVL_US;
	of_property_read_u32(serdev->dev.of_node, "refresh-ivl-us", &val);
	ash->refresh_ivl = us_to_ktime(val);

	ash->conn_st = CONN_HANDSHAKE;
	init_completion(&ash->connection_ready);
	init_completion(&ash->packet_ready);
	mutex_init(&ash->tx_lock);

	noise_init(&ash->noise_st, true);
	if (!noise_keypair_generate(&ash->noise_st.hs.loc_static)) {
		dev_err(&serdev->dev, "Unable to generate static keypair\n");
		ret = -EIO;
		goto error;
	}

	spin_lock_init(&ash->tx_queue_lock);
	INIT_WORK(&ash->tx_work, ash_tx_work_fn);
	ash->tx_wq = alloc_ordered_workqueue("ashen-tamper-tx", WQ_MEM_RECLAIM);
	if (!ash->tx_wq) {
		ret = -ENOMEM;
		goto error;
	}

	hrtimer_setup(&ash->hb_timer, ash_hb_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_HARD);
	hrtimer_setup(&ash->refresh_timer, ash_refresh_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_HARD);

	ret = serdev_device_open(serdev);
	if (ret) {
		dev_err(&serdev->dev, "Unable to open ashen heartbeat link\n");
		goto error_wq;
	}

	baudrate = serdev_device_set_baudrate(serdev, baudrate);
	dev_info(&serdev->dev, "Using baudrate: %u\n", baudrate);
	serdev_device_set_flow_control(serdev, false);

	/* We are the initiator: kick off the handshake with message "a". */
	ashen_continue_handshake(ash, NULL, 0);
	return 0;

error_wq:
	destroy_workqueue(ash->tx_wq);
error:
	if (panic_on_error)
		panic("ashen-tamper initialization failure");
	return ret;
}

static void ashen_tamper_remove(struct serdev_device *serdev)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);

	/* Stop the timers before they can queue more work. */
	hrtimer_cancel(&ash->refresh_timer);
	hrtimer_cancel(&ash->hb_timer);

	if (ash->conn_st == CONN_CONNECTED) {
		u8 type = ASHEN_MSG_DISCONNECT;
		ash_send_envelope(ash, &type, sizeof(type));
	}

	/* Drain the disconnect message before tearing the link down. */
	destroy_workqueue(ash->tx_wq);
	serdev_device_close(serdev);
}

static struct serdev_device_driver ashen_tamper_driver = {
	.probe = ashen_tamper_probe,
	.remove = ashen_tamper_remove,
	.driver = {
		.name = "ashen-tamper",
		.of_match_table = ashen_tamper_of_match,
		.dev_groups = ashen_groups,
	},
};

module_serdev_device_driver(ashen_tamper_driver);

module_param(panic_on_error, bool, 0644);
MODULE_DESCRIPTION("Ashen tamper sensor heartbeat protocol driver");
MODULE_AUTHOR("Yasec");
MODULE_AUTHOR("Jan Sebastian Götte <kernel@yasec.de>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
