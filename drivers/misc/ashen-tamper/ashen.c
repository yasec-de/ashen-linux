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
#define ASHEN_TAMPER_DEFAULT_TIMEOUT_US 10000
#define ASHEN_TAMPER_DEFAULT_REFRESH_IVL_US 5000
#define ASHEN_TAMPER_SERDEV_TIMEOUT 100 /* jiffies */
#define ASHEN_TAMPER_RX_BUF_SIZE 256
#define ASHEN_TAMPER_HS_TIMEOUT_US 250000
#define ASHEN_TAMPER_RESET_LEN 8

static void ashen_queue_restart(struct ashen_tamper *ash);

static int ash_serdev_write(struct ashen_tamper *ash, u8 *msg, size_t msg_len) {
	if (msg_len == serdev_device_write(ash->serdev, msg, msg_len,
			ASHEN_TAMPER_SERDEV_TIMEOUT)) {
		return 0;
	}
	dev_err_ratelimited(&ash->serdev->dev,
			"I/O error writing to serial\n");
	ashen_queue_restart(ash);
	return -EIO;
}

static int ash_tx_one(struct ashen_tamper *ash, const struct ashen_tx_req *req)
{
	u8 wire[sizeof(ash->tx_buf) + 16];
	ssize_t encoded;
	size_t clen = req->len + NOISE_MAC_LEN;
	noise_encrypt_transport_message(&ash->noise_st, req->payload, req->len,
			ash->tx_buf);
	encoded = cobs_encode(ash->tx_buf, clen, wire, sizeof(wire));
	if (encoded < 0)
		return -EMSGSIZE;

	return ash_serdev_write(ash, wire, encoded);
}

static void ash_tx_work_fn(struct work_struct *w)
{
	struct ashen_tamper *ash = container_of(w, struct ashen_tamper, tx_work);
	struct ashen_tx_req req;
	unsigned long flags;
	bool ok;

	for (;;) {
		spin_lock_irqsave(&ash->tx_queue_lock, flags);
		ok = kfifo_get(&ash->tx_queue, &req);
		spin_unlock_irqrestore(&ash->tx_queue_lock, flags);

		if (!ok)
			return;
		
		wait_for_completion_killable(&ash->connection_ready);
		mutex_lock(&ash->tx_lock);
		if (ash_tx_one(ash, &req)) {
			dev_err(&ash->serdev->dev, "I/O error during payload transmission\n");
		} else if (req.len == sizeof(struct ashen_msg_echo) &&
			   req.payload[0] == ASHEN_MSG_ECHO_REQUEST &&
			   !hrtimer_active(&ash->hb_timer)) {
			/* Start the first response deadline only once the request has
			 * actually reached serdev.  Starting it when the hrtimer merely
			 * queues this work can panic during early-boot workqueue delays. */
			hrtimer_start(&ash->hb_timer, ash->timeout,
					HRTIMER_MODE_REL_HARD);
		}
		mutex_unlock(&ash->tx_lock);
	}
}

/* Queue a transport message. Safe from atomic context. */
static int ash_send_envelope(struct ashen_tamper *ash,
		const void *msg, size_t len)
{
	struct ashen_tx_req req;
	unsigned long flags;
	bool ok;

	if (len > ASHEN_TX_MAX_PAYLOAD)
		return -EMSGSIZE;

	memcpy(req.payload, msg, len);
	req.len = len;

	spin_lock_irqsave(&ash->tx_queue_lock, flags);
	ok = kfifo_put(&ash->tx_queue, req);
	spin_unlock_irqrestore(&ash->tx_queue_lock, flags);
	if (!ok)
		return -ENOSPC;

	queue_work(ash->tx_wq, &ash->tx_work);
	return 0;
}

static void ashen_queue_restart(struct ashen_tamper *ash)
{
	queue_work(ash->tx_wq, &ash->restart_work);
}

static void ashen_continue_handshake(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	u8 hs_msg[NOISE_MAX_HS_MSG_LEN];
	u8 wire[NOISE_MAX_HS_MSG_LEN + 2];
	ssize_t to_write;
	ssize_t encoded;
	bool done = false;
	u8 type;
	hrtimer_cancel(&ash->restart_timer);
	
	to_write = noise_handshake(&ash->noise_st, buf, len, hs_msg, &done);
	if (to_write < 0) {
		dev_err_ratelimited(&ash->serdev->dev, "noise handshake error\n");
		ashen_queue_restart(ash);
		return;
	}

	mutex_lock(&ash->tx_lock);
	if (to_write) {
		encoded = cobs_encode(hs_msg, to_write, wire, sizeof(wire));
		if (encoded < 0 || ash_serdev_write(ash, wire, encoded)) {
			mutex_unlock(&ash->tx_lock);
			return;
		}
	}

	if (!done) {
		hrtimer_start(&ash->restart_timer,
				us_to_ktime(ASHEN_TAMPER_HS_TIMEOUT_US),
				HRTIMER_MODE_REL_SOFT);
		mutex_unlock(&ash->tx_lock);
		return;
	}
	WRITE_ONCE(ash->conn_st, CONN_CONNECTED);
	complete_all(&ash->connection_ready);

	if (ash->autostart)
		hrtimer_start(&ash->refresh_timer, 0, HRTIMER_MODE_REL_HARD);

	type = ASHEN_MSG_STATUS_REQUEST;
	if (ash_send_envelope(ash, &type, sizeof(type)))
		dev_err(&ash->serdev->dev,
				"failed to send status request\n");
	mutex_unlock(&ash->tx_lock);
}

static void ashen_restart_handshake(struct work_struct *w)
{
	struct ashen_tamper *ash = container_of(w, struct ashen_tamper, restart_work);
	static const u8 reset[ASHEN_TAMPER_RESET_LEN] = {0};
	unsigned long flags;
	WRITE_ONCE(ash->conn_st, CONN_DISCONNECTED);
	mutex_lock(&ash->rx_lock);
	mutex_lock(&ash->tx_lock);
	if (hrtimer_active(&ash->refresh_timer)) {
		ash->autostart = true;
		hrtimer_cancel(&ash->refresh_timer);
	}
	reinit_completion(&ash->connection_ready);

	spin_lock_irqsave(&ash->tx_queue_lock, flags);
	kfifo_reset(&ash->tx_queue);
	spin_unlock_irqrestore(&ash->tx_queue_lock, flags);

	serdev_device_write_flush(ash->serdev);

	noise_init(&ash->noise_st, true);
	if (!noise_keypair_generate(&ash->noise_st.hs.loc_static)) {
		mutex_unlock(&ash->rx_lock);
		mutex_unlock(&ash->tx_lock);
		dev_err_ratelimited(&ash->serdev->dev,
				"unable to generate static keypair. giving up.\n");
		return;
	}

	if (ash_serdev_write(ash, reset, sizeof(reset))) {
		mutex_unlock(&ash->rx_lock);
		mutex_unlock(&ash->tx_lock);
		ashen_queue_restart(ash);
		return;
	}
	ash->framer->len = 0;
	ash->framer->sync = 0;
	WRITE_ONCE(ash->conn_st, CONN_HANDSHAKE);
	mutex_unlock(&ash->tx_lock);
	ashen_continue_handshake(ash, NULL, 0);
	mutex_unlock(&ash->rx_lock);
}

static void ashen_handle_packet(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	u64 delta_ns;
	if (len < 1) {
		dev_warn(&ash->serdev->dev, "empty message\n");
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
		int ret;

		if (len != sizeof(*msg))
			goto malformed;
		dev_info(&ash->serdev->dev, "pairing successful\n");

		type = ASHEN_MSG_STATUS_REQUEST;
		ret = ash_send_envelope(ash, &type, sizeof(type));
		if (ret)
			dev_warn(&ash->serdev->dev,
					"failed to send status request: %d\n", ret);
		break;
	}
	case ASHEN_MSG_STATUS_RESPONSE: {
		const struct ashen_msg_status_response *msg = (const void *)buf;

		if (len != sizeof(*msg))
			goto malformed;
		dev_info(&ash->serdev->dev,
				"status: peer_trusted=%d is_keyed=%d\n",
				msg->peer_trusted, msg->is_keyed);
		break;
	}
	case ASHEN_MSG_ECHO_RESPONSE: {
		const struct ashen_msg_echo *msg = (const void *)buf;

		if (len != sizeof(*msg))
			goto malformed;

		delta_ns = ktime_get_ns() - be64_to_cpu(msg->value);
		if (delta_ns > ktime_to_ns(ash->timeout)) {
			dev_warn(&ash->serdev->dev,
					"received echo response stale by %llu ns\n",
					delta_ns);
		} else {
			/* Restart the timer. */
			hrtimer_start(&ash->hb_timer, ash->timeout,
					HRTIMER_MODE_REL_HARD);
		}
		break;
	}
	case ASHEN_MSG_DISCONNECT:
		if (len != 1)
			goto malformed;
		
		dev_warn(&ash->serdev->dev, "device asked to disconnect, disarming heartbeat\n");
		WRITE_ONCE(ash->conn_st, CONN_DISCONNECTED);
		hrtimer_cancel(&ash->refresh_timer);
		hrtimer_cancel(&ash->hb_timer);
		reinit_completion(&ash->connection_ready);
		break;
	default:
		dev_warn(&ash->serdev->dev, "unexpected message type %d\n",
				buf[0]);
		break;
	}
	return;

malformed:
	dev_warn(&ash->serdev->dev, "malformed message type %d\n", buf[0]);
}

static void ashen_receive_packet(void *ctx,
		const u8 *buf, size_t len)
{
	struct ashen_tamper *ash = (struct ashen_tamper *)ctx;
	u8 *frame = (u8 *)buf; /* framer buffer, in-place decrypt is fine */
	mutex_lock(&ash->rx_lock);
	switch (READ_ONCE(ash->conn_st)) {
	case CONN_DISCONNECTED:
		dev_warn(&ash->serdev->dev,
				"received out-of-order message from device\n");
		mutex_unlock(&ash->rx_lock);
		break;
	case CONN_HANDSHAKE:
		ashen_continue_handshake(ash, buf, len);
		mutex_unlock(&ash->rx_lock);
		break;
	case CONN_CONNECTED:
		if (len < NOISE_MAC_LEN) {
			mutex_unlock(&ash->rx_lock);
			break;
		}

		if (!noise_decrypt_transport_message(&ash->noise_st,
					frame, len, frame)) {
			dev_warn_ratelimited(&ash->serdev->dev,
					"transport decrypt failed, restarting\n");
			ashen_queue_restart(ash);
			mutex_unlock(&ash->rx_lock);
			break;
		}
		mutex_unlock(&ash->rx_lock);
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

static enum hrtimer_restart
ash_hb_timer_fn(struct hrtimer *t)
{
	panic("Timeout on ashen tamper alarm heartbeat link");
	return HRTIMER_NORESTART; /* unreachable */
}

static enum hrtimer_restart
ash_restart_timer_fn(struct hrtimer *t)
{
	struct ashen_tamper *ash = container_of(t, struct ashen_tamper, restart_timer);

	dev_warn_ratelimited(&ash->serdev->dev,
			"handshake timed out, retrying\n");
	ashen_queue_restart(ash);
	return HRTIMER_NORESTART;
}

static enum hrtimer_restart
ash_refresh_timer_fn(struct hrtimer *t)
{
	struct ashen_tamper *ash = container_of(t, struct ashen_tamper, refresh_timer);
	struct ashen_msg_echo msg = {
		.type = ASHEN_MSG_ECHO_REQUEST,
		.value = cpu_to_be64(ktime_get_ns()),
	};

	if (ash_send_envelope(ash, &msg, sizeof(msg)))
		dev_warn_ratelimited(&ash->serdev->dev,
				"failed to queue echo request\n");

	hrtimer_forward_now(t, ash->refresh_ivl);
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

	WRITE_ONCE(ash->conn_st, CONN_DISCONNECTED);
	init_completion(&ash->connection_ready);
	mutex_init(&ash->tx_lock);
	mutex_init(&ash->rx_lock);

	spin_lock_init(&ash->tx_queue_lock);
	INIT_KFIFO(ash->tx_queue);
	INIT_WORK(&ash->tx_work, ash_tx_work_fn);
	INIT_WORK(&ash->restart_work, ashen_restart_handshake);
	ash->tx_wq = alloc_ordered_workqueue("ashen-tamper-tx", WQ_MEM_RECLAIM);
	if (!ash->tx_wq) {
		ret = -ENOMEM;
		goto error;
	}

	hrtimer_setup(&ash->hb_timer, ash_hb_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_HARD);
	hrtimer_setup(&ash->refresh_timer, ash_refresh_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_HARD);
	hrtimer_setup(&ash->restart_timer, ash_restart_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_SOFT);

	ret = serdev_device_open(serdev);
	if (ret) {
		dev_err(&serdev->dev, "Unable to open ashen heartbeat link\n");
		goto error_wq;
	}

	baudrate = serdev_device_set_baudrate(serdev, baudrate);
	dev_info(&serdev->dev, "Using baudrate: %u\n", baudrate);
	serdev_device_set_flow_control(serdev, false);
	queue_work(ash->tx_wq, &ash->restart_work);
	return 0;

error_wq:
	destroy_workqueue(ash->tx_wq);
error:
	return ret;
}

static void ashen_tamper_remove(struct serdev_device *serdev)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);
	WRITE_ONCE(ash->conn_st, CONN_DISCONNECTED);

	hrtimer_cancel(&ash->restart_timer);
	hrtimer_cancel(&ash->refresh_timer);
	hrtimer_cancel(&ash->hb_timer);
	cancel_work_sync(&ash->restart_work);
	cancel_work_sync(&ash->tx_work);
	serdev_device_close(serdev);
	destroy_workqueue(ash->tx_wq);
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

MODULE_DESCRIPTION("Ashen tamper sensor heartbeat protocol driver");
MODULE_AUTHOR("Yasec");
MODULE_AUTHOR("Jan Sebastian Götte <kernel@yasec.de>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
