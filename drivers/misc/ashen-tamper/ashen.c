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
#include "ashen.h"

#define ASHEN_TAMPER_DEFAULT_BAUDRATE 1000000
#define ASHEN_TAMPER_MAX_BUF_SIZE 8192
#define ASHEN_TAMPER_DEFAULT_TIMEOUT_MIN_US 10000
#define ASHEN_TAMPER_DEFAULT_SLACK_MIN_US 5000
#define ASHEN_TAMPER_SERDEV_TIMEOUT 100 /* jiffies */
#define ASHEN_TAMPER_RX_BUF_SIZE 256

static bool panic_on_error;


static void ashen_continue_handshake(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	ssize_t ret;
	ssize_t to_write;
	bool done = false;

	ret = noise_handshake(&ash->noise_st, buf, len, ash->tx_buf, &done);
	if (ret < 0) {
		pr_err("ashen-tamper: noise handshake error\n");
		ash->conn_st = CONN_DISCONNECTED;
		return;
	}
	to_write = ret;

	if (to_write) {
		ret = serdev_device_write(ash->serdev, ash->tx_buf, to_write,
				ASHEN_TAMPER_SERDEV_TIMEOUT);
		if (ret != to_write) {
			if (ret == -ETIMEDOUT || ret == -ERESTARTSYS)
				pr_err("ashen-tamper: timeout during handshake\n");
			else
				pr_err("ashen-tamper: I/O error during handshake\n");
			ash->conn_st = CONN_DISCONNECTED;
			return;
		}
	}

	if (done) {
		ash->conn_st = CONN_CONNECTED;
		complete(&ash->connection_ready);
	}
}

static void ashen_handle_packet(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	complete(&ash->packet_ready);
}

static void ashen_receive_packet(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
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

static void ashen_on_frame(void *ctx, const u8 *frame, size_t len)
{
	ashen_receive_packet(ctx, frame, len);
}

static size_t ashen_receive(struct serdev_device *serdev,
		const u8 *buf, size_t size)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);

	return ashen_framer_push(ash->framer, buf, size);
}

static const struct serdev_device_ops ashen_serdev_ops = {
	.receive_buf = ashen_receive,
	.write_wakeup = serdev_device_write_wakeup,
};

static const struct of_device_id ashen_tamper_of_match[] = {
	{
	 .compatible = "ashen,hbv1",
	},
	{}
};
MODULE_DEVICE_TABLE(of, ashen_tamper_of_match);

/* ponytail: __maybe_unused until the heartbeat rx path calls these */
static void __maybe_unused reset_hb_timeout(struct ashen_tamper *ash)
{
	hrtimer_forward_now(&ash->hb_timer, ash->timeout);
}

static void __maybe_unused start_hb_timer(struct ashen_tamper *ash, unsigned int ivl_adv_us)
{
	ktime_t ivl_adv = us_to_ktime(ivl_adv_us);
	ash->timeout = min(ash->timeout_min, ivl_adv + ash->slack_min);
	hrtimer_start(&ash->hb_timer, ash->timeout, HRTIMER_MODE_REL_PINNED);
}

static enum hrtimer_restart
ash_hb_timer_fn(struct hrtimer *hrtimer)
{
	panic("Timeout on ashen tamper alarm heartbeat link");
	return HRTIMER_RESTART; /* unreachable */
}

static ssize_t timeout_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%lld\n", ktime_to_us(ash->timeout));
}

/* ponytail: RO until the *_store handlers exist, then back to RW */
static DEVICE_ATTR_RO(timeout);

static ssize_t armed_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%d\n", ash->timeout > 0);
}

static DEVICE_ATTR_RO(armed);

static ssize_t connected_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	return sysfs_emit(buf, "%d\n", 0); /* FIXME */
}

static DEVICE_ATTR_RO(connected);

static struct attribute *ashen_attrs[] = {
	&dev_attr_timeout.attr,
	&dev_attr_armed.attr,
	&dev_attr_connected.attr,
	NULL,
};

ATTRIBUTE_GROUPS(ashen);

static int ashen_tamper_probe(struct serdev_device *serdev)
{
	int ret;
	u32 speed = ASHEN_TAMPER_DEFAULT_BAUDRATE;
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
	ash->framer->on_frame = ashen_on_frame;
	ash->framer->ctx = ash;

	of_property_read_u32(serdev->dev.of_node, "current-speed", &speed);

	val = ASHEN_TAMPER_DEFAULT_TIMEOUT_MIN_US;
	of_property_read_u32(serdev->dev.of_node, "timeout-min-us", &val);
	ash->timeout_min = us_to_ktime(val);

	val = ASHEN_TAMPER_DEFAULT_SLACK_MIN_US;
	of_property_read_u32(serdev->dev.of_node, "slack-min-us", &val);
	ash->slack_min = us_to_ktime(val);

	ash->timeout = 0;
	ash->conn_st = CONN_HANDSHAKE;
	init_completion(&ash->connection_ready);
	init_completion(&ash->packet_ready);
	mutex_init(&ash->tx_lock);

	hrtimer_setup(&ash->hb_timer, ash_hb_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_HARD);

	ret = serdev_device_open(serdev);
	if (ret) {
		dev_err(&serdev->dev, "Unable to open ashen heartbeat link\n");
		goto error;
	}

	speed = serdev_device_set_baudrate(serdev, speed);
	dev_info(&serdev->dev, "Using baudrate: %u\n", speed);
	serdev_device_set_flow_control(serdev, false);
	return 0;
error:
	if (panic_on_error)
		panic("ashen-tamper initialization failure");
	return ret;
}

static void ashen_tamper_remove(struct serdev_device *serdev)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);

	hrtimer_cancel(&ash->hb_timer);
	/* Flush any pending characters in the driver. */
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
