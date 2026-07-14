// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <linux/kernel.h>
#include <linux/hrtimer.h>
#include <linux/serdev.h>
#include <linux/sysfs.h>
#include "cobs.h"
#include "noise.h"
#include "ashen.h"

#define ASHEN_TAMPER_DEFAULT_BAUDRATE 1000000
#define ASHEN_TAMPER_MAX_BUF_SIZE 8192
#define ASHEN_TAMPER_DEFAULT_TIMEOUT_MIN_US 10000
#define ASHEN_TAMPER_DEFAULT_SLACK_MIN_US 5000
#define ASHEN_TAMPER_SERDEV_TIMEOUT 100 /* jiffies */

static bool panic_on_error;


static void ashen_continue_handshake(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	ssize_t ret;
	ssize_t to_write;

	ret = noise_handshake(ashen->noise_st, buf, len, ash->tx_buf); 
	if (ret < 0) {
		pr_err("ashen-tamper: noise handshake error\n"); 
		ash->conn_st = CONN_DISCONNECTED;
		return;
	} else if (ret == 0) {
		complete(ash->connection_ready);
		ash->conn_st = CONN_CONNECTED;
		return;
	} /* else: ret > 0 */
	to_write = ret;

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

static void ashen_handle_packet(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	complete(ash->packet_ready);
}

static void ashen_receive_packet(struct ashen_tamper *ash,
		const u8 *buf, size_t len)
{
	ssize_t ret;
	switch (ash->conn_st) {
	case CONN_DISCONNECTED:
		pr_warn("ashen-tamper: received out-of-order message from device\n");
		break;
	case CONN_HANDSHAKE:
		ashen_continue_handshake(ash, buf, len);
		break;
	case CONN_CONNECTED:
		if (!noise_decrypt_transport_message(ash->noise_st,
					ash->rx_buf, ash->rx_len, ash->rx_buf))
			break;

		ashen_handle_packet(ash,
				ash->rx_buf, ash->rx_len - NOISE_MAC_LEN);
		break;
	}
}

static size_t ashen_receive_chunk(struct ashen_tamper *ash,
		const u8 *buf, size_t size)
{
	ssize_t len;
	size_t nul_pos = strnlen(buf, size);
	if (ash->rx_len + nul_pos > ARRAY_SIZE(ash->rx_buf)) {
		ash->rx_sync = false;
		pr_warn("ashen-tamper: receive buffer overrun\n");
		return nul_pos;
	}

	memcpy(ash->rx_buf + ash->rx_len, buf, nul_pos);
	ash->rx_len += nul_pos;

	if (nul_pos == size) {
		return nul_pos;
	}

	/* frame complete. decode in place. */
	len = cobs_decode(ash->rx_buf, ash->rx_len,
			ash->rx_buf, ARRAY_SIZE(ash->rx_buf));
	if (len >= 0) {
		ashen_receive_packet(ash, ash->rx_buf, len);
	} else if (len == -EINTR) {
		pr_warn("ashen-tamper: truncated frame received\n");
		/* no point in resetting ash->rx_sync here since we already
		 * received the next null byte, so we are synced. */
	}/* else: consecutive null bytes received. Technically, a valid empty
	     frame is [0x01 0x00], not just [0x00]. We ignore this here since
	     runs of null bytes are useful for initial sync. */
	ash->rx_len = 0;
	return nul_pos;
}

static size_t ashen_receive(struct serdev_device *serdev,
		const u8 *buf, size_t size)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);
	size_t consumed;

	while (size && consumed = ashen_receive_chunk(ash, buf, size)) {
		buf += consumed;
		size -= consumed;
	}
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

static void reset_hb_timeout(struct ashen_tamper *ash)
{
	hrtimer_forward_now(&ash.timer, ash->timeout);
}

static void start_hb_timer(struct ashen_tamper *ash, unsigned int ivl_adv_us)
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
			  const char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%llu\n", ktime_to_us(ash->timeout));
}

static DEVICE_ATTR_RW(timeout);

static ssize_t armed_show(struct device *dev, struct device_attribute *attr,
			  const char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%llu\n", ash->timeout > 0);
}

static DEVICE_ATTR_RW(armed);

static ssize_t connected_show(struct device *dev, struct device_attribute *attr,
			  const char *buf)
{
	struct ashen_tamper *ash = dev_get_drvdata(dev);
	return sysfs_emit(buf, "%llu\n", 0); /* FIXME */
}

static DEVICE_ATTR_RW(armed);

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
	u32 bufsize = 0;

	struct ashen_tamper *ash = devm_kzalloc(serdev->dev,
			sizeof(*ash), GFP_KERNEL | __GFP_NOFAIL);

	if (!ash) {
		pr_err("ashen-tamper: Fail to allocate driver structure\n");
		goto error;
	}

	ash->serdev = serdev;
	serdev_device_set_drvdata(serdev, ash);
	serdev_device_set_client_ops(serdev, &ashen_serdev_ops);

	of_property_read_u32(serdev->dev.of_node, "current-speed", &speed);

	ash->timeout_min = ASHEN_TAMPER_DEFAULT_TIMEOUT_MIN_US;
	of_property_read_u32(serdev->dev.of_node, "timeout-min-us",
			&ash->timeout_min);
	ash->timeout_min = us_to_ktime(ash->timeout_min);

	ash->slack_min = ASHEN_TAMPER_DEFAULT_SLACK_MIN_US;
	of_property_read_u32(serdev->dev.of_node, "slack-min-us",
			&ash->slack_min);
	ash->slack_min = us_to_ktime(ash->slack_min);

	ash->timeout = 0;

	hrtimer_setup(&ash->hb_timer, ash_hb_timer_fn, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_HARD);

	ret = sysfs_create_group(&serdev->dev->kobj, &ashen_group);
	if (ret) {
		dev_err(&serdev->dev,
			"Unable to create ashen heartbeat link sysfs attrs\n");
		goto error;
	}

	ret = serdev_device_open(serdev);
	if (ret) {
		dev_err(&serdev->dev, "Unable to open ashen heartbeat link\n");
		goto error;
	}

	speed = serdev_device_set_baudrate(serdev, speed);
	dev_info(&serdev->dev, "Using baudrate: %u\n", speed);
	serdev_device_set_flow_control(serdev, false);
	mutex_init(&ash->tx_lock);
	return 0;
error:
	kfree(ash);
	if (panic_on_error)
		panic("ashen-tamper initialization failure");
	return ret;
}

static void ashen_tamper_remove(struct serdev_device *serdev)
{
	struct ashen_tamper *ash = serdev_device_get_drvdata(serdev);

	/* Flush any pending characters in the driver. */
	serdev_device_close(serdev);
}

static struct serdev_device_driver ashen_tamper_driver = {
	.probe = ashen_tamper_probe,
	.remove = ashen_tamper_remove,
	.driver = {
		.name = "ashen-tamper",
		.of_match_table = ashen_tamper_of_match,
	},
};

module_serdev_device_driver(ashen_tamper_driver);

module_param(panic_on_error, bool, 0644);
MODULE_DESCRIPTION("Ashen tamper sensor heartbeat protocol driver");
MODULE_AUTHOR("Yasec");
MODULE_AUTHOR("Jan Sebastian Götte <kernel@yasec.de>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
