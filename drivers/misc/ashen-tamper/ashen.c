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

#define ASHEN_TAMPER_DEFAULT_BAUDRATE 1000000
#define ASHEN_TAMPER_DEFAULT_TX_BUF_SIZE 128
#define ASHEN_TAMPER_DEFAULT_RX_BUF_SIZE 128
#define ASHEN_TAMPER_DEFAULT_TIMEOUT_MIN_US 10000
#define ASHEN_TAMPER_DEFAULT_SLACK_MIN_US 5000


struct ashen_tamper {
	struct hrtimer hb_timer;
	struct serdev_device *serdev;
	spinlock_t noise_lock; /* noise state machine lock */
	struct noise_state noise_st;
	ktime_t timeout_min;
	ktime_t slack_min;
	ktime_t timeout;
	unsigned char *rx_buf;
	unsigned char *tx_buf;
};

static const struct serdev_device_ops ashen_serdev_ops = {
	.receive_buf = ashen_tty_receive,
	.write_wakeup = ashen_tty_wakeup,
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
	struct ashen_tamper *ash = devm_kzalloc(serdev->dev, sizeof(*ash), GFP_KERNEL | __GFP_NOFAIL);

	if (!ash) {
		pr_err("ashen-tamper: Fail to allocate driver structure\n");
		return -ENOMEM;
	}
	ash->serdev = serdev;

	spin_lock_init(&qca->lock);
	INIT_WORK(&qca->tx_work, qcauart_transmit);

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

	serdev_device_set_drvdata(serdev, ash);
	serdev_device_set_client_ops(serdev, &ashen_serdev_ops);

	ret = sysfs_create_group(&serdev->dev->kobj, &ashen_group);
	if (ret) {
		dev_err(&serdev->dev, "Unable to create ashen heartbeat link sysfs attrs\n");
		goto free;
	}

	ret = serdev_device_open(serdev);
	if (ret) {
		dev_err(&serdev->dev, "Unable to open ashen heartbeat link\n");
		goto free;
	}

	speed = serdev_device_set_baudrate(serdev, speed);
	dev_info(&serdev->dev, "Using baudrate: %u\n", speed);
	serdev_device_set_flow_control(serdev, false);

	return 0;
free:
	kfree(ash);
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

MODULE_DESCRIPTION("Ashen tamper sensor heartbeat protocol driver");
MODULE_AUTHOR("Yasec");
MODULE_AUTHOR("Jan Sebastian Götte <kernel@yasec.de>");
MODULE_LICENSE("GPL");
MODULE_VERSION(QCAUART_DRV_VERSION);
