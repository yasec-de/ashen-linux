// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#include <linux/ashen-tamper.h>
#include <linux/auxiliary_bus.h>
#include <linux/module.h>

#include "tpm.h"

static int tpm_ashen_send(struct tpm_chip *chip, u8 *buf, size_t bufsiz,
			  size_t cmd_len)
{
	struct ashen_tamper *ash = dev_get_drvdata(&chip->dev);
	struct tpm_header *hdr = (struct tpm_header *)buf;
	u32 ordinal = be32_to_cpu(hdr->ordinal);

	return ashen_tpm_transact(ash, buf, bufsiz, cmd_len,
				  tpm_calc_ordinal_duration(chip, ordinal));
}

static const struct tpm_class_ops tpm_ashen_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.send = tpm_ashen_send,
};

static int tpm_ashen_probe(struct auxiliary_device *adev,
			   const struct auxiliary_device_id *id)
{
	struct ashen_tamper *ash = dev_get_platdata(&adev->dev);
	struct tpm_chip *chip;

	if (!ash)
		return -ENODEV;

	chip = tpmm_chip_alloc(&adev->dev, &tpm_ashen_ops);
	if (IS_ERR(chip))
		return PTR_ERR(chip);

	dev_set_drvdata(&chip->dev, ash);
	auxiliary_set_drvdata(adev, chip);
	chip->flags |= TPM_CHIP_FLAG_TPM2 | TPM_CHIP_FLAG_SYNC;

	return tpm_chip_register(chip);
}

static void tpm_ashen_remove(struct auxiliary_device *adev)
{
	struct tpm_chip *chip = auxiliary_get_drvdata(adev);

	tpm_chip_unregister(chip);
}

static const struct auxiliary_device_id tpm_ashen_id_table[] = {
	{ .name = "ashen_tamper.tpm" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, tpm_ashen_id_table);

static struct auxiliary_driver tpm_ashen_driver = {
	.probe = tpm_ashen_probe,
	.remove = tpm_ashen_remove,
	.id_table = tpm_ashen_id_table,
	.driver = {
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_auxiliary_driver(tpm_ashen_driver);

MODULE_IMPORT_NS("ASHEN_TAMPER");
MODULE_DESCRIPTION("TPM 2.0 frontend for the ashen tamper peripheral");
MODULE_AUTHOR("Jan Sebastian Götte <kernel@yasec.de>");
MODULE_LICENSE("GPL");
