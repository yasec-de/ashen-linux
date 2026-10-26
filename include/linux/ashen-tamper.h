/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Yasec / Jan Sebastian Götte 2026
 * Author:       Jan Sebastian Götte <kernel@yasec.de>
 */

#ifndef _LINUX_ASHEN_TAMPER_H
#define _LINUX_ASHEN_TAMPER_H

#include <linux/types.h>

struct ashen_tamper;

int ashen_tpm_transact(struct ashen_tamper *ash, u8 *buf, size_t bufsiz,
		size_t cmd_len, unsigned long timeout);

#endif /* _LINUX_ASHEN_TAMPER_H */
