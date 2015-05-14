/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#ifndef HYFI_NETFILTER_H_
#define HYFI_NETFILTER_H_

#include <linux/netdevice.h>
#include "hyfi_api.h"

#define HA_HASH_BITS 8
#define HA_HASH_SIZE (1 << HA_HASH_BITS)

#define HD_HASH_BITS 8
#define HD_HASH_SIZE (1 << HD_HASH_BITS)

int hyfi_netfilter_init(void);
void hyfi_netfilter_fini(void);

#endif /* HYFI_NETFILTER_H_ */
