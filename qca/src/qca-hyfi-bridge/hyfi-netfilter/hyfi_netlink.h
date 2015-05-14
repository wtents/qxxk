/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#ifndef HYFI_NETLINK_H_
#define HYFI_NETLINK_H_

#include "hyfi_bridge.h"

void hyfi_netlink_event_send(u32 event_type, u32 event_len, void *event_data);

int hyfi_netlink_init(void);

void hyfi_netlink_fini(void);

#endif /* HYFI_NETLINK_H_ */
