/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#ifndef HYFI_FDB_H_
#define HYFI_FDB_H_

#include "hyfi_bridge.h"

static inline int hyfi_fdb_should_update(struct hyfi_net_bridge *hyfi_br,
		const struct net_bridge_port *src, const struct net_bridge_port *dst)
{
	return (hyfi_portgrp_relay(hyfi_bridge_get_port(src))
			|| !hyfi_portgrp_relay(hyfi_bridge_get_port(dst)));
}

int hyfi_fdb_init(void);
void hyfi_fdb_fini(void);

/*
 * Fill buffer with forwarding table records in
 * the API format.
 */
int hyfi_fdb_fillbuf(struct net_bridge *br, void *buf, u_int32_t buf_len,
		u_int32_t skip, u_int32_t *bytes_written, u_int32_t *bytes_needed);

#endif /* HYFI_FDB_H_ */
