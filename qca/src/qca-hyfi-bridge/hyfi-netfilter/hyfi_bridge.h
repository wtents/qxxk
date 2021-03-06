/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#ifndef HYFI_BRIDGE_H_
#define HYFI_BRIDGE_H_

#include <br_private.h>
#include "hyfi_api.h"
#include "hyfi_netfilter.h"
#include "hyfi_seamless.h"
#include "hyfi_osdep.h"

#define HY_BRIDGE_DEBUG

#ifdef HY_BRIDGE_DEBUG
extern u_int32_t psw_debug;
#define DPRINTK( __fmt, ... )  do { if(unlikely(psw_debug)) printk( __fmt, ##__VA_ARGS__ ); } while(0)
#else
#define DPRINTK(...)
#endif

#ifndef IPPROTO_ETHERIP
#define IPPROTO_ETHERIP (97)
#endif

#define HYFI_AGGR_REORD_FLUSH_QUOTA 2
#define HYFI_BRIDGE_ME				(NULL)

struct hyfi_net_bridge {
	spinlock_t lock;

	spinlock_t hash_ha_lock;
	struct hlist_head hash_ha[HA_HASH_SIZE];

	spinlock_t hash_hd_lock;
	struct hlist_head hash_hd[HD_HASH_SIZE];

	u_int32_t flags;
	u_int32_t hatbl_aging_time;
	struct timer_list hatbl_timer;
	u_int32_t ha_entry_cnt;
	pid_t event_pid;

	struct path_switch_param path_switch_param;
	void *mc;
	struct list_head port_list;

	struct net_device *dev;
};

struct hyfi_net_bridge_port {
	u_int8_t group_num;
	u_int8_t group_type;
	u_int8_t bcast_enable;
	u_int8_t port_type;

	struct list_head list;
	struct rcu_head	rcu;
	struct net_device *dev;
};

struct hyfi_net_bridge *hyfi_bridge_get(const struct net_bridge *br);
struct hyfi_net_bridge *hyfi_bridge_get_by_dev(const struct net_device *dev);
struct hyfi_net_bridge_port * hyfi_bridge_get_port(const struct net_bridge_port *p);
struct hyfi_net_bridge_port * hyfi_bridge_get_port_by_dev(const struct net_device *dev);

static inline bool hyfi_brmode_relay_override(
		const struct hyfi_net_bridge *hyfi_br)
{
	return (hyfi_br->flags & HYFI_BRIDGE_FLAG_MODE_RELAY_OVERRIDE) ?
			true : false;
}

static inline bool hyfi_tcp_sp(const struct hyfi_net_bridge *hyfi_br)
{
	return (hyfi_br->flags & HYFI_BRIDGE_FLAG_MODE_TCP_SP) ? true : false;
}

static inline bool hyfi_portgrp_relay(const struct hyfi_net_bridge_port *p)
{
	return (!p || (p && p->group_type == HYFI_PORTGRP_TYPE_RELAY)) ?
			true : false;
}

static inline u_int32_t hyfi_portgrp_num(const struct hyfi_net_bridge_port *p)
{
	if (!p)
		return 0;

	return (p->group_num);
}

static inline int hyfi_bridge_portgrp_relay(struct net_bridge_port *p)
{
    return hyfi_portgrp_relay(hyfi_bridge_get_port(p));
}

static inline int hyfi_bridge_should_flood(const struct hyfi_net_bridge_port *hyfi_p,
		const struct sk_buff *skb)
{
	if (hyfi_p && hyfi_p->bcast_enable)
		return 1;

	return 0;
}

int hyfi_bridge_dev_event(unsigned long event, struct net_device *dev);
int hyfi_bridge_set_bridge_name(const char *br_name);
int hyfi_bridge_init_port(struct net_bridge_port *p);
int hyfi_bridge_delete_port(struct net_bridge_port *p);
int hyfi_bridge_should_deliver(const struct hyfi_net_bridge_port *src,
		const struct hyfi_net_bridge_port *dst, const struct sk_buff *skb);
struct net_bridge_port *hyfi_bridge_get_dst(const struct net_bridge_port *src,
		struct sk_buff **skb);

int hyfi_bridge_init(void);

void hyfi_bridge_fini(void);

#endif /* HYFI_BRIDGE_H_ */
