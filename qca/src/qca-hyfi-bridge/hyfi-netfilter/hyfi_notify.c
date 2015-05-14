/*
 *  QCA HyFi Notify
 *
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/rtnetlink.h>
#include <net/net_namespace.h>
#include "hyfi_netlink.h"
#include "hyfi_bridge.h"
#include "hyfi_hatbl.h"
#include "mc_snooping.h"

static int hyfi_device_event(struct notifier_block *unused, unsigned long event,
		void *ptr);

static struct notifier_block hyfi_device_notifier = { .notifier_call =
		hyfi_device_event };

/*
 * Handle changes in state of network devices enslaved to a bridge.
 */
static int hyfi_device_event(struct notifier_block *unused, unsigned long event,
		void *ptr)
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p = hyfi_br_port_get(dev);
	struct net_bridge *br;
	struct hyfi_net_bridge *hyfi_br = hyfi_bridge_get(HYFI_BRIDGE_ME);
	u_int32_t device_event;

	/* A bridge event */
	if (!hyfi_bridge_dev_event(event, dev))
		return NOTIFY_DONE;

	/* Not a port of a bridge */
	if (p == NULL) {
	    return NOTIFY_DONE;
	}

	br = p->br;

	/* Not our bridge */
	if (br->dev != hyfi_br->dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
		device_event =
				netif_carrier_ok(dev) ?
						HYFI_EVENT_LINK_UP : HYFI_EVENT_LINK_DOWN;

		/* Send a link change notification */
		hyfi_netlink_event_send(device_event, sizeof(u_int32_t), p);
		break;

	case NETDEV_FEAT_CHANGE:
		break;

	case NETDEV_UNREGISTER:
		break;

	default:
		break;
	}

	return NOTIFY_DONE;
}

void hyfi_br_notify(int group, int event, const void *ptr)
{
    struct hyfi_net_bridge *hyfi_br = hyfi_bridge_get(HYFI_BRIDGE_ME);
    if (!hyfi_br)
        return;

    switch (group) {
        case RTNLGRP_LINK:
        {
            struct net_bridge_port *p = (struct net_bridge_port *)ptr;

            if (p->br->dev != hyfi_br->dev)
                return;

            switch (event) {
            case RTM_NEWLINK: {
                hyfi_bridge_init_port(p);
                break;
            }

            case RTM_DELLINK: {
                hyfi_hatbl_delete_by_port(hyfi_br, p);
                hyfi_bridge_delete_port(p);

                mc_nbp_change(p, event);
                break;
            }

            default:
                break;
            }
        }
        break;

        case RTNLGRP_NEIGH:
        {
            struct net_bridge_fdb_entry *fdb = (struct net_bridge_fdb_entry *)ptr;
            mc_fdb_change(fdb->addr.addr, event);
        }
        break;

        default:
            break;
    }
}

int __init hyfi_notify_init(void)
{
	int ret;

	ret = register_netdevice_notifier(&hyfi_device_notifier);
    rcu_assign_pointer(br_notify_hook, hyfi_br_notify);

	if (ret) {
		printk( KERN_ERR "hyfi: Failed to register to netdevice notifier\n" );
	}

	return ret;
}

void hyfi_notify_fini(void)
{
	unregister_netdevice_notifier(&hyfi_device_notifier);
    rcu_assign_pointer(br_notify_hook, NULL);
}
