/*
 *  QCA HyFi Netfilter
 *
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include "hyfi_netfilter.h"
#include "hyfi_filters.h"
#include "hyfi_bridge.h"
#include "hyfi_fdb.h"
#ifndef HYFI_MC_STANDALONE_NF
#include "mc_netfilter.h"
#endif


unsigned int hyfi_netfilter_forwarding_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *) );

unsigned int hyfi_netfilter_local_out_hook(unsigned int hooknum,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *));

unsigned int hyfi_netfilter_local_in_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *) );

unsigned int hyfi_netfilter_pre_routing_hook( unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *) );

struct nf_hook_ops hyfi_hook_ops[] __read_mostly =
{
    {
            .pf = NFPROTO_BRIDGE,
            .priority = 1,
            .hooknum = NF_INET_FORWARD,
            .hook = hyfi_netfilter_forwarding_hook,
            .owner = THIS_MODULE,
    },
    {
            .pf = NFPROTO_BRIDGE,
            .priority = 1,
            .hooknum = NF_INET_LOCAL_OUT,
            .hook = hyfi_netfilter_local_out_hook,
            .owner = THIS_MODULE,
    },
    {
            .pf = NFPROTO_BRIDGE,
            .priority = 1,
            .hooknum = NF_INET_LOCAL_IN,
            .hook = hyfi_netfilter_local_in_hook,
            .owner = THIS_MODULE,
    },
    {
            .pf = NFPROTO_BRIDGE,
            .priority = 1,
            .hooknum = NF_INET_PRE_ROUTING,
            .hook = hyfi_netfilter_pre_routing_hook,
            .owner = THIS_MODULE,
    }
};

#define IEEE1905_MULTICAST_ADDR     "\x01\x80\xC2\x00\x00\x13" /* IEEE 1905.1 Multicast address */

unsigned int hyfi_netfilter_forwarding_hook(unsigned int hooknum,
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct hyfi_net_bridge *hyfi_br = hyfi_bridge_get_by_dev(out);
	struct net_bridge_port *br_port = hyfi_br_port_get(out);
	struct hyfi_net_bridge_port *hyfi_dst_p = hyfi_bridge_get_port(br_port);
	struct hyfi_net_bridge_port *hyfi_src_p = hyfi_bridge_get_port_by_dev(in);

	if (unlikely(!hyfi_br || !br_port))
		return NF_ACCEPT;

	if (unlikely( (hyfi_is_ieee1905_pkt(skb)
					&& (!compare_ether_addr(eth_hdr(skb)->h_dest,
							IEEE1905_MULTICAST_ADDR)
							|| is_broadcast_ether_addr(eth_hdr(skb)->h_dest)))
					|| hyfi_is_hcp_pkt(skb))) {
		/* Do not forward IEEE1905.1 and HCP Bcast/Mcast packets */
		return NF_DROP;
	}

	/* Should deliver */
	if (!hyfi_bridge_should_deliver(hyfi_src_p, hyfi_dst_p, skb)) {
	    return NF_DROP;
	}

	/* Should flood */
	if (!hyfi_br->flags & HYFI_BRIDGE_FLAG_MODE_RELAY_OVERRIDE) {
		if (unlikely(is_multicast_ether_addr(eth_hdr(skb)->h_dest))) {
			if (!hyfi_bridge_should_flood(hyfi_dst_p, skb)) {
				return NF_DROP;
			}
		} else {
			if (!__br_fdb_get(br_port->br, eth_hdr(skb)->h_dest)) {
				if (!hyfi_bridge_should_flood(hyfi_dst_p, skb)) {
					return NF_DROP;
				}
			}
		}
	}

#ifndef HYFI_MC_STANDALONE_NF
	return mc_forward_hook(hooknum, skb, in, out, okfn);
#else
	return NF_ACCEPT;
#endif
}

unsigned int hyfi_netfilter_local_out_hook(unsigned int hooknum,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct hyfi_net_bridge *hyfi_br = hyfi_bridge_get_by_dev(out);
    struct net_bridge_port *br_port = hyfi_br_port_get(out);
	struct hyfi_net_bridge_port *hyfi_p = hyfi_bridge_get_port(br_port);

    if (unlikely(!hyfi_br || !br_port || !hyfi_p)) {
        return NF_ACCEPT;
    }

    if (hyfi_brmode_relay_override(hyfi_br)) {
        return NF_ACCEPT;
    }

	/* Should flood */
	if (unlikely(is_multicast_ether_addr(eth_hdr(skb)->h_dest))) {
		if (!hyfi_bridge_should_flood(hyfi_p, skb)) {
			return NF_DROP;
		}
	} else {
		if (!__br_fdb_get(br_port->br, eth_hdr(skb)->h_dest)) {
			if (!hyfi_bridge_should_flood(hyfi_p, skb)) {
				return NF_DROP;
			}
		}
	}

	return NF_ACCEPT;
}

unsigned int hyfi_netfilter_local_in_hook(unsigned int hooknum,
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct hyfi_net_bridge *hyfi_br = hyfi_bridge_get_by_dev(in);

    if (unlikely(!hyfi_br))
        return NF_ACCEPT;

	/* Is it an IEEE1905.1/LLDP/HCP packet? */
	if (unlikely(
			hyfi_ieee1905_frame_filter(skb, in) || hyfi_is_lldp_pkt(skb)
					|| hyfi_hcp_frame_filter(skb, in))) {

		if (likely(hyfi_br)) {
			struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);

			if (skb2) {
				skb2->dev = hyfi_br->dev;
				netif_receive_skb(skb2);
			}

			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

unsigned int hyfi_netfilter_pre_routing_hook(unsigned int hooknum,
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct hyfi_net_bridge *hyfi_br = hyfi_bridge_get_by_dev(in);
	struct net_bridge_port *br_port = hyfi_br_port_get(in);
	struct hyfi_net_bridge_port *hyfi_p  = hyfi_bridge_get_port(br_port);
	struct net_bridge_fdb_entry *dst;

	if (unlikely(hyfi_is_ieee1901_pkt(skb) && hyfi_br)) {
		struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);

		if (skb2) {
			memcpy(eth_hdr(skb2)->h_dest, hyfi_br->dev->dev_addr, ETH_ALEN);
			skb2->pkt_type = PACKET_HOST;
			skb2->dev = hyfi_br->dev;
			netif_receive_skb(skb2);
		}

		return NF_DROP;
	}

	if (!hyfi_br || !br_port || !hyfi_p)
		return NF_ACCEPT;

	if (hyfi_brmode_relay_override(hyfi_br)) {
		goto out;
	}

	if (unlikely(
			(!hyfi_p->bcast_enable)
					&& (is_multicast_ether_addr(eth_hdr(skb)->h_dest)))) {
		if (hyfi_is_ieee1905_pkt(skb) || hyfi_is_lldp_pkt(skb)
				|| hyfi_is_hcp_pkt(skb)) {
			return NF_ACCEPT;
		} else {
			/* Drop broadcast and multicast packets on non-broadcast enabled ports */
			return NF_DROP;
		}
	}

	if ((dst = __br_fdb_get(br_port->br, eth_hdr(skb)->h_source))) {
		if (!hyfi_fdb_should_update(hyfi_br, br_port, dst->dst)) {
			/* Drop packet, do not update fdb */
			return NF_DROP;
		}
	}

	out:
#ifndef HYFI_MC_STANDALONE_NF
	return mc_pre_routing_hook(hooknum, skb, in, out, okfn);
#else
	return NF_ACCEPT;
#endif
}

int hyfi_netfilter_init(void)
{
	int ret = 0;

	/* Register netfilter hooks */
	ret = nf_register_hooks(hyfi_hook_ops, ARRAY_SIZE(hyfi_hook_ops));

	return ret;
}

void hyfi_netfilter_fini(void)
{
	nf_unregister_hooks(hyfi_hook_ops, ARRAY_SIZE(hyfi_hook_ops));
}
