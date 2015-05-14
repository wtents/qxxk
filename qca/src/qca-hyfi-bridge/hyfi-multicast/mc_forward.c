/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
*/
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/if_ether.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <net/inet_ecn.h>

#include "mc_private.h"
#include "mc_snooping.h"
#include "hyfi_osdep.h"
#include "hyfi_bridge.h"
#include "hyfi_hatbl.h"

static void mc_retag(void *iph, __be16 etype, __be32 dscp)
{
    __be32 _dscp = MC_DSCP(dscp);

    if (etype == ETH_P_IP) {
        ipv4_copy_dscp(_dscp, iph);
    } 
#ifdef HYBRID_MC_MLD
    else if (etype == ETH_P_IPV6) {
        ipv6_copy_dscp(_dscp, iph);
    }
#endif
}

static int mc_encap_check_source(int pro, void *srcs, int offset, void *iph)
{
    if (pro == htons(ETH_P_IP)) {
        return (*((__be32 *)srcs + offset) == ((struct iphdr *)iph)->saddr);
    }
#ifdef HYBRID_MC_MLD
    else {
        return (!ipv6_addr_cmp((struct in6_addr *)srcs + offset, &((struct ipv6hdr *)iph)->saddr));
    }
#endif
    return 0;
}

static int mc_encap_filter_source(struct __mc_encaptbl_dev *dev, void *ip, __be16 pro)
{
    int n = 0;

    if (!dev->in_nsrcs && !dev->ex_nsrcs)
        return 0;

    /* Check INCLUDE list first */
    for (n = 0; n < dev->in_nsrcs; n++) {
        if (mc_encap_check_source(pro, dev->in_srcs, n, ip))
            break;
    }
    if (n != dev->in_nsrcs)
        return 0;

    /* Then check EXCLUDE list */
    if (dev->ex_nsrcs == HYFI_MC_EX_SRCS_INVAL)
        return 1;
    for (n = 0; n < dev->ex_nsrcs; n++) {
        if (mc_encap_check_source(pro, dev->ex_srcs, n, ip))
            break;
    }
    if (n == dev->ex_nsrcs)
        return 0;
 
    return 1;
}

static void mc_encap_hook(struct net_bridge *br, 
        struct __mc_encaptbl_dev *encap_dev, 
        struct sk_buff *skb, int forward)
{
    struct net_bridge_port *pdst = NULL;
    memcpy(eth_hdr(skb)->h_dest, encap_dev->mac, ETH_ALEN);

    pdst = hyfi_bridge_get_dst(hyfi_br_port_get(skb->dev), &skb);

    if (pdst) {
        if (!skb || pdst == (struct net_bridge_port *)-1)
            goto out;

        if (forward)
            hyfi_br_forward(pdst, skb);
        else
            br_deliver(pdst, skb);
    }
out: 
    if (skb && !pdst)
        kfree_skb(skb);
}

static int mc_do_encap(struct mc_mdb_entry *mdb, void *iph, struct sk_buff *skb, int forward)
{
    int i;
    struct net_bridge *br = netdev_priv(mdb->mc->dev);
    struct __mc_encaptbl_dev *prev = NULL;
    struct mc_struct *mc = mdb->mc;

    if (!mdb->encap_dev_cnt) {
        kfree_skb(skb);
        return 0;
    }

    if (mc->debug && printk_ratelimit()) {
        if (mdb->group.pro == htons(ETH_P_IP)) {
            MC_PRINT("Encap the Group "MC_IP4_STR" to following QCA devices:\n", 
                    MC_IP4_FMT((u8 *)(&mdb->group)));
        } else {
            MC_PRINT("Encap the Group "MC_IP6_STR" to following QCA devices:\n",
                    MC_IP6_FMT((__be16 *)(&mdb->group)));
        }
        read_lock(&mdb->rwlock);
        for (i = 0; i < mdb->encap_dev_cnt; i++) {
            MC_PRINT("  -- "MC_MAC_STR"\n", MC_MAC_FMT(mdb->encap_dev[i].mac));
        }
        read_unlock(&mdb->rwlock);
    }

    read_lock(&mdb->rwlock);
    for (i = 0; i < mdb->encap_dev_cnt; i++) {
        if (mc_encap_filter_source(&mdb->encap_dev[i], iph, mdb->group.pro))
            continue;
        if (prev != NULL) {
            struct sk_buff *skb2;

            if ((skb2 = skb_copy(skb, GFP_ATOMIC)) == NULL) {
                kfree_skb(skb);
                read_unlock(&mdb->rwlock);
                return -ENOMEM;
            }
            mc_encap_hook(br, prev, skb2, forward);
        }
        prev = &mdb->encap_dev[i];
    }

    if (prev) {
        if (!(skb = skb_unshare(skb, GFP_ATOMIC))) {
            read_unlock(&mdb->rwlock);
            return -EINVAL;
        }
        mc_encap_hook(br, prev, skb, forward);
    } else {
        kfree_skb(skb);
    }

    read_unlock(&mdb->rwlock);

    return 0;
}

static void mc_flood_hook(__be32 ifindex, struct sk_buff *skb, int forward)
{
    struct net_device *dev;
    struct net_bridge_port *br_port;
 
    if (!(dev = dev_get_by_index(&init_net, ifindex))) 
        return;

    br_port = hyfi_br_port_get(dev);
    if (!br_port)
        goto out;

	hyfi_hatbl_update_mcast_stats(br_port->br, skb, br_port);

    if (forward) {
        hyfi_br_forward(br_port, skb);
    }
    else {
        br_deliver(br_port, skb);
    }
out:
    dev_put(dev);
}

static int mc_do_flood(struct mc_mdb_entry *mdb, struct sk_buff *skb, int forward)
{
    int i;
    __be32 prev = 0;
    struct sk_buff *skb2;
    struct mc_struct *mc = mdb->mc;

    if (mc->debug && printk_ratelimit()) {
        if (mdb->group.pro == htons(ETH_P_IP)) {
            MC_PRINT("Flood the Group "MC_IP4_STR" to following interfaces:\n", 
                    MC_IP4_FMT((u8 *)(&mdb->group)));
        } else {
            MC_PRINT("Flood the Group "MC_IP6_STR" to following interfaces:\n",
                    MC_IP6_FMT((__be16 *)(&mdb->group)));
        }
        read_lock(&mdb->rwlock);
        for (i = 0; i < mdb->flood_ifcnt; i++) {
            struct net_device *dev = dev_get_by_index(&init_net, mdb->flood_ifindex[i]);
            MC_PRINT("  -- %s\n", dev->name);
            dev_put(dev);
        }
        read_unlock(&mdb->rwlock);
    }

    read_lock(&mdb->rwlock);
    for (i = 0; i < mdb->flood_ifcnt; i++) {
        if (prev) {
            if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
                kfree_skb(skb);
                read_unlock(&mdb->rwlock);
                return -ENOMEM;
            }
            mc_flood_hook(prev, skb2, forward);
        }
        prev = mdb->flood_ifindex[i];
    }
    if (prev) 
        mc_flood_hook(prev, skb, forward);
    read_unlock(&mdb->rwlock);

    return 0;
}

static int mc_convert(struct mc_struct *mc, struct sk_buff *skb, int forward)
{
    __be16 etype = 0;
    struct ethhdr *eh;
    const struct iphdr *ip;
#ifdef HYBRID_MC_MLD
    const struct ipv6hdr *ip6;
#endif
    struct mc_ip group;
    struct hlist_head *head;
    struct mc_mdb_entry *mdb;
    void *iph = NULL;
    struct sk_buff *skb2 = NULL;
    int is_management;

    eh = eth_hdr(skb);
    etype = ntohs(eh->h_proto);

    if (forward && (MC_SKB_CB(skb)->igmp || MC_SKB_CB(skb)->non_snoop))
        goto out;

    switch (etype) {
        case ETH_P_IP:
            ip = ip_hdr(skb);
            if (!forward && (ip->protocol == IPPROTO_IGMP ||
                        mc_find_acl_rule(&mc->igmp_acl, ip->daddr, NULL,
                            eh->h_dest, MC_ACL_RULE_NON_SNOOPING)))
                goto out;

            if (!mc->convert_all && ip->protocol != IPPROTO_UDP)
                goto out;

            is_management = mc_find_acl_rule(&mc->igmp_acl, ip->daddr, NULL, 
                    eh->h_dest, MC_ACL_RULE_MANAGEMENT);

            memset(&group, 0, sizeof group);
            group.u.ip4 = ip->daddr;
            group.pro = htons(ETH_P_IP);
            iph = (void *)ip;
            break;
#ifdef HYBRID_MC_MLD
        case ETH_P_IPV6:
            ip6 = ipv6_hdr(skb);
            if (!forward && (ip6->nexthdr == IPPROTO_ICMPV6 ||
                        mc_find_acl_rule(&mc->mld_acl, 0, (void *)&ip6->daddr,
                            eh->h_dest, MC_ACL_RULE_NON_SNOOPING)))
                goto out;

            if (!mc->convert_all && ip6->nexthdr != IPPROTO_UDP)
                goto out;

            is_management = mc_find_acl_rule(&mc->mld_acl, 0, (void *)&ip6->daddr,
                    eh->h_dest, MC_ACL_RULE_MANAGEMENT);

            memset(&group, 0, sizeof group);
            hyfi_ipv6_addr_copy(&group.u.ip6, &ip6->daddr);
            group.pro = htons(ETH_P_IPV6);
            iph = (void *)ip6;
            break;
#endif
        default:
            goto out;
    }

    head = &mc->hash[mc_group_hash(mc->salt, group.u.ip4)];
    mdb = mc_mdb_find(head, &group);
    if (!mdb || !atomic_read(&mdb->users)) {
        if (mc->forward_policy == MC_POLICY_FLOOD || is_management)
            goto out;
        kfree_skb(skb);
        return 0;
    }

    if (mc->enable_retag)
        mc_retag(iph, etype, mc->dscp);

    if (mdb->flood_ifcnt) {
        if (!(skb2 = skb_clone(skb, GFP_ATOMIC)) || 
                (mc_do_flood(mdb, skb2, forward) < 0)) {
            kfree_skb(skb);
            return 0;
        }
    }

    mc_do_encap(mdb, iph, skb, forward);

    return 0;
out:
    return -EINVAL;
}

static int mc_process(const struct net_bridge_port *src, struct sk_buff *skb)
{
	struct net_bridge *br;
    struct hyfi_net_bridge *hyfi_br;
    struct mc_struct *mc;
    void *fdb;

    if (!src) {
    	hyfi_br = hyfi_bridge_get_by_dev(BR_INPUT_SKB_CB(skb)->brdev);
    } else {
    	br = src->br;
    	hyfi_br = hyfi_bridge_get(br);
    }

    mc = MC_DEV(hyfi_br);

    if (!mc || !mc->started || 
            is_broadcast_ether_addr(eth_hdr(skb)->h_dest))
        return -EINVAL;

    if (!src)
        return mc_convert(mc, skb, 0);

    fdb = __br_fdb_get(br, eth_hdr(skb)->h_source);

    if (!fdb)
        return -EINVAL;

    MC_SKB_CB(skb)->fdb = fdb;
    MC_SKB_CB(skb)->port = (void *)src;

    if (mc_rcv(mc, skb)) {
        kfree_skb(skb);
        return 0;
    }
    
    return mc_convert(mc, skb, 1);
}

int mc_forward_init(void)
{
    rcu_assign_pointer(br_multicast_handle_hook, mc_process);

    return 0;
}

void mc_forward_exit(void)
{
    rcu_assign_pointer(br_multicast_handle_hook, NULL);
}

