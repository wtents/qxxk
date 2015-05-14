/*
 * Copyright (c) 2012 The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

#ifndef HYFI_FILTERS_H_
#define HYFI_FILTERS_H_

#include <linux/skbuff.h>

static inline int hyfi_is_hcp_pkt(struct sk_buff *skb)
{
	struct ethhdr *ethhdr = eth_hdr(skb);
	static const u8 ATH_OUI[3] = { 0x00, 0x03, 0x7f }; /* to be replaced with a define */

	if (unlikely(ethhdr->h_proto == htons(0x88b7))) {
		u8 *data = (u8 *) ethhdr;
		u8 *OUIPtr = data + ETH_HLEN;
		u16 ID = get_unaligned((u16*) (OUIPtr + 3));
		if (!memcmp(ATH_OUI, OUIPtr, sizeof ATH_OUI) && (htons(0x0000) == ID)) {
			return 1;
		}
	}
	return 0;
}

static inline int hyfi_hcp_frame_filter(struct sk_buff *skb,
		const struct net_device *dev)
{
	if (unlikely(hyfi_is_hcp_pkt(skb))) {
		u8 *data = (u8 *) eth_hdr(skb);
		put_unaligned(htonl(dev->ifindex), (u32*) (data + 33)); /* The number is to be replaced with a define */
		return 1;
	}

	return 0;
}

static inline int hyfi_is_ieee1905_pkt(struct sk_buff *skb)
{
	struct ethhdr *ethhdr = eth_hdr(skb);

	if (unlikely(ethhdr->h_proto == htons(0x893A))) {
		return 1;
	}

	return 0;
}

static inline int hyfi_is_ieee1901_pkt(struct sk_buff *skb)
{
	struct ethhdr *ethhdr = eth_hdr(skb);

	if (unlikely(ethhdr->h_proto == htons(0x88E1))) {
		return 1;
	}

	return 0;
}

static inline int hyfi_is_lldp_pkt(struct sk_buff *skb)
{
	struct ethhdr *ethhdr = eth_hdr(skb);

	if (unlikely(ethhdr->h_proto == htons(0x88CC))) {
		return 1;
	}

	return 0;
}

static inline int hyfi_ieee1905_frame_filter(struct sk_buff *skb,
		const struct net_device *dev)
{
	if (unlikely(hyfi_is_ieee1905_pkt(skb))) {
		u8 *data = (u8 *) eth_hdr(skb);
		u8 ifindex = (u8) (dev->ifindex);
		put_unaligned(ifindex,
				(u8 *) (data + sizeof(struct ethhdr) + 1));
		return 1;
	}

	return 0;
}

#endif /* HYFI_FILTERS_H_ */
