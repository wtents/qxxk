/*
 **************************************************************************
 * Copyright (c) 2013, The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **************************************************************************
 */

/*
 * nss_tun6rd.c
 *
 * This file is the NSS 6rd tunnel module
 * ------------------------REVISION HISTORY-----------------------------
 * Qualcomm Atheros         15/sep/2013              Created
 */

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <net/ipip.h>
#include <linux/if_arp.h>
#include "nss_api_if.h"
#include "nss_hlos_if.h"

/*
 * NSS tun6rd debug macros
 */
#if (NSS_TUN6RD_DEBUG_LEVEL < 1)
#define nss_tun6rd_assert(fmt, args...)
#else
#define nss_tun6d_assert(c) if (!(c)) { BUG_ON(!(c)); }
#endif

#if (NSS_TUN6RD_DEBUG_LEVEL < 2)
#define nss_tun6rd_error(fmt, args...)
#else
#define nss_tun6rd_error(fmt, args...) printk(KERN_WARNING "nss tun6rd:"fmt, ##args)
#endif

#if (NSS_TUN6RD_DEBUG_LEVEL < 3)
#define nss_tun6rd_warning(fmt, args...)
#else
#define nss_tun6rd_warning(fmt, args...) printk(KERN_WARNING "nss tun6rd:"fmt, ##args)
#endif

#if (NSS_TUN6RD_DEBUG_LEVEL < 4)
#define nss_tun6rd_info(fmt, args...)
#else
#define nss_tun6rd_info(fmt, args...) printk(KERN_INFO "nss tun6rd :"fmt, ##args)
#endif

#if (NSS_TUN6RD_DEBUG_LEVEL < 5)
#define nss_tun6rd_trace(fmt, args...)
#else
#define nss_tun6rd_trace(fmt, args...) printk(KERN_DEBUG "nss tun6rd :"fmt, ##args)
#endif

void nss_tun6rd_exception(void *ctx, void *buf);
void nss_tun6rd_event_receive(void *ctx, nss_tun6rd_event_t ev_type,
			      void *os_buf, uint32_t len);

enum tun6rd_metadata_types {
	TUN6RD_METADATA_TYPE_IF_UP,
	TUN6RD_METADATA_TYPE_IF_DOWN
};

/*
 * 6rd configuration command structure
 */
struct nss_tunnel_6rd_cfg{
	uint32_t prefix[4]; /*6rd prefix */
	uint32_t relay_prefix; /* Relay prefix */
	uint16_t prefixlen; /* 6rd prefix len */
	uint16_t relay_prefixlen; /* Relay prefix length*/
	uint32_t saddr; /* Tunnel source address */
	uint32_t daddr; /* Tunnel destination addresss */
	uint8_t  tos; /* Tunnel tos field */
	uint8_t  ttl; /* Tunnel ttl field */

};

/*
 * 6rd tunnel interface down command structure
 */
struct tun6rd_if_down_param{
	uint32_t prefix[4]; /*Tunnel 6rd prefix */
};

/*
 * 6rd Tunnel generic param
 */
struct nss_tunnel_6rd_param {
	enum tun6rd_metadata_types  type;
	union {
		struct nss_tunnel_6rd_cfg   cfg;
		struct tun6rd_if_down_param ifdown_param;
	}sub;
};

/*
 * 6rd tunnel host instance
 */
struct nss_tun6rd_tunnel{
	void *nss_ctx;
	uint32_t if_num;
	struct net_device *netdev;
	uint32_t device_up;
};

/*
 * 6rd tunnel stats
 */
struct nss_tun6rd_stats{
	uint32_t rx_packets;
	uint32_t rx_bytes;
	uint32_t tx_packets;
	uint32_t tx_bytes;
};

struct nss_tun6rd_tunnel g_tun6rd;

/*
 * Internal function
 */
static int
nss_tun6rd_dev_event(struct notifier_block  *nb,
			unsigned long event,
			void  *dev);

/*
 * Linux Net device Notifier
 */
struct notifier_block nss_tun6rd_notifier = {
	.notifier_call = nss_tun6rd_dev_event,
};

/*
 * nss_tun6rd_dev_up()
 *	6RD Tunnel device i/f up handler
 */
void nss_tun6rd_dev_up( struct net_device * netdev)
{
	struct ip_tunnel *tunnel;
	struct ip_tunnel_6rd_parm *ip6rd;
	const struct iphdr  *tiph;
	struct nss_tunnel_6rd_param tun6rdparam;
	struct nss_tunnel_6rd_cfg   *tun6rdcfg;
	nss_tx_status_t status;

	/*
	 * Validate netdev for ipv6-in-ipv4  Tunnel
	 */
	if (netdev->type != ARPHRD_SIT ) {
		return;
	}

	tunnel = (struct ip_tunnel*)netdev_priv(netdev);
	ip6rd =  &tunnel->ip6rd;

	/*
	 * Valid 6rd Tunnel Check
	 * 1. 6rd Prefix len should be non zero
	 * 2. Relay prefix length should not be greater then 32
	 * 3. To allow for stateless address auto-configuration on the CE LAN side,
	 *    6rd delegated prefix SHOULD be /64 or shorter.
	 */
	if ((ip6rd->prefixlen == 0 )
			|| (ip6rd->relay_prefixlen > 32)
			|| (ip6rd->prefixlen
				+ (32 - ip6rd->relay_prefixlen) > 64)){

		nss_tun6rd_error("Invalid 6rd argument prefix len %d     \
				relayprefix len %d \n",
				ip6rd->prefixlen,ip6rd->relay_prefixlen);
		return;
	}

	nss_tun6rd_info(" Valid 6rd Tunnel Prefix %x %x %x %x  \n        \
			prefix len %d  relay_prefix %d relay_prefixlen %d \n",
			ip6rd->prefix.s6_addr32[0],ip6rd->prefix.s6_addr32[1],
			ip6rd->prefix.s6_addr32[2],ip6rd->prefix.s6_addr32[3],
			ip6rd->prefixlen, ip6rd->relay_prefix,
			ip6rd->relay_prefixlen);

	/*
	 * Prepare The Tunnel configuration parameter to send to nss
	 */
	memset( &tun6rdparam, 0, sizeof(struct nss_tunnel_6rd_param));
	tun6rdparam.type = TUN6RD_METADATA_TYPE_IF_UP;
	tun6rdcfg = (struct nss_tunnel_6rd_cfg *)&tun6rdparam.sub.cfg;

	/*
	 * Find the Tunnel device ipHeader info
	 */
	tiph = &tunnel->parms.iph ;
	nss_tun6rd_trace(" Tunnel Param srcaddr %x daddr %x ttl %d tos %x\n",
			tiph->saddr, tiph->daddr,tiph->ttl,tiph->tos);

	if(tiph->saddr == 0) {
		nss_tun6rd_error("Tunnel src address not configured  %x\n",
				tiph->saddr);
		return;
	}

	if (tiph->daddr == 0) {
		nss_tun6rd_error("Tunnel dest address not configured  %x\n",
				tiph->daddr);
		return;
	}

	tun6rdcfg->prefixlen       = ip6rd->prefixlen;
	tun6rdcfg->relay_prefix    = ip6rd->relay_prefix;
	tun6rdcfg->relay_prefixlen = ip6rd->relay_prefixlen;
	tun6rdcfg->saddr           = ntohl(tiph->saddr);
	tun6rdcfg->daddr           = ntohl(tiph->daddr);
	tun6rdcfg->prefix[0]       = ntohl(ip6rd->prefix.s6_addr32[0]);
	tun6rdcfg->prefix[1]       = ntohl(ip6rd->prefix.s6_addr32[1]);
	tun6rdcfg->prefix[2]       = ntohl(ip6rd->prefix.s6_addr32[2]);
	tun6rdcfg->prefix[3]       = ntohl(ip6rd->prefix.s6_addr32[3]);
	tun6rdcfg->ttl             = tiph->ttl;
	tun6rdcfg->tos             = tiph->tos;

        nss_tun6rd_trace(" 6rd Tunnel info \n");
        nss_tun6rd_trace(" saddr %x daddr %d ttl %x  tos %x \n",
			tiph->saddr, tiph->daddr, tiph->ttl, tiph->tos);
	nss_tun6rd_trace(" Prefix %x:%x:%x:%x  Prefix len %d \n",
			ip6rd->prefix.s6_addr32[0], ip6rd->prefix.s6_addr32[1],
			ip6rd->prefix.s6_addr32[2], ip6rd->prefix.s6_addr32[3],
			ip6rd->prefixlen);
	nss_tun6rd_trace("Relay Prefix %x Len %d\n",
			ip6rd->relay_prefix, ip6rd->relay_prefixlen);

	/*
	 * Register 6rd tunnel with NSS
	 */
	g_tun6rd.nss_ctx = nss_register_tun6rd_if(g_tun6rd.if_num,
				nss_tun6rd_exception,
				nss_tun6rd_event_receive,
				netdev);
	if (g_tun6rd.nss_ctx == NULL) {
		nss_tun6rd_trace("nss_register_tun6rd_if Failed \n");
		return;
	} else {
		nss_tun6rd_trace("nss_register_tun6rd_if Success \n");
	}

	nss_tun6rd_trace("Sending 6rd tunnel i/f up command to NSS  %x \n",
			(int)g_tun6rd.nss_ctx);

	/*
	 * Send 6rd Tunnel UP command to NSS
	 */
	status = nss_tx_generic_if_buf(g_tun6rd.nss_ctx,
			g_tun6rd.if_num,
			(uint8_t *)&tun6rdparam,
			sizeof(struct nss_tunnel_6rd_param));

	if (status != NSS_TX_SUCCESS) {
		nss_tun6rd_error("Tunnel up command error %d \n", status);
		return;
	}

	g_tun6rd.device_up = 1;
}

/*
 * nss_tun6rd_dev_down()
 *	6RD Tunnel device i/f down handler
 */
void nss_tun6rd_dev_down( struct net_device * netdev)
{
	struct ip_tunnel *tunnel;
	struct ip_tunnel_6rd_parm *ip6rd;
	struct nss_tunnel_6rd_param tun6rdparam;
	struct tun6rd_if_down_param *ifdown;
	nss_tx_status_t status;

	/*
	 * Check if tunnel 6rd is registered ?
	 */
	if (g_tun6rd.nss_ctx == NULL) {
		return;
	}

	/*
	 * Validate netdev for ipv6-in-ipv4  Tunnel
	 */
	if (netdev->type != ARPHRD_SIT ) {
		return;
	}

	tunnel = (struct ip_tunnel*)netdev_priv(netdev);
	ip6rd =  &tunnel->ip6rd;

	/*
	 * Valid 6rd Tunnel Check
	 */
	if ((ip6rd->prefixlen == 0 )
			|| (ip6rd->relay_prefixlen > 32 )
			|| (ip6rd->prefixlen
				+ (32 - ip6rd->relay_prefixlen) > 64)){

		nss_tun6rd_error("Invalid 6rd argument prefix len %d  \
				relayprefix len %d \n",
				ip6rd->prefixlen,ip6rd->relay_prefixlen);
		return;
	}

	memset( &tun6rdparam, 0, sizeof(struct nss_tunnel_6rd_param));
	tun6rdparam.type = TUN6RD_METADATA_TYPE_IF_DOWN;
	ifdown = (struct tun6rd_if_down_param *)&tun6rdparam.sub.ifdown_param;
	ifdown->prefix[0]       = ntohl(ip6rd->prefix.s6_addr32[0]);
	ifdown->prefix[1]       = ntohl(ip6rd->prefix.s6_addr32[1]);
	ifdown->prefix[2]       = ntohl(ip6rd->prefix.s6_addr32[2]);
	ifdown->prefix[3]       = ntohl(ip6rd->prefix.s6_addr32[3]);

	nss_tun6rd_trace(" Prefix %x:%x:%x:%x  Prefix len %d \n",
			ip6rd->prefix.s6_addr32[0], ip6rd->prefix.s6_addr32[1],
			ip6rd->prefix.s6_addr32[2], ip6rd->prefix.s6_addr32[3],
			ip6rd->prefixlen);


	nss_tun6rd_trace("Sending Tunnle 6rd Down command %x \n",g_tun6rd.if_num);
	status = nss_tx_generic_if_buf(g_tun6rd.nss_ctx,
			g_tun6rd.if_num,
			(uint8_t *)&tun6rdparam,
			sizeof(struct nss_tunnel_6rd_param));

	if (status != NSS_TX_SUCCESS) {
		nss_tun6rd_error("Tunnel down command error %d \n", status);
		return;
	}

	/*
	 * Un-Register 6rd tunnel with NSS
	 */
	nss_unregister_tun6rd_if(g_tun6rd.if_num);
	g_tun6rd.nss_ctx = NULL;
	g_tun6rd.device_up = 0;
	return;
}

/*
 * nss_tun6rd_dev_event()
 *	Net device notifier for 6rd module
 */
static int nss_tun6rd_dev_event(struct notifier_block  *nb,
		unsigned long event, void  *dev)
{
	struct net_device *netdev = (struct net_device *)dev;

	nss_tun6rd_trace("%s\n",__FUNCTION__);
	switch (event) {
	case NETDEV_UP:
		nss_tun6rd_trace(" NETDEV_UP :event %lu name %s \n",
				event,netdev->name);
		nss_tun6rd_dev_up(netdev);
		break;

	case NETDEV_DOWN:
		nss_tun6rd_trace(" NETDEV_DOWN :event %lu name %s \n",
				event,netdev->name);
		nss_tun6rd_dev_down(netdev);
		break;

	default:
		nss_tun6rd_trace("Unhandled notifier dev %s  event %x  \n",
				netdev->name,(int)event);
		break;
	}

	return NOTIFY_DONE;
}

/*
 * nss_tun6rd_exception()
 *	Exception handler registered to NSS driver
 */
void nss_tun6rd_exception(void *ctx, void *buf)
{
	struct net_device *dev = (struct net_device *)ctx;
	struct sk_buff *skb = (struct sk_buff *)buf;
	const struct iphdr *iph;

	skb->dev = dev;
	nss_tun6rd_info("received - %d bytes name %s ver %x \n",
			skb->len,dev->name,skb->data[0]);

	iph = (const struct iphdr *)skb->data;

	/*
	 * Packet after Decap/Encap Did not find the Rule.
	 */
	if (iph->version == 4) {
		if(iph->protocol == IPPROTO_IPV6){
			skb_pull(skb, sizeof(struct iphdr));
			skb->protocol = htons(ETH_P_IPV6);
			skb_reset_network_header(skb);
			skb->pkt_type = PACKET_HOST;
			skb->ip_summed = CHECKSUM_NONE;
			dev_queue_xmit(skb);
			return;
		}
		skb->protocol = htons(ETH_P_IP);
	} else {
		skb->protocol = htons(ETH_P_IPV6);
	}

	skb_reset_network_header(skb);
	skb->pkt_type = PACKET_HOST;
	skb->skb_iif = dev->ifindex;
	skb->ip_summed = CHECKSUM_NONE;
	netif_receive_skb(skb);
}

/*
 *  nss_tun6rd_update_dev_stats
 *	Update the Dev stats received from NetAp
 */
static void nss_tun6rd_update_dev_stats(struct net_device *dev,
					struct nss_tun6rd_stats_sync *tun6rdstats)
{
	void *ptr;
	struct nss_tun6rd_stats stats;

	stats.rx_packets = tun6rdstats->rx_packets;
	stats.rx_bytes = tun6rdstats->rx_bytes;
	stats.tx_packets = tun6rdstats->tx_packets;
	stats.tx_bytes = tun6rdstats->tx_bytes;
	ptr = (void *)&stats;
	ipip6_update_offload_stats(dev, ptr);
}

/**
 * @brief Event Callback to receive events from NSS
 * @param[in] pointer to net device context
 * @param[in] event type
 * @param[in] pointer to buffer
 * @param[in] length of buffer
 * @return Returns void
 */
void nss_tun6rd_event_receive(void *if_ctx, nss_tun6rd_event_t ev_type,
			    void *os_buf, uint32_t len)
{
	struct net_device *netdev = NULL;
	netdev = (struct net_device *)if_ctx;

	switch (ev_type) {
	case NSS_TUN6RD_EVENT_STATS:
		nss_tun6rd_update_dev_stats(netdev, (struct nss_tun6rd_stats_sync *)os_buf );
		break;

	default:
		nss_tun6rd_info("%s: Unknown Event from NSS",
			      __FUNCTION__);
		break;
	}
}

/*
 * nss_tun6rd_init_module()
 *	Tunnel 6rd module init function
 */
int __init nss_tun6rd_init_module(void)
{
	nss_tun6rd_info("module (platform - IPQ806x , Build - %s:%s) loaded\n",
			__DATE__, __TIME__);

	register_netdevice_notifier(&nss_tun6rd_notifier);
	nss_tun6rd_trace("Netdev Notifier registerd \n");

	g_tun6rd.if_num = NSS_TUNRD_IF_NUMBER;
	g_tun6rd.netdev = NULL;
	g_tun6rd.device_up = 0;
	g_tun6rd.nss_ctx = NULL;

	return 0;
}

/*
 * nss_tun6rd_exit_module()
 *	Tunnel 6rd module exit function
 */
void __exit nss_tun6rd_exit_module(void)
{

	unregister_netdevice_notifier(&nss_tun6rd_notifier);
	nss_tun6rd_info("module unloaded\n");
}

module_init(nss_tun6rd_init_module);
module_exit(nss_tun6rd_exit_module);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("NSS tun6rd offload manager");
