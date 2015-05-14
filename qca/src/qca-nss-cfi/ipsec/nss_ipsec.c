/* Copyright (c) 2013, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */

/**
 * @file NSS IPsec offload manager
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/dst.h>

#include <nss_api_if.h>
#include <nss_cfi_if.h>
#include "nss_ipsec.h"


/*
 * tunnel list head, the protection is required for accessing the
 * list. The integrity of the object will require some type of
 * reference count so that delete doesn't happen when the create
 * is working on it.
 */

static void *gbl_nss_ctx = NULL;
static struct net_device *gbl_except_dev = NULL;
static spinlock_t gbl_dev_lock;

/*
 * IPsec stats param structure
 */
struct nss_ipsec_stats_param {
	uint32_t rule_drop;	/* push rule failed due to NSS driver */
	uint32_t rule_fail;	/* other push rule errors */
};

static struct nss_ipsec_stats_param param;

/*
 * This is used by KLIPS for communicate the device along with the
 * packet. We need this to derive the mapping of the incoming flow
 * to the IPsec tunnel
 */
struct nss_ipsec_skb_cb {
	struct net_device *ipsec_dev;
};

/*
 * IPsec rule table structure.
 */
struct nss_ipsec_rule_tbl {
	struct nss_ipsec_rule_entry entry[NSS_IPSEC_TBL_MAX_ENTRIES];

	uint32_t free_count;
	uint32_t num_pending_sync;

	uint32_t if_num;

	spinlock_t lock;
	wait_queue_head_t waitq;
};

static struct nss_ipsec_rule_tbl gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_MAX];

typedef void (*nss_ipsec_sync_op_t)(struct nss_ipsec_rule_tbl *, struct nss_ipsec_rule_sync *);

/*
 * nss_ipsec_get_ipsec_dev()
 * 	get ipsec netdevice from skb. Openswan stack fills up ipsec_dev in skb.
 */
static inline struct net_device * nss_ipsec_get_ipsec_dev(struct sk_buff *skb)
{
	struct net_device *dev;
	dev = (((struct nss_ipsec_skb_cb *)skb->cb)->ipsec_dev);

	return dev;
}

/*
 * nss_ipsec_get_next_hdr()
 * 	get next hdr after IPv4 header.
 */
static inline void * nss_ipsec_get_next_hdr(struct nss_ipsec_ipv4_hdr *ip)
{
	return ((uint8_t *)ip + NSS_IPSEC_IPHDR_SZ);
}

/*
 * nss_ipsec_set_crypto_sid()
 * 	set crpto session id to IPsec rule.
 */
static inline void nss_ipsec_set_crypto_sid(struct nss_ipsec_rule *rule, uint32_t crypto_sid)
{
	struct nss_ipsec_rule_data *data = &rule->type.push.data;

	data->crypto_sid = crypto_sid;
}

/*
 * nss_ipsec_copy_from_sync()
 * 	copy selector and data info from sync message received.
 */
static inline void nss_ipsec_copy_from_sync(struct nss_ipsec_rule_entry *entry, struct nss_ipsec_rule_sync *sync)
{
	if (sync == NULL) {
		memset(entry, 0, sizeof(struct nss_ipsec_rule_entry));
		entry->aging = NSS_IPSEC_TBL_ENTRY_DELETED;
		return;
	}

	memcpy(&entry->sel, &sync->sel, sizeof(struct nss_ipsec_rule_sel));
	memcpy(&entry->data, &sync->data, sizeof(struct nss_ipsec_rule_data));

	entry->aging = NSS_IPSEC_TBL_ENTRY_ACTIVE;
}

/*
 * nss_ipsec_copy_from_entry()
 * 	copy selector and data info from IPsec rule entry
 */
static inline void nss_ipsec_copy_from_entry(struct nss_ipsec_rule_push *push, struct nss_ipsec_rule_entry *entry)
{
	if (entry->aging == NSS_IPSEC_TBL_ENTRY_DELETED) {
		memset(push, 0, sizeof(struct nss_ipsec_rule_push));
		return;
	}

	memcpy(&push->sel, &entry->sel, sizeof(struct nss_ipsec_rule_sel));
	memcpy(&push->data, &entry->data, sizeof(struct nss_ipsec_rule_data));
}

/*
 * nss_ipsec_parse_packet()
 * 	Parse packet to fill up selector information.
 */
static uint32_t nss_ipsec_parse_packet(struct nss_ipsec_ipv4_hdr *ip, struct nss_ipsec_rule_sel *sel, struct nss_ipsec_rule_data *data)
{
	struct nss_ipsec_tcp_hdr *tcp = NULL;
	struct nss_ipsec_udp_hdr *udp = NULL;
	struct nss_ipsec_esp_hdr *esp = NULL;

	if (ip->ver_ihl != 0x45) {
		nss_cfi_dbg("IPv4 header mismatch:ver_ihl = %d\n", ip->ver_ihl);
		return NSS_IPSEC_RULE_OP_NONE;
	}

	switch(ip->protocol) {
	case IPPROTO_TCP:
		tcp = nss_ipsec_get_next_hdr(ip);

		sel->dst_port = ntohs(tcp->dst_port);
		sel->src_port = ntohs(tcp->src_port);
		sel->dst_ip = ntohl(ip->dst_ip);
		sel->src_ip = ntohl(ip->src_ip);
		sel->proto = IPPROTO_TCP;

		break;

	case IPPROTO_UDP:
		udp = nss_ipsec_get_next_hdr(ip);

		sel->dst_port = ntohs(udp->dst_port);
		sel->src_port = ntohs(udp->src_port);
		sel->dst_ip = ntohl(ip->dst_ip);
		sel->src_ip = ntohl(ip->src_ip);
		sel->proto = IPPROTO_UDP;

		break;

	case IPPROTO_ESP:
		esp = nss_ipsec_get_next_hdr(ip);

		sel->dst_ip = ntohl(ip->dst_ip);
		sel->src_ip = ntohl(ip->src_ip);
		sel->proto = IPPROTO_ESP;
		sel->spi = ntohl(esp->spi);

		break;
	default:
		nss_cfi_dbg("inner IPv4 header mismatch:proto = %d\n", ip->protocol);
		return NSS_IPSEC_RULE_OP_NONE;
	}

	return NSS_IPSEC_RULE_OP_ADD;
}

/*
 * nss_ipsec_sync_none()
 * 	Invalid sync callback.
 */
static void nss_ipsec_sync_none(struct nss_ipsec_rule_tbl *tbl, struct nss_ipsec_rule_sync *sync)
{
	nss_cfi_err("invalid sync callback \n");
}

/*
 * nss_ipsec_sync_add()
 * 	Add an entry to Host IPsec table.
 */
static void nss_ipsec_sync_add(struct nss_ipsec_rule_tbl *tbl, struct nss_ipsec_rule_sync *sync)
{
	struct nss_ipsec_rule_entry *entry;
	uint32_t idx;

	idx = sync->index.num;
	entry = &tbl->entry[idx];

	if (!tbl->free_count) {
		nss_cfi_dbg("table(%p) full, add operation failed\n", tbl);
		return;
	}

	if (entry->aging != NSS_IPSEC_TBL_ENTRY_DELETED) {
		nss_cfi_dbg("table(%p) entry exists, add operation failed\n", tbl);
		return;
	}

	nss_ipsec_copy_from_sync(entry, sync);

	tbl->free_count--;
	nss_cfi_dbg("add_op, table freecnt %d\n", tbl->free_count);
}

/*
 * nss_ipsec_sync_del()
 * 	Delete an entry from Host IPsec table.
 */
static void nss_ipsec_sync_del(struct nss_ipsec_rule_tbl *tbl, struct nss_ipsec_rule_sync *sync)
{
	struct nss_ipsec_rule_entry *entry;
	uint32_t idx;

	idx = sync->index.num;
	entry = &tbl->entry[idx];

	if (tbl->free_count == NSS_IPSEC_TBL_MAX_ENTRIES) {
		nss_cfi_dbg("table(%p) empty, delete operation failed\n", tbl);
		return;
	}

	if (entry->aging == NSS_IPSEC_TBL_ENTRY_DELETED) {
		nss_cfi_dbg("table(%p) entry nonexistent, delete operation failed\n", tbl);
		return;
	}

	nss_ipsec_copy_from_sync(entry, NULL);

	tbl->free_count++;
}

/*
 * nss_ipsec_sync_flush()
 * 	Flush enries mentioned in index bitmap on host.
 */
static void nss_ipsec_sync_flush(struct nss_ipsec_rule_tbl *tbl, struct nss_ipsec_rule_sync *sync)
{
	struct nss_ipsec_rule_entry *entry;
	int i;

	for (i = 0; i < NSS_IPSEC_TBL_MAX_ENTRIES; i++) {
		if (!sync->index.map[i]) {
			continue;
		}

		nss_cfi_info("flushing entry idx %d\n",i);

		entry = &tbl->entry[i];

		nss_cfi_assert(entry->aging != NSS_IPSEC_TBL_ENTRY_DELETED);

		nss_ipsec_copy_from_sync(entry, NULL);

		tbl->free_count++;
	}

	if (waitqueue_active(&tbl->waitq)) {
		tbl->num_pending_sync--;
		wake_up_interruptible(&tbl->waitq);
	}

}

/*
 * nss_ipsec_push_rule()
 * 	Push rule to NSS.
 */
static int nss_ipsec_push_rule(struct nss_ipsec_rule *rule, uint32_t if_num)
{
	const uint32_t size = sizeof(struct nss_ipsec_rule);
	nss_tx_status_t status;

	if (gbl_nss_ctx == NULL) {
		param.rule_fail++;
		nss_cfi_err("nss ctx is NULL, not able to push rule\n");
		return -1;
	}

	nss_cfi_dbg("pushing rule_op %d, for if_num %d with size %d\n", rule->op, if_num, size);

	status = nss_tx_ipsec_rule(gbl_nss_ctx, if_num, 0, (uint8_t *)rule, size);
	if (status != NSS_TX_SUCCESS) {
		param.rule_drop++;
		nss_cfi_dbg("push rule(%d) failed for if_num: %d\n", rule->op, if_num);
		return -1;
	}

	return 0;
}

/*
 * nss_ipsec_push_rule_sync()
 * 	Push rule to NSS synchronously
 */
static int nss_ipsec_push_rule_sync(struct nss_ipsec_rule *rule, struct nss_ipsec_rule_tbl *tbl)
{
	const uint32_t size = sizeof(struct nss_ipsec_rule);
	nss_tx_status_t status;

	if (gbl_nss_ctx == NULL) {
		param.rule_fail++;
		nss_cfi_err("nss ctx is NULL, not able to push rule\n");
		return -1;
	}

	tbl->num_pending_sync++;

	status = nss_tx_ipsec_rule(gbl_nss_ctx, tbl->if_num, 0, (uint8_t *)rule, size);
	if (status != NSS_TX_SUCCESS) {
		param.rule_drop++;
		nss_cfi_dbg("push rule failed for if_num: %d\n", tbl->if_num);
		return -1;
	}

	wait_event_interruptible_timeout(tbl->waitq, (tbl->num_pending_sync == 0), msecs_to_jiffies(5000));

	return 0;
}

/*
 * nss_ipsec_free_rule()
 * 	Free Perticular rule on NSS.
 */
static int nss_ipsec_free_rule(struct nf_conn *ct) __attribute__((unused));
static int nss_ipsec_free_rule(struct nf_conn *ct)
{
	const uint32_t size = sizeof(struct nss_ipsec_rule);
	struct nss_ipsec_rule rule;
	struct nss_ipsec_rule_sel *sel;
	struct nf_conntrack_tuple orig_tuple;
	uint32_t if_num;

	memset(&rule, 0, size);
	sel = &rule.type.push.sel;

	rule.op = NSS_IPSEC_RULE_OP_DEL;

	orig_tuple = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

	sel->src_ip = (uint32_t)orig_tuple.src.u3.ip;
	sel->dst_ip = (uint32_t)orig_tuple.dst.u3.ip;
	sel->proto = (int32_t)orig_tuple.dst.protonum;

	switch (sel->proto) {
	case IPPROTO_TCP:
		sel->src_port = (int32_t)orig_tuple.src.u.tcp.port;
		sel->dst_port = (int32_t)orig_tuple.dst.u.tcp.port;

		if_num = NSS_IPSEC_ENCAP_INTERFACE;

		break;

	case IPPROTO_UDP:
		sel->src_port = (int32_t)orig_tuple.src.u.udp.port;
		sel->dst_port = (int32_t)orig_tuple.dst.u.udp.port;

		if_num = NSS_IPSEC_ENCAP_INTERFACE;

		break;

	case IPPROTO_ESP:
		sel->src_port = 0;
		sel->dst_port = 0;

		if_num = NSS_IPSEC_DECAP_INTERFACE;

		break;

	default:
		nss_cfi_err("%s Unhandled prorocol %d\n",__FUNCTION__, sel->proto);
		return -1;
	}

	nss_cfi_info("deleting rule: src_ip %d , dest_ip %d , proto %d,"
			"src_port %d , dest_port %d\n",sel->src_ip, sel->dst_ip,
			sel->proto, sel->src_port, sel->dst_port);

	sel->src_ip = ntohl(sel->src_ip);
	sel->dst_ip = ntohl(sel->dst_ip);
	sel->src_port = ntohs(sel->src_port);
	sel->dst_port = ntohs(sel->dst_port);

	if (nss_ipsec_push_rule(&rule, if_num) < 0) {
		nss_cfi_err("unable to delete rule: src_ip %d , dest_ip %d ,"
				"proto %d, src_port %d , dest_port %d\n",
				sel->src_ip, sel->dst_ip, sel->proto,
				sel->src_port, sel->dst_port);

		return -1;
	}

	return 0;
}

/*
 * nss_ipsec_free_session()
 * 	Free perticular session on NSS.
 */
static int32_t nss_ipsec_free_session(uint32_t crypto_sid)
{
	const uint32_t size = sizeof(struct nss_ipsec_rule);
	struct nss_ipsec_rule rule;

	memset(&rule, 0, size);
	rule.op = NSS_IPSEC_RULE_OP_DEL_SID;

	nss_ipsec_set_crypto_sid(&rule, crypto_sid);

	if (nss_ipsec_push_rule(&rule, NSS_IPSEC_ENCAP_INTERFACE) < 0) {
		nss_cfi_err("unable to delete session id:%d\n", crypto_sid);
		return -1;
	}

	if (nss_ipsec_push_rule(&rule, NSS_IPSEC_DECAP_INTERFACE) < 0) {
		nss_cfi_err("unable to delete session id:%d\n", crypto_sid);
		return -1;
	}

	return 0;
}

/*
 * nss_ipsec_free_all()
 * 	Free both IPsec encap and decap tables on NSS.
 */
static int32_t nss_ipsec_free_all(void)
{
	struct nss_ipsec_rule rule;
	struct nss_ipsec_rule_tbl *tbl;

	memset(&rule, 0, sizeof(struct nss_ipsec_rule));
	rule.op = NSS_IPSEC_RULE_OP_DEL_ALL;

	tbl = &gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_ENCAP];
	if (nss_ipsec_push_rule_sync(&rule, tbl) < 0) {
		nss_cfi_err("unable to delete all sessions for encap table\n");
		return -1;
	}

	nss_cfi_info("freed up encap table\n");

	tbl = &gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_DECAP];
	if (nss_ipsec_push_rule_sync(&rule, tbl) < 0) {
		nss_cfi_err("unable to delete all sessions for decap table\n");
		return -1;
	}

	nss_cfi_info("freed up decap table\n");

	return 0;
}

/*
 * nss_ipsec_trap_encap()
 * 	Trap IPsec pkts for sending encap fast path rules.
 */
static int32_t nss_ipsec_trap_encap(struct sk_buff *skb, uint32_t crypto_sid)
{
	struct nss_ipsec_ipv4_hdr *tun;
	struct nss_ipsec_ipv4_hdr *ip;
	struct nss_ipsec_rule rule;
	struct nss_ipsec_rule_push *push;
	struct nss_ipsec_rule_data *data;
	struct net_device *ipsec_dev;
	uint32_t op;

	ipsec_dev = nss_ipsec_get_ipsec_dev(skb);
	if (ipsec_dev == NULL) {
		nss_cfi_dbg("ipsec_dev is NULL , returning\n");
		return -1;
	}

	tun = (struct nss_ipsec_ipv4_hdr *)skb->data;
	ip = (struct nss_ipsec_ipv4_hdr *)(skb->data + NSS_IPSEC_IPHDR_SZ + NSS_IPSEC_ESPHDR_SZ);

	memset(&rule, 0, sizeof(struct nss_ipsec_rule));
	push = &rule.type.push;

	/*
	 * for encap we use the inner header to create the selector
	 */
	op = nss_ipsec_parse_packet(ip, &push->sel, &push->data);
	if (op == NSS_IPSEC_RULE_OP_NONE) {
		nss_cfi_dbg("error during encap trap\n");
		return -1;
	}

	data = &push->data;

	memcpy(&data->ip, tun, NSS_IPSEC_IPHDR_SZ);
	memcpy(&data->esp, ((uint8_t *)tun + NSS_IPSEC_IPHDR_SZ), NSS_IPSEC_ESPHDR_SZ);

	skb->skb_iif = ipsec_dev->ifindex;

	rule.op = op;
	nss_ipsec_set_crypto_sid(&rule, crypto_sid);

	if (nss_ipsec_push_rule(&rule, NSS_IPSEC_ENCAP_INTERFACE) < 0) {
		return -1;
	}

	return 0;
}

/*
 * nss_ipsec_trap_decap()
 * 	Trap IPsec pkts for sending decap fast path rules.
 */
static int32_t nss_ipsec_trap_decap(struct sk_buff *skb, uint32_t crypto_sid)
{
	struct nss_ipsec_ipv4_hdr *tun;
	struct nss_ipsec_ipv4_hdr *ip;
	struct nss_ipsec_rule rule;
	struct nss_ipsec_rule_push *push;
	struct net_device *ipsec_dev;
	uint32_t op;

	ipsec_dev = nss_ipsec_get_ipsec_dev(skb);
	if (ipsec_dev == NULL) {
		nss_cfi_dbg("ipsec_dev is NULL , so returning\n");
		return -1;
	};

	tun = (struct nss_ipsec_ipv4_hdr *)skb_network_header(skb);
	ip = (struct nss_ipsec_ipv4_hdr *)(skb->data + NSS_IPSEC_ESPHDR_SZ);

	memset(&rule, 0, sizeof(struct nss_ipsec_rule));

	push = &rule.type.push;

	/*
	 * for decap we use the tunnel header to create the selector
	 */
	op = nss_ipsec_parse_packet(tun, &push->sel, &push->data);
	if (op == NSS_IPSEC_RULE_OP_NONE) {
		nss_cfi_dbg("error during decap trap\n");
		return -1;
	}

	skb->skb_iif = ipsec_dev->ifindex;

	rule.op = op;
	nss_ipsec_set_crypto_sid(&rule, crypto_sid);

	if (nss_ipsec_push_rule(&rule, NSS_IPSEC_DECAP_INTERFACE) < 0) {
		return -1;
	}

	return 0;
}

/*
 * nss_ipsec_data_cb()
 * 	ipsec exception routine for handling exceptions from NSS IPsec package
 *
 * exception function called by NSS HLOS driver when it receives
 * a packet for exception with the interface number for decap
 */
static void nss_ipsec_data_cb(void *ctx, void *buf)
{
	struct net_device *dev = gbl_except_dev;
	struct sk_buff *skb = (struct sk_buff *)buf;
	struct nss_ipsec_ipv4_hdr *ip;

	/*
	 * need to hold the lock prior to accessing the dev
	 */
	spin_lock(&gbl_dev_lock);

	if(!dev) {
		spin_unlock(&gbl_dev_lock);
		dev_kfree_skb_any(skb);
		return;
	}

	dev_hold(dev);

	spin_unlock(&gbl_dev_lock);

	ip = (struct nss_ipsec_ipv4_hdr *)skb->data;

	nss_cfi_dbg_skb(skb, NSS_IPSEC_DBG_DUMP_LIMIT);

	if (ip->ver_ihl != 0x45) {
		nss_cfi_dbg("unkown ipv4 header\n");
		return;
	}

	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = cpu_to_be16(ETH_P_IP);
	skb->dev = dev;
	skb->skb_iif = dev->ifindex;

	netif_receive_skb(skb);

	dev_put(dev);
}

static nss_ipsec_sync_op_t gbl_sync_op[NSS_IPSEC_RULE_OP_MAX] = {
	[NSS_IPSEC_RULE_OP_NONE] = nss_ipsec_sync_none,
	[NSS_IPSEC_RULE_OP_ADD] = nss_ipsec_sync_add,
	[NSS_IPSEC_RULE_OP_DEL] = nss_ipsec_sync_del,
	[NSS_IPSEC_RULE_OP_DEL_SID] = nss_ipsec_sync_flush,
	[NSS_IPSEC_RULE_OP_DEL_ALL] = nss_ipsec_sync_flush,
};

/*
 * nss_ipsec_event_cb()
 * 	Callback function for IPsec events.
 */
static void nss_ipsec_event_cb(void *ctx, uint32_t if_num, void *buf, uint32_t len)
{
	struct nss_ipsec_rule_tbl *tbl;
	struct nss_ipsec_rule_sync *sync;
	struct nss_ipsec_rule *rule;
	nss_ipsec_sync_op_t fn;

	switch(if_num) {
	case NSS_IPSEC_ENCAP_INTERFACE:
		tbl = &gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_ENCAP];
		break;

	case NSS_IPSEC_DECAP_INTERFACE:
		tbl = &gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_DECAP];
		break;

	default:
		nss_cfi_err("invalid interface number for event callback: %d\n", if_num);
		return;
	}

	rule = (struct nss_ipsec_rule *)buf;

	nss_cfi_assert(len == sizeof(struct nss_ipsec_rule));

	if (rule->op >= NSS_IPSEC_RULE_OP_MAX) {
		return;
	}

	fn = gbl_sync_op[rule->op];
	sync = &rule->type.sync;

	spin_lock_bh(&tbl->lock);

	fn(tbl, sync);

	spin_unlock_bh(&tbl->lock);
}

/*
 * nss_ipsec_table_init()
 * 	Initialize IPsec tables.
 */
void nss_ipsec_table_init(struct nss_ipsec_rule_tbl *tbl, uint32_t if_num)
{
	tbl->free_count = NSS_IPSEC_TBL_MAX_ENTRIES;
	tbl->if_num = if_num;
	tbl->num_pending_sync = 0;

	spin_lock_init(&tbl->lock);

	init_waitqueue_head(&tbl->waitq);
}

/*
 * nss_ipsec_dev_event()
 * 	notifier function for IPsec device events.
 */
static int nss_ipsec_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;

	switch (event) {
	case NETDEV_UP:

		if (strncmp(dev->name, "ipsec0", strlen("ipsec0")) != 0) {
			break;
		}

		nss_cfi_info("IPsec interface coming up: %s\n", dev->name);

		spin_lock_bh(&gbl_dev_lock);

		gbl_except_dev = dev;

		spin_unlock_bh(&gbl_dev_lock);

		gbl_nss_ctx = nss_register_ipsec_if(NSS_C2C_TX_INTERFACE, nss_ipsec_data_cb, dev);

		nss_register_ipsec_event_if(NSS_C2C_TX_INTERFACE, nss_ipsec_event_cb);

		nss_cfi_assert(gbl_nss_ctx);

		break;

        case NETDEV_DOWN:

		if (strncmp(dev->name, "ipsec0", strlen("ipsec0")) != 0) {
			break;
		}

		nss_cfi_info("IPsec interface going down: %s\n", dev->name);

		spin_lock_bh(&gbl_dev_lock);

		gbl_except_dev = NULL;

		spin_unlock_bh(&gbl_dev_lock);

		break;

	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block nss_ipsec_notifier = {
	.notifier_call = nss_ipsec_dev_event,
};

/*
 * nss_ipsec_init_module()
 * 	Initialize IPsec rule tables and register various callbacks
 */
int __init nss_ipsec_init_module(void)
{
	nss_cfi_info("NSS IPsec (platform - IPQ806x , Build - %s:%s) loaded\n", __DATE__, __TIME__);

	register_netdevice_notifier(&nss_ipsec_notifier);

	nss_cfi_ocf_register_ipsec(nss_ipsec_trap_encap, nss_ipsec_trap_decap, nss_ipsec_free_session);

	nss_ipsec_table_init(&gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_ENCAP], NSS_IPSEC_ENCAP_INTERFACE);
	nss_ipsec_table_init(&gbl_rule_tbl[NSS_IPSEC_TBL_TYPE_DECAP], NSS_IPSEC_DECAP_INTERFACE);

	spin_lock_init(&gbl_dev_lock);

	memset(&param, 0, sizeof(struct nss_ipsec_stats_param));

	return 0;
}

/*
 * nss_ipsec_exit_module()
 */
void __exit nss_ipsec_exit_module(void)
{
	nss_cfi_ocf_unregister_ipsec();

	nss_ipsec_free_all();

	nss_unregister_ipsec_if(NSS_C2C_TX_INTERFACE);

	unregister_netdevice_notifier(&nss_ipsec_notifier);

	nss_cfi_info("module unloaded\n");
}


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Qualcomm Atheros");
MODULE_DESCRIPTION("NSS IPsec offload manager");

module_init(nss_ipsec_init_module);
module_exit(nss_ipsec_exit_module);

