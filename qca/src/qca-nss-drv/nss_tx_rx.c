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
 * nss_tx_rx.c
 *	NSS Tx and Rx APIs
 */

#include "nss_core.h"
#include <nss_hal.h>
#include <linux/module.h>
#include <linux/ppp_channel.h>
#include <net/arp.h>
//#include <linux/sched.h>
#include <net/pkt_sched.h>

/*
 * Global variables/extern declarations
 */
extern struct nss_top_instance nss_top_main;
extern struct nss_frequency_statistics nss_freq_stat;
extern struct nss_runtime_sampling nss_runtime_samples;
extern struct nss_cmd_buffer nss_cmd_buf;
extern int nss_ctl_redirect;

extern struct workqueue_struct *nss_wq;
extern nss_work_t *nss_work;
extern void *nss_freq_change_context;

#define NSS_ACK_STARTED 0
#define NSS_ACK_FINISHED 1

#if (NSS_DEBUG_LEVEL > 0)
#define NSS_VERIFY_CTX_MAGIC(x) nss_verify_ctx_magic(x)
#define NSS_VERIFY_INIT_DONE(x) nss_verify_init_done(x)

/*
 * nss_verify_ctx_magic()
 */
static inline void nss_verify_ctx_magic(struct nss_ctx_instance *nss_ctx)
{
	nss_assert(nss_ctx->magic == NSS_CTX_MAGIC);
}

static inline void nss_verify_init_done(struct nss_ctx_instance *nss_ctx)
{
	nss_assert(nss_ctx->state == NSS_CORE_STATE_INITIALIZED);
}

#else
#define NSS_VERIFY_CTX_MAGIC(x)
#define NSS_VERIFY_INIT_DONE(x)
#endif

/*
 * nss_rx_metadata_nss_freq_ack()
 *	Handle the nss ack of frequency change.
 */
static void nss_rx_metadata_nss_freq_ack(struct nss_ctx_instance *nss_ctx, struct nss_freq_ack *nfa)
{
	if (nfa->ack_status == NSS_ACK_STARTED) {
		/*
		 * NSS finished start noficiation - HW change clocks and send end notification
		 */
		nss_info("%p: NSS ACK Received: %d - Change HW CLK/Send Finish to NSS\n", nss_ctx, nfa->ack_status);

		return;
	}

	if (nfa->ack_status == NSS_ACK_FINISHED) {
		/*
		 * NSS finished end notification - Done
		 */
		nss_info("%p: NSS ACK Received: %d - End Notification ACK - Running: %dmhz\n", nss_ctx, nfa->ack_status, nfa->freq_current);
		nss_runtime_samples.freq_scale_ready = 1;
		return;
	}

	nss_info("%p: NSS had an error - Running: %dmhz\n", nss_ctx, nfa->freq_current);
}

/*
 * nss_rx_metadata_ipv4_rule_establish()
 *	Handle the establishment of an IPv4 rule.
 */
static void nss_rx_metadata_ipv4_rule_establish(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_establish *nire)
{
	struct nss_ipv4_cb_params nicp;

	// GGG FIXME THIS SHOULD NOT BE A MEMCPY
	nicp.reason = NSS_IPV4_CB_REASON_ESTABLISH;
	memcpy(&nicp.params, nire, sizeof(struct nss_ipv4_establish));

	/*
	 * Call IPv4 manager callback function
	 */
	if (nss_ctx->nss_top->ipv4_callback) {
		nss_ctx->nss_top->ipv4_callback(&nicp);
	} else {
		nss_info("%p: IPV4 establish message received before connection manager has registered", nss_ctx);
	}
}

/*
 * nss_rx_metadata_ipv4_rule_sync()
 *	Handle the syncing of an IPv4 rule.
 */
static void nss_rx_metadata_ipv4_rule_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipv4_rule_sync *nirs)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_ipv4_cb_params nicp;
	struct net_device *pppoe_dev = NULL;

	nicp.reason = NSS_IPV4_CB_REASON_SYNC;
	nicp.params.sync.index = nirs->index;
	nicp.params.sync.flow_max_window = nirs->flow_max_window;
	nicp.params.sync.flow_end = nirs->flow_end;
	nicp.params.sync.flow_max_end = nirs->flow_max_end;
	nicp.params.sync.flow_rx_packet_count = nirs->flow_rx_packet_count;
	nicp.params.sync.flow_rx_byte_count = nirs->flow_rx_byte_count;
	nicp.params.sync.flow_tx_packet_count = nirs->flow_tx_packet_count;
	nicp.params.sync.flow_tx_byte_count = nirs->flow_tx_byte_count;
	nicp.params.sync.return_max_window = nirs->return_max_window;
	nicp.params.sync.return_end = nirs->return_end;
	nicp.params.sync.return_max_end = nirs->return_max_end;
	nicp.params.sync.return_rx_packet_count = nirs->return_rx_packet_count;
	nicp.params.sync.return_rx_byte_count = nirs->return_rx_byte_count;
	nicp.params.sync.return_tx_packet_count = nirs->return_tx_packet_count;
	nicp.params.sync.return_tx_byte_count = nirs->return_tx_byte_count;

	nicp.params.sync.qos_tag = nirs->qos_tag;

	nicp.params.sync.flags = 0;
	if (nirs->flags & NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK) {
		nicp.params.sync.flags |= NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (nirs->flags & NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW) {
		nicp.params.sync.flags |= NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (nirs->flags & NSS_IPV4_RULE_CREATE_FLAG_ROUTED) {
		nicp.params.sync.flags |= NSS_IPV4_CREATE_FLAG_ROUTED;
	}

	switch (nirs->reason) {
	case NSS_IPV4_RULE_SYNC_REASON_STATS:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_STATS;
		break;

	case NSS_IPV4_RULE_SYNC_REASON_FLUSH:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_FLUSH;
		break;

	case NSS_IPV4_RULE_SYNC_REASON_EVICT:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_EVICT;
		break;

	case NSS_IPV4_RULE_SYNC_REASON_DESTROY:
		nicp.params.sync.reason = NSS_IPV4_SYNC_REASON_DESTROY;
		break;

	default:
		nss_warning("Bad ipv4 sync reason: %d\n", nirs->reason);
		return;
	}

	/*
	 * Convert ms ticks from the NSS to jiffies.  We know that inc_ticks is small
	 * and we expect HZ to be small too so we can multiply without worrying about
	 * wrap-around problems.  We add a rounding constant to ensure that the different
	 * time bases don't cause truncation errors.
	 */
	nss_assert(HZ <= 100000);
	nicp.params.sync.delta_jiffies = ((nirs->inc_ticks * HZ) + (MSEC_PER_SEC / 2)) / MSEC_PER_SEC;

	/*
	 * Call IPv4 manager callback function
	 */
	if (nss_ctx->nss_top->ipv4_callback) {
		nss_ctx->nss_top->ipv4_callback(&nicp);
	} else {
		nss_info("%p: IPV4 sync message received before connection manager has registered", nss_ctx);
	}

	/*
	 * Update statistics maintained by NSS driver
	 */
	spin_lock_bh(&nss_top->stats_lock);

	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_RX_PKTS] += nirs->flow_rx_packet_count + nirs->return_rx_packet_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_RX_BYTES] += nirs->flow_rx_byte_count + nirs->return_rx_byte_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_TX_PKTS] += nirs->flow_tx_packet_count + nirs->return_tx_packet_count;
	nss_top->stats_ipv4[NSS_STATS_IPV4_ACCELERATED_TX_BYTES] += nirs->flow_tx_byte_count + nirs->return_tx_byte_count;

	/*
	 * Update the PPPoE interface stats, if there is any PPPoE session on the interfaces.
	 */
	if (nirs->flow_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->flow_pppoe_session_id, (uint8_t *)nirs->flow_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->flow_rx_packet_count, nirs->flow_rx_byte_count,
					nirs->flow_tx_packet_count, nirs->flow_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	if (nirs->return_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->return_pppoe_session_id, (uint8_t *)nirs->return_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->return_rx_packet_count, nirs->return_rx_byte_count,
					nirs->return_tx_packet_count, nirs->return_tx_byte_count);
			dev_put(pppoe_dev);
		}
       }

	/*
	 * TODO: Update per dev accelerated statistics
	 */

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_ipv6_rule_establish()
 *	Handle the establishment of an IPv6 rule.
 */
static void nss_rx_metadata_ipv6_rule_establish(struct nss_ctx_instance *nss_ctx, struct nss_ipv6_rule_establish *nire)
{
	struct nss_ipv6_cb_params nicp;

	// GGG FIXME THIS SHOULD NOT BE A MEMCPY
	nicp.reason = NSS_IPV6_CB_REASON_ESTABLISH;
	memcpy(&nicp.params, nire, sizeof(struct nss_ipv6_establish));

	/*
	 * Call IPv6 manager callback function
	 */
	if (nss_ctx->nss_top->ipv6_callback) {
		nss_ctx->nss_top->ipv6_callback(&nicp);
	} else {
		nss_info("%p: IPV6 establish message received before connection manager has registered", nss_ctx);
	}
}

/*
 * nss_rx_metadata_ipv6_rule_sync()
 *	Handle the syncing of an IPv6 rule.
 */
static void nss_rx_metadata_ipv6_rule_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipv6_rule_sync *nirs)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_ipv6_cb_params nicp;
	struct net_device *pppoe_dev = NULL;

	nicp.reason = NSS_IPV6_CB_REASON_SYNC;
	nicp.params.sync.index = nirs->index;
	nicp.params.sync.flow_max_window = nirs->flow_max_window;
	nicp.params.sync.flow_end = nirs->flow_end;
	nicp.params.sync.flow_max_end = nirs->flow_max_end;
	nicp.params.sync.flow_rx_packet_count = nirs->flow_rx_packet_count;
	nicp.params.sync.flow_rx_byte_count = nirs->flow_rx_byte_count;
	nicp.params.sync.flow_tx_packet_count = nirs->flow_tx_packet_count;
	nicp.params.sync.flow_tx_byte_count = nirs->flow_tx_byte_count;
	nicp.params.sync.return_max_window = nirs->return_max_window;
	nicp.params.sync.return_end = nirs->return_end;
	nicp.params.sync.return_max_end = nirs->return_max_end;
	nicp.params.sync.return_rx_packet_count = nirs->return_rx_packet_count;
	nicp.params.sync.return_rx_byte_count = nirs->return_rx_byte_count;
	nicp.params.sync.return_tx_packet_count = nirs->return_tx_packet_count;
	nicp.params.sync.return_tx_byte_count = nirs->return_tx_byte_count;

	nicp.params.sync.qos_tag = nirs->qos_tag;

	nicp.params.sync.flags = 0;
	if (nirs->flags & NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK) {
		nicp.params.sync.flags |= NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (nirs->flags & NSS_IPV6_RULE_CREATE_FLAG_BRIDGE_FLOW) {
		nicp.params.sync.flags |= NSS_IPV6_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (nirs->flags & NSS_IPV6_RULE_CREATE_FLAG_ROUTED) {
		nicp.params.sync.flags |= NSS_IPV6_CREATE_FLAG_ROUTED;
	}

	switch(nirs->reason) {
	case NSS_IPV6_RULE_SYNC_REASON_FLUSH:
	case NSS_IPV6_RULE_SYNC_REASON_DESTROY:
	case NSS_IPV6_RULE_SYNC_REASON_EVICT:
		nicp.params.sync.final_sync = 1;
		break;

	case NSS_IPV6_RULE_SYNC_REASON_STATS:
		nicp.params.sync.final_sync = 0;
		break;

	default:
		nss_warning("Bad ipv6 sync reason: %d\n", nirs->reason);
		return;
	}

	/*
	 * Convert ms ticks from the NSS to jiffies.  We know that inc_ticks is small
	 * and we expect HZ to be small too so we can multiply without worrying about
	 * wrap-around problems.  We add a rounding constant to ensure that the different
	 * time bases don't cause truncation errors.
	 */
	nss_assert(HZ <= 100000);
	nicp.params.sync.delta_jiffies = ((nirs->inc_ticks * HZ) + (MSEC_PER_SEC / 2)) / MSEC_PER_SEC;

	/*
	 * Call IPv6 manager callback function
	 */
	if (nss_ctx->nss_top->ipv6_callback) {
		nss_ctx->nss_top->ipv6_callback(&nicp);
	} else {
		nss_info("%p: IPV6 sync message received before connection manager has registered", nss_ctx);
	}

	/*
	 * Update statistics maintained by NSS driver
	 */
	spin_lock_bh(&nss_top->stats_lock);

	nss_top->stats_ipv6[NSS_STATS_IPV6_ACCELERATED_RX_PKTS] += nirs->flow_rx_packet_count + nirs->return_rx_packet_count;
	nss_top->stats_ipv6[NSS_STATS_IPV6_ACCELERATED_RX_BYTES] += nirs->flow_rx_byte_count + nirs->return_rx_byte_count;
	nss_top->stats_ipv6[NSS_STATS_IPV6_ACCELERATED_TX_PKTS] += nirs->flow_tx_packet_count + nirs->return_tx_packet_count;
	nss_top->stats_ipv6[NSS_STATS_IPV6_ACCELERATED_TX_BYTES] += nirs->flow_tx_byte_count + nirs->return_tx_byte_count;

	/*
	 * Update the PPPoE interface stats, if there is any PPPoE session on the interfaces.
	 */
	if (nirs->flow_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->flow_pppoe_session_id, (uint8_t *)nirs->flow_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->flow_rx_packet_count, nirs->flow_rx_byte_count,
					nirs->flow_tx_packet_count, nirs->flow_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	if (nirs->return_pppoe_session_id) {
		pppoe_dev = ppp_session_to_netdev(nirs->return_pppoe_session_id, (uint8_t *)nirs->return_pppoe_remote_mac);
		if (pppoe_dev) {
			ppp_update_stats(pppoe_dev, nirs->return_rx_packet_count, nirs->return_rx_byte_count,
				nirs->return_tx_packet_count, nirs->return_tx_byte_count);
			dev_put(pppoe_dev);
		}
	}

	/*
	 * TODO: Update per dev accelerated statistics
	 */

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_freq_change()
 *     NSS frequency change API.
 */
nss_tx_status_t nss_freq_change(void *ctx, uint32_t eng, uint32_t stats_enable, uint32_t start_or_end)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_freq_change *nfc;

	nss_info("%p: Frequency Changing to: %d\n", nss_ctx, eng);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_NSS_FREQ_CHANGE;

	nfc = &ntmo->sub.freq_change;
	nfc->frequency = eng;
	nfc->start_or_end = start_or_end;
	nfc->stats_enable = stats_enable;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: unable to enqueue 'nss frequency change' - marked as stopped\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit, NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_rx_metadata_tun6rd_stats_sync()
 *	Handle the syncing of 6rd tunnel stats.
 */
static void nss_rx_metadata_tun6rd_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_tun6rd_stats_sync *ntun6rdss)
{
	void *ctx;
	nss_tun6rd_if_event_callback_t cb;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	uint32_t id = ntun6rdss->interface;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_top->if_ctx[id];
	cb = nss_top->tun6rd_if_event_callback;

	/*
	 * call 6rd tunnel callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for 6rd tunnel interface %d before registration", nss_ctx, ntun6rdss->interface);
		return;
	}

	cb(ctx, NSS_TUN6RD_EVENT_STATS, (void *)ntun6rdss, sizeof(struct nss_tun6rd_stats_sync));
}

/*
 * nss_rx_metadata_tunipip6_stats_sync()
 *	Handle the syncing of ipip6 tunnel stats.
 */
static void nss_rx_metadata_tunipip6_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_tunipip6_stats_sync *ntunipip6ss)
{
	void *ctx;
	nss_tunipip6_if_event_callback_t cb;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	uint32_t id = ntunipip6ss->interface;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_top->if_ctx[id];
	cb = nss_top->tunipip6_if_event_callback;

	/*
	 * call ipip6 tunnel callback
	 */

	if (!cb || !ctx) {
		nss_warning("%p: Event received for ipip6 tunnel interface %d before registration", nss_ctx, ntunipip6ss->interface);
		return;
	}

	cb(ctx, NSS_TUNIPIP6_EVENT_STATS, (void *)ntunipip6ss, sizeof(struct nss_tunipip6_stats_sync));
}

/*
 * nss_rx_metadata_crypto_sync()
 * 	Handle the syncing of Crypto stats.
 */
static void nss_rx_metadata_crypto_sync(struct nss_ctx_instance *nss_ctx, struct nss_crypto_sync *ncss)
{
	void *ctx;
	nss_crypto_sync_callback_t cb;

	nss_trace("%p: Callback received for interface %d", nss_ctx, ncss->interface_num);

	ctx = nss_ctx->nss_top->crypto_ctx;
	cb = nss_ctx->nss_top->crypto_sync_callback;

	/*
	 * Call Crypto sync callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: sync rcvd for crypto if %d before registration", nss_ctx, ncss->interface_num);
		return;
	}

	cb(ctx, ncss->buf, ncss->len);
}

/*
 * nss_rx_metadata_gmac_stats_sync()
 *	Handle the syncing of GMAC stats.
 */
static void nss_rx_metadata_gmac_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_gmac_stats_sync *ngss)
{
	void *ctx;
	nss_phys_if_event_callback_t cb;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	uint32_t id = ngss->interface;

	if (id >= NSS_MAX_PHYSICAL_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_ctx->nss_top->if_ctx[id];
	cb = nss_ctx->nss_top->phys_if_event_callback[id];

	/*
	 * Call GMAC driver callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for GMAC interface %d before registration", nss_ctx, ngss->interface);
		return;
	}

	cb(ctx, NSS_GMAC_EVENT_STATS, (void *)ngss, sizeof(struct nss_gmac_stats_sync));

	spin_lock_bh(&nss_top->stats_lock);
	nss_top->stats_gmac[id][NSS_STATS_GMAC_TOTAL_TICKS] += ngss->gmac_total_ticks;
	if (unlikely(nss_top->stats_gmac[id][NSS_STATS_GMAC_WORST_CASE_TICKS] < ngss->gmac_worst_case_ticks)) {
		nss_top->stats_gmac[id][NSS_STATS_GMAC_WORST_CASE_TICKS] = ngss->gmac_worst_case_ticks;
	}

	nss_top->stats_gmac[id][NSS_STATS_GMAC_ITERATIONS] += ngss->gmac_iterations;
	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_interface_stats_sync()
 *	Handle the syncing of interface statistics.
 */
static void nss_rx_metadata_interface_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_interface_stats_sync *niss)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	uint32_t id = niss->interface;
	uint32_t i;

	spin_lock_bh(&nss_top->stats_lock);

	nss_top->stats_if_host[id][NSS_STATS_IF_HOST_RX_PKTS] += niss->host_rx_packets;
	nss_top->stats_if_host[id][NSS_STATS_IF_HOST_RX_BYTES] += niss->host_rx_bytes;
	nss_top->stats_if_host[id][NSS_STATS_IF_HOST_TX_PKTS] += niss->host_tx_packets;
	nss_top->stats_if_host[id][NSS_STATS_IF_HOST_TX_BYTES] += niss->host_tx_bytes;

	for (i = 0; i < NSS_EXCEPTION_EVENT_UNKNOWN_MAX; i++) {
		nss_top->stats_if_exception_unknown[id][i] += niss->exception_events_unknown[i];
	}

	for (i = 0; i < NSS_EXCEPTION_EVENT_IPV4_MAX; i++) {
		nss_top->stats_if_exception_ipv4[id][i] += niss->exception_events_ipv4[i];
	}

	for (i = 0; i < NSS_EXCEPTION_EVENT_IPV6_MAX; i++) {
		nss_top->stats_if_exception_ipv6[id][i] += niss->exception_events_ipv6[i];
	}

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_nss_stats_sync()
 *	Handle the syncing of NSS statistics.
 */
static void nss_rx_metadata_nss_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_nss_stats_sync *nnss)
{
	struct nss_top_instance *nss_top = nss_ctx->nss_top;

	spin_lock_bh(&nss_top->stats_lock);

	/*
	 * IPv4 stats
	 */
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_CREATE_REQUESTS] += nnss->ipv4_connection_create_requests;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_CREATE_COLLISIONS] += nnss->ipv4_connection_create_collisions;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_CREATE_INVALID_INTERFACE] += nnss->ipv4_connection_create_invalid_interface;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_DESTROY_REQUESTS] += nnss->ipv4_connection_destroy_requests;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_DESTROY_MISSES] += nnss->ipv4_connection_destroy_misses;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_HASH_HITS] += nnss->ipv4_connection_hash_hits;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_HASH_REORDERS] += nnss->ipv4_connection_hash_reorders;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_FLUSHES] += nnss->ipv4_connection_flushes;
	nss_top->stats_ipv4[NSS_STATS_IPV4_CONNECTION_EVICTIONS] += nnss->ipv4_connection_evictions;

	/*
	 * IPv6 stats
	 */
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_CREATE_REQUESTS] += nnss->ipv6_connection_create_requests;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_CREATE_COLLISIONS] += nnss->ipv6_connection_create_collisions;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_CREATE_INVALID_INTERFACE] += nnss->ipv6_connection_create_invalid_interface;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_DESTROY_REQUESTS] += nnss->ipv6_connection_destroy_requests;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_DESTROY_MISSES] += nnss->ipv6_connection_destroy_misses;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_HASH_HITS] += nnss->ipv6_connection_hash_hits;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_HASH_REORDERS] += nnss->ipv6_connection_hash_reorders;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_FLUSHES] += nnss->ipv6_connection_flushes;
	nss_top->stats_ipv6[NSS_STATS_IPV6_CONNECTION_EVICTIONS] += nnss->ipv6_connection_evictions;

	/*
	 * pppoe stats
	 */
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_CREATE_REQUESTS] += nnss->pppoe_session_create_requests;
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_CREATE_FAILURES] += nnss->pppoe_session_create_failures;
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_DESTROY_REQUESTS] += nnss->pppoe_session_destroy_requests;
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_DESTROY_MISSES] += nnss->pppoe_session_destroy_misses;

	/*
	 * n2h stats
	 */
	nss_top->stats_n2h[NSS_STATS_N2H_QUEUE_DROPPED] += nnss->except_queue_dropped;
	nss_top->stats_n2h[NSS_STATS_N2H_TOTAL_TICKS] += nnss->except_total_ticks;
	if (unlikely(nss_top->stats_n2h[NSS_STATS_N2H_WORST_CASE_TICKS] < nnss->except_worst_case_ticks)) {
		nss_top->stats_n2h[NSS_STATS_N2H_WORST_CASE_TICKS] = nnss->except_worst_case_ticks;
	}
	nss_top->stats_n2h[NSS_STATS_N2H_ITERATIONS] += nnss->except_iterations;

	/*
	 * pbuf_mgr stats
	 */
	nss_top->stats_pbuf[NSS_STATS_PBUF_ALLOC_FAILS] += nnss->pbuf_alloc_fails;
	nss_top->stats_pbuf[NSS_STATS_PBUF_PAYLOAD_ALLOC_FAILS] += nnss->pbuf_payload_alloc_fails;

	/*
	 * TODO: Clean-up PE stats (there is no PE on NSS now)
	 */
	nss_top->pe_queue_dropped += nnss->pe_queue_dropped;
	nss_top->pe_total_ticks += nnss->pe_total_ticks;
	if (unlikely(nss_top->pe_worst_case_ticks < nnss->pe_worst_case_ticks)) {
		nss_top->pe_worst_case_ticks = nnss->pe_worst_case_ticks;
	}
	nss_top->pe_iterations += nnss->pe_iterations;

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_pppoe_exception_stats_sync()
 *	Handle the syncing of PPPoE exception statistics.
 */
static void nss_rx_metadata_pppoe_exception_stats_sync(struct nss_ctx_instance *nss_ctx, struct nss_pppoe_exception_stats_sync *npess)
{
	/* Place holder */
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	uint32_t index = npess->index;
	uint32_t interface_num = npess->interface_num;
	uint32_t i;

	spin_lock_bh(&nss_top->stats_lock);

	for (i = 0; i < NSS_EXCEPTION_EVENT_PPPOE_MAX; i++) {
		nss_top->stats_if_exception_pppoe[interface_num][index][i] += npess->exception_events_pppoe[i];
	}

	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_tx_destroy_pppoe_connection_rule)
 *	Destroy PPoE connection rule associated with the session ID and remote server MAC address.
 */
static void nss_tx_destroy_pppoe_connection_rule(void *ctx, uint16_t pppoe_session_id, uint8_t *pppoe_remote_mac)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_pppoe_rule_destroy *nprd;
	uint16_t *pppoe_remote_mac_uint16_t = (uint16_t *)pppoe_remote_mac;
	uint32_t i, j, k;

	nss_info("%p: Destroy all PPPoE rules of session ID: %x remote MAC: %x:%x:%x:%x:%x:%x", nss_ctx, pppoe_session_id,
			pppoe_remote_mac[0], pppoe_remote_mac[1], pppoe_remote_mac[2],
			pppoe_remote_mac[3], pppoe_remote_mac[4], pppoe_remote_mac[5]);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy all rules by PPPoE session dropped as core not ready", nss_ctx);
		return;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy all rules by PPPoE session dropped as command allocation failed", nss_ctx);
		return;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_DESTROY_PPPOE_CONNECTION_RULE;

	nprd = &ntmo->sub.pppoe_rule_destroy;
	nprd->pppoe_session_id = pppoe_session_id;
	nprd->pppoe_remote_mac[0] = pppoe_remote_mac_uint16_t[0];
	nprd->pppoe_remote_mac[1] = pppoe_remote_mac_uint16_t[1];
	nprd->pppoe_remote_mac[2] = pppoe_remote_mac_uint16_t[2];

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy all rules by PPPoE session\n", nss_ctx);
		return;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);

	/*
	 * Reset the PPPoE statistics.
	 */
	spin_lock_bh(&nss_top->stats_lock);
	/*
	 * TODO: Don't reset all the statistics. Reset only the destroyed session's stats.
	 */
	for (i = 0; i < NSS_MAX_NET_INTERFACES; i++) {
		for (j = 0; j < NSS_PPPOE_NUM_SESSION_PER_INTERFACE; j++) {
			for (k = 0; k < NSS_EXCEPTION_EVENT_PPPOE_MAX; k++) {
				nss_top->stats_if_exception_pppoe[i][j][k] = 0;
			}
		}
	}

	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_CREATE_REQUESTS] = 0;
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_CREATE_FAILURES] = 0;
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_DESTROY_REQUESTS] = 0;
	nss_top->stats_pppoe[NSS_STATS_PPPOE_SESSION_DESTROY_MISSES] = 0;

	/*
	 * TODO: Do we need to unregister the destroy method? The ppp_dev has already gone.
	 */
	spin_unlock_bh(&nss_top->stats_lock);
}

/*
 * nss_rx_metadata_pppoe_rule_create_success()
 *	Handle the PPPoE rule create success message.
 */
static void nss_rx_metadata_pppoe_rule_create_success(struct nss_ctx_instance *nss_ctx, struct nss_pppoe_rule_create_success *pcs)
{
	struct net_device *ppp_dev = ppp_session_to_netdev(pcs->pppoe_session_id, pcs->pppoe_remote_mac);

	if (!ppp_dev) {
		nss_warning("%p: There is not any PPP devices with SID: %x remote MAC: %x:%x:%x:%x:%x:%x", nss_ctx, pcs->pppoe_session_id,
			pcs->pppoe_remote_mac[0], pcs->pppoe_remote_mac[1], pcs->pppoe_remote_mac[2],
			pcs->pppoe_remote_mac[3], pcs->pppoe_remote_mac[4], pcs->pppoe_remote_mac[5]);

		return;
	}

	if (!ppp_register_destroy_method(ppp_dev, nss_tx_destroy_pppoe_connection_rule, (void *)nss_ctx)) {
		nss_warning("%p: Failed to register destroy method", nss_ctx);
	}

	dev_put(ppp_dev);
}

/*
 * nss_rx_metadata_profiler_sync()
 *	Handle the syncing of profiler information.
 */
static void nss_rx_metadata_profiler_sync(struct nss_ctx_instance *nss_ctx, struct nss_profiler_sync *profiler_sync)
{
	void *ctx = nss_ctx->nss_top->profiler_ctx[nss_ctx->id];
	nss_profiler_callback_t cb = nss_ctx->nss_top->profiler_callback[nss_ctx->id];

	if (!cb || !ctx) {
		nss_warning("%p: Event received for profiler interface before registration", nss_ctx);
	}

	cb(ctx, profiler_sync->buf, profiler_sync->len);
}

/*
 * nss_frequency_workqueue()
 *	Queue Work to the NSS Workqueue based on Current index.
 */
static void nss_frequency_workqueue(void)
{
	BUG_ON(!nss_wq);

	nss_cmd_buf.current_freq = nss_runtime_samples.freq_scale[nss_runtime_samples.freq_scale_index].frequency;

	nss_work = (nss_work_t *)kmalloc(sizeof(nss_work_t), GFP_KERNEL);
	if (!nss_work) {
		nss_info("NSS FREQ WQ kmalloc fail");
		return;
	}

	INIT_WORK((struct work_struct *)nss_work, nss_wq_function);
	nss_work->frequency = nss_cmd_buf.current_freq;
	nss_work->stats_enable =  1;
	queue_work(nss_wq, (struct work_struct *)nss_work);
}


/*
 *  nss_rx_metadata_nss_core_stats()
 *	Handle the core stats
 */
static void nss_rx_metadata_nss_core_stats(struct nss_ctx_instance *nss_ctx, struct nss_core_stats *core_stats)
{
	uint32_t b_index;
	uint32_t minimum;
	uint32_t maximum;
	uint32_t sample;

	sample = core_stats->inst_cnt_total;

	/*
	 * We do not accept any statistics if auto scaling is off,
	 * we start with a fresh sample set when scaling is
	 * eventually turned on.
	 */
	if (!nss_cmd_buf.auto_scale && nss_runtime_samples.initialized) {
		return;
	}

	/*
	 * Delete Current Index Value, Add New Value, Recalculate new Sum, Shift Index
	 */
	b_index = nss_runtime_samples.buffer_index;

	nss_runtime_samples.sum = nss_runtime_samples.sum - nss_runtime_samples.buffer[b_index];
	nss_runtime_samples.buffer[b_index] = sample;
	nss_runtime_samples.sum = nss_runtime_samples.sum + nss_runtime_samples.buffer[b_index];
	nss_runtime_samples.buffer_index = (b_index + 1) & NSS_SAMPLE_BUFFER_MASK;

	if (nss_runtime_samples.sample_count < NSS_SAMPLE_BUFFER_SIZE) {
		nss_runtime_samples.sample_count++;

		/*
		 * Samples Are All Ready, Start Auto Scale
		 */
		if (nss_runtime_samples.sample_count == NSS_SAMPLE_BUFFER_SIZE ) {
			nss_cmd_buf.auto_scale = 1;
			nss_runtime_samples.freq_scale_ready = 1;
			nss_runtime_samples.initialized = 1;
		}

		return;
	}

	nss_runtime_samples.average = nss_runtime_samples.sum / nss_runtime_samples.sample_count;

	/*
	 * Print out statistics every 10 seconds
	 */
	if (nss_runtime_samples.message_rate_limit == NSS_MESSAGE_RATE_LIMIT) {
		nss_info("%p: Running AVG:%x Sample:%x Divider:%d\n", nss_ctx, nss_runtime_samples.average, core_stats->inst_cnt_total, nss_runtime_samples.sample_count);
		nss_info("%p: Current Frequency Index:%d\n", nss_ctx, nss_runtime_samples.freq_scale_index);
		nss_info("%p: Auto Scale:%d Auto Scale Ready:%d\n", nss_ctx, nss_runtime_samples.freq_scale_ready, nss_cmd_buf.auto_scale);
		nss_info("%p: Current Rate:%x\n", nss_ctx, nss_runtime_samples.average);

		nss_runtime_samples.message_rate_limit = 0;
	} else {
		nss_runtime_samples.message_rate_limit++;
	}

	/*
	 * Scale Algorithmn UP and DOWN
	 */
	if ((nss_runtime_samples.freq_scale_ready == 1) && (nss_cmd_buf.auto_scale == 1)) {
		if (nss_runtime_samples.freq_scale_rate_limit_up == NSS_FREQUENCY_SCALE_RATE_LIMIT_UP) {
			nss_info("%p: Preparing Switch Inst_Cnt Avg:%x\n", nss_ctx, nss_runtime_samples.average);

			maximum = nss_runtime_samples.freq_scale[nss_runtime_samples.freq_scale_index].maximum;

			if ((sample > maximum) && (nss_runtime_samples.freq_scale_index < (nss_runtime_samples.freq_scale_sup_max - 1))) {
				nss_runtime_samples.freq_scale_index++;
				nss_runtime_samples.freq_scale_ready = 0;
				nss_frequency_workqueue();
				nss_info("%p: Switch Up with Sample %x \n", nss_ctx, sample);
			} else {
				nss_info("%p: No Change at Max\n", nss_ctx);
			}
			nss_runtime_samples.freq_scale_rate_limit_up = 0;
			return;

		} else {
			nss_runtime_samples.freq_scale_rate_limit_up++;
		}

		minimum = nss_runtime_samples.freq_scale[nss_runtime_samples.freq_scale_index].minimum;

		if ((nss_runtime_samples.average < minimum) && (nss_runtime_samples.freq_scale_index > 0)) {
			nss_runtime_samples.freq_scale_rate_limit_down++;

			if (nss_runtime_samples.freq_scale_rate_limit_down == NSS_FREQUENCY_SCALE_RATE_LIMIT_DOWN) {
				nss_runtime_samples.freq_scale_index--;
				nss_runtime_samples.freq_scale_ready = 0;
				nss_frequency_workqueue();
				nss_runtime_samples.freq_scale_rate_limit_down = 0;
			}
		} else {
			nss_runtime_samples.freq_scale_rate_limit_down = 0;
		}
	}
}

/*
 *  nss_rx_metadata_ipsec_events_sync()
 *	Handle the IPsec events
 */
static void nss_rx_metadata_ipsec_events_sync(struct nss_ctx_instance *nss_ctx, struct nss_ipsec_events_sync *nies)
{
	void *ctx;
	nss_ipsec_event_callback_t cb;
	uint32_t id = nies->ipsec_if_num;

	if (id >= NSS_MAX_NET_INTERFACES) {
		nss_warning("%p: Callback received for invalid interface %d", nss_ctx, id);
		return;
	}

	ctx = nss_ctx->nss_top->if_ctx[id];
	cb = nss_ctx->nss_top->ipsec_event_callback;

	/*
	 * Call IPsec callback
	 */
	if (!cb || !ctx) {
		nss_warning("%p: Event received for IPsec interface %d before registration", nss_ctx, id);
		return;
	}

	cb(ctx, nies->event_if_num, nies->buf, nies->len);
}

/*
 * nss_rx_metadata_shaper_response()
 *	Called to process a shaper response (to a shaper config command issued)
 */
static void nss_rx_metadata_shaper_response(struct nss_ctx_instance *nss_ctx, struct nss_rx_shaper_response *sr)
{
	struct nss_tx_shaper_configure *ntsc = &sr->request;
	nss_shaper_config_response_callback_t cb;
	void *cb_app_data;
	struct module *owner;
	struct nss_shaper_response response;

	/*
	 * Pass the response to the originator
	 */
	cb = (nss_shaper_config_response_callback_t)ntsc->opaque1;
	cb_app_data = (void *)ntsc->opaque2;
	owner = (struct module *)ntsc->opaque3;

	nss_info("%p: shaper response: %p, cb: %p, arg: %p, owner: %p, response type: %d, request type: %d\n",
			nss_ctx, sr, cb, cb_app_data, owner, sr->type, ntsc->type);
//	printk(KERN_INFO "%p: shaper response: %p, cb: %p, arg: %p, owner: %p, response type: %d, request type: %d\n",
//			nss_ctx, sr, cb, cb_app_data, owner, sr->type, ntsc->type);

	/*
	 * Create a response structure from the NSS metadata response
	 */
	switch(sr->type) {
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_ASSIGN_SUCCESS:
		nss_info("%p: assign shaper success num: %u", nss_ctx, sr->rt.shaper_assign_success.shaper_num);
		response.rt.shaper_assign_success.shaper_num = sr->rt.shaper_assign_success.shaper_num;
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_ASSIGN_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPERS:
		nss_info("%p: no shapers", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPERS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER:
		nss_info("%p: no shaper", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPER;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODE:
		nss_info("%p: no shaper node", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODE;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODES:
		nss_info("%p: no shaper nodes", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_NO_SHAPER_NODES;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_OLD:
		nss_info("%p: old request", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_OLD;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_UNRECOGNISED:
		nss_info("%p: unrecognised command", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_UNRECOGNISED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_QUEUE_LIMIT_INVALID:
		nss_info("%p: fifo queue limit set fail", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_FIFO_QUEUE_LIMIT_INVALID;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_DROP_MODE_INVALID:
		nss_info("%p: fifo drop mode fail", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_FIFO_DROP_MODE_INVALID;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BAD_DEFAULT_CHOICE:
		nss_info("%p: bad default choice", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BAD_DEFAULT_CHOICE;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_DUPLICATE_QOS_TAG:
		nss_info("%p: Duplicate qos tag", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_DUPLICATE_QOS_TAG;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_RATE_AND_BURST_REQUIRED:
		nss_info("%p: Burst size and rate must be provided for CIR", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_CIR_RATE_AND_BURST_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_BURST_LESS_THAN_MTU:
		nss_info("%p: CIR burst size cannot be smaller than mtu", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CIR_BURST_LESS_THAN_MTU;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_LESS_THAN_MTU:
		nss_info("%p: PIR burst size cannot be smaller than mtu", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_LESS_THAN_MTU;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_REQUIRED:
		nss_info("%p: PIR burst size required if peakrate is specifies", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_TBL_PIR_BURST_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_ALL_PARAMS_REQUIRED:
		nss_info("%p: Codel requires non-zero value for target, interval and limit", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_ALL_PARAMS_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_RATE_AND_BURST_REQUIRED:
		nss_info("%p: Burst size and rate must be provided for bf group", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_RATE_AND_BURST_REQUIRED;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_BURST_LESS_THAN_MTU:
		nss_info("%p: Bf group burst cannot be less than MTU", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_BURST_LESS_THAN_MTU;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_CHILD_NOT_BF_GROUP:
		nss_info("%p: Bf can have only Bf group as child node", nss_ctx);
		response.type = NSS_RX_SHAPER_RESPONSE_TYPE_CHILD_NOT_BF_GROUP;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_ALLOC_SUCCESS:
		nss_info("%p: node alloc success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_NODE_ALLOC_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_PRIO_ATTACH_SUCCESS:
		nss_info("%p: prio attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_PRIO_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_PRIO_DETACH_SUCCESS:
		nss_info("%p: prio detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_PRIO_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_CODEL_CHANGE_PARAM_SUCCESS:
		nss_info("%p: codel configure success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_CODEL_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_ATTACH_SUCCESS:
		nss_info("%p: tbl attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_DETACH_SUCCESS:
		nss_info("%p: tbl detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_TBL_CHANGE_PARAM_SUCCESS:
		nss_info("%p: tbl configure success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_TBL_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_ATTACH_SUCCESS:
		nss_info("%p: bf attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_DETACH_SUCCESS:
		nss_info("%p: bf detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_ATTACH_SUCCESS:
		nss_info("%p: bf group attach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_GROUP_ATTACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_DETACH_SUCCESS:
		nss_info("%p: bf group detach success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_GROUP_DETACH_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_BF_GROUP_CHANGE_PARAM_SUCCESS:
		nss_info("%p: bf group configure success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_BF_GROUP_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_SET_ROOT_SUCCESS:
		nss_info("%p: shaper root set success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_SET_ROOT_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_SET_DEFAULT_SUCCESS:
		nss_info("%p: shaper default set success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_SET_DEFAULT_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_FREE_SUCCESS:
		nss_info("%p: node free success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_NODE_FREE_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_UNASSIGN_SUCCESS:
		nss_info("%p: unassign shaper success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_UNASSIGN_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_FIFO_CHANGE_PARAM_SUCCESS:
		nss_info("%p: fifo limit set success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_FIFO_CHANGE_PARAM_SUCCESS;
		break;
	case NSS_RX_SHAPER_RESPONSE_TYPE_SHAPER_NODE_BASIC_STATS_GET_SUCCESS:
		nss_info("%p: basic stats success", nss_ctx);
		response.type = NSS_SHAPER_RESPONSE_TYPE_SHAPER_NODE_BASIC_STATS_GET_SUCCESS;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_packets = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_packets;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_bytes_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.enqueued_packets_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.enqueued_packets_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_packets = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_packets;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_bytes_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.dequeued_packets_dropped = sr->rt.shaper_node_basic_stats_get_success.delta.dequeued_packets_dropped;
		response.rt.shaper_node_basic_stats_get_success.delta.queue_overrun = sr->rt.shaper_node_basic_stats_get_success.delta.queue_overrun;
		response.rt.shaper_node_basic_stats_get_success.qlen_bytes = sr->rt.shaper_node_basic_stats_get_success.qlen_bytes;
		response.rt.shaper_node_basic_stats_get_success.qlen_packets = sr->rt.shaper_node_basic_stats_get_success.qlen_packets;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dequeued = sr->rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dequeued;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dequeued = sr->rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dequeued;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dropped = sr->rt.shaper_node_basic_stats_get_success.packet_latency_peak_msec_dropped;
		response.rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dropped = sr->rt.shaper_node_basic_stats_get_success.packet_latency_minimum_msec_dropped;
		break;
	default:
		module_put(owner);
		nss_warning("%p: unknown response type: %d\n", nss_ctx, response.type);
		return;
	}

	/*
	 * Re-Create original request
	 */
	response.request.i_shaper = ntsc->i_shaper;
	response.request.interface_num = ntsc->interface_num;
	switch(ntsc->type) {
	case NSS_TX_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER:
		nss_info("%p: assign shaper num: %u", nss_ctx, ntsc->mt.assign_shaper.shaper_num);
		response.request.mt.assign_shaper.shaper_num = ntsc->mt.assign_shaper.shaper_num;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE:
		nss_info("%p: Alloc shaper node type: %d, qos_tag: %x",
				nss_ctx, ntsc->mt.alloc_shaper_node.node_type, ntsc->mt.alloc_shaper_node.qos_tag);
		response.request.mt.alloc_shaper_node.node_type = ntsc->mt.alloc_shaper_node.node_type;
		response.request.mt.alloc_shaper_node.qos_tag = ntsc->mt.alloc_shaper_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE:
		nss_info("%p: Free shaper node qos_tag: %x",
				nss_ctx, ntsc->mt.alloc_shaper_node.qos_tag);
		response.request.mt.free_shaper_node.qos_tag = ntsc->mt.free_shaper_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_PRIO_ATTACH:
		nss_info("%p: Prio node: %x, attach: %x, priority: %u",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.prio_attach.child_qos_tag, ntsc->mt.shaper_node_config.snc.prio_attach.priority);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.prio_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.prio_attach.child_qos_tag;
		response.request.mt.shaper_node_config.snc.prio_attach.priority = ntsc->mt.shaper_node_config.snc.prio_attach.priority;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_PRIO_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_PRIO_DETACH:
		nss_info("%p: Prio node: %x, detach @ priority: %u",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.prio_detach.priority);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.prio_detach.priority = ntsc->mt.shaper_node_config.snc.prio_detach.priority;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_PRIO_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM:
		nss_info("%p: Codel node: %x, configure", nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.codel_param.qlen_max = ntsc->mt.shaper_node_config.snc.codel_param.qlen_max;
		response.request.mt.shaper_node_config.snc.codel_param.cap.interval = ntsc->mt.shaper_node_config.snc.codel_param.cap.interval;
		response.request.mt.shaper_node_config.snc.codel_param.cap.target = ntsc->mt.shaper_node_config.snc.codel_param.cap.target;
		response.request.mt.shaper_node_config.snc.codel_param.cap.mtu = ntsc->mt.shaper_node_config.snc.codel_param.cap.mtu;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_TBL_ATTACH:
		nss_info("%p: Tbl node: %x, attach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.tbl_attach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.tbl_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.tbl_attach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_TBL_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_TBL_DETACH:
		nss_info("%p: Tbl node: %x, detach",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_TBL_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM:
		nss_info("%p: Tbl node: %x, configure", nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.tbl_param.qlen_bytes = ntsc->mt.shaper_node_config.snc.tbl_param.qlen_bytes;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.rate = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.rate;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.burst = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.burst;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.max_size = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.max_size;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit = ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.rate = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.rate;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.burst = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.burst;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.max_size = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.max_size;
		response.request.mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit = ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_ATTACH:
		nss_info("%p: Bigfoot node: %x, attach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.bf_attach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.bf_attach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_DETACH:
		nss_info("%p: Bigfoot node: %x, detach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.bf_detach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_detach.child_qos_tag = ntsc->mt.shaper_node_config.snc.bf_detach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH:
		nss_info("%p: Bigfoot group node: %x, attach: %x",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag,
				ntsc->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_group_attach.child_qos_tag = ntsc->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH:
		nss_info("%p: Bigfoot group node: %x, detach",
				nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM:
		nss_info("%p: Bigfoot group node: %x, configure", nss_ctx, ntsc->mt.shaper_node_config.qos_tag);
		response.request.mt.shaper_node_config.qos_tag = ntsc->mt.shaper_node_config.qos_tag;
		response.request.mt.shaper_node_config.snc.bf_group_param.quantum = ntsc->mt.shaper_node_config.snc.bf_group_param.quantum;
		response.request.mt.shaper_node_config.snc.bf_group_param.lap.rate = ntsc->mt.shaper_node_config.snc.bf_group_param.lap.rate;
		response.request.mt.shaper_node_config.snc.bf_group_param.lap.burst = ntsc->mt.shaper_node_config.snc.bf_group_param.lap.burst;
		response.request.mt.shaper_node_config.snc.bf_group_param.lap.max_size = ntsc->mt.shaper_node_config.snc.bf_group_param.lap.max_size;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_SET_DEFAULT:
		nss_info("%p: Set default node qos_tag: %x",
				nss_ctx, ntsc->mt.set_default_node.qos_tag);
		response.request.mt.set_default_node.qos_tag = ntsc->mt.set_default_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_SET_DEFAULT;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_SET_ROOT:
		nss_info("%p: Set root node qos_tag: %x",
				nss_ctx, ntsc->mt.set_root_node.qos_tag);
		response.request.mt.set_root_node.qos_tag = ntsc->mt.set_root_node.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_SET_ROOT;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER:
		nss_info("%p: unassign shaper num: %u", nss_ctx, ntsc->mt.unassign_shaper.shaper_num);
		response.request.mt.unassign_shaper.shaper_num = ntsc->mt.unassign_shaper.shaper_num;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM:
		nss_info("%p: fifo param limit set: %u, drop_mode: %d", nss_ctx, ntsc->mt.shaper_node_config.snc.fifo_param.limit,
				ntsc->mt.shaper_node_config.snc.fifo_param.drop_mode);
		response.request.mt.shaper_node_config.snc.fifo_param.limit = ntsc->mt.shaper_node_config.snc.fifo_param.limit;
		response.request.mt.shaper_node_config.snc.fifo_param.drop_mode = (nss_shaper_config_fifo_drop_mode_t)ntsc->mt.shaper_node_config.snc.fifo_param.drop_mode;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM;
		break;
	case NSS_TX_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET:
		nss_info("%p: basic stats get for: %u", nss_ctx, ntsc->mt.shaper_node_basic_stats_get.qos_tag);
		response.request.mt.shaper_node_basic_stats_get.qos_tag = ntsc->mt.shaper_node_basic_stats_get.qos_tag;
		response.request.type = NSS_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET;
		break;
	default:
		module_put(owner);
		nss_warning("%p: Unknown request type: %d", nss_ctx, ntsc->type);
		return;
	}

	/*
	 * Return the response
	 */
	cb(cb_app_data, &response);
	module_put(owner);
}

/*
 * nss_rx_handle_status_pkt()
 *	Handle the metadata/status packet.
 */
void nss_rx_handle_status_pkt(struct nss_ctx_instance *nss_ctx, struct sk_buff *nbuf)
{
	struct nss_rx_metadata_object *nrmo;

	nrmo = (struct nss_rx_metadata_object *)nbuf->data;

	switch (nrmo->type) {
	case NSS_RX_METADATA_TYPE_IPV4_RULE_ESTABLISH:
		nss_rx_metadata_ipv4_rule_establish(nss_ctx, &nrmo->sub.ipv4_rule_establish);
		break;

	case NSS_RX_METADATA_TYPE_IPV4_RULE_SYNC:
		nss_rx_metadata_ipv4_rule_sync(nss_ctx, &nrmo->sub.ipv4_rule_sync);
		break;

	case NSS_RX_METADATA_TYPE_IPV6_RULE_ESTABLISH:
		nss_rx_metadata_ipv6_rule_establish(nss_ctx, &nrmo->sub.ipv6_rule_establish);
		break;

	case NSS_RX_METADATA_TYPE_IPV6_RULE_SYNC:
		nss_rx_metadata_ipv6_rule_sync(nss_ctx, &nrmo->sub.ipv6_rule_sync);
		break;

	case NSS_RX_METADATA_TYPE_GMAC_STATS_SYNC:
		nss_rx_metadata_gmac_stats_sync(nss_ctx, &nrmo->sub.gmac_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_INTERFACE_STATS_SYNC:
		nss_rx_metadata_interface_stats_sync(nss_ctx, &nrmo->sub.interface_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_NSS_STATS_SYNC:
		nss_rx_metadata_nss_stats_sync(nss_ctx, &nrmo->sub.nss_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_PPPOE_STATS_SYNC:
		nss_rx_metadata_pppoe_exception_stats_sync(nss_ctx, &nrmo->sub.pppoe_exception_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_PPPOE_RULE_CREATE_SUCCESS:
		nss_rx_metadata_pppoe_rule_create_success(nss_ctx, &nrmo->sub.pppoe_rule_create_success);
		break;

	case NSS_RX_METADATA_TYPE_PROFILER_SYNC:
		nss_rx_metadata_profiler_sync(nss_ctx, &nrmo->sub.profiler_sync);
		break;

	case NSS_RX_METADATA_TYPE_FREQ_ACK:
		nss_rx_metadata_nss_freq_ack(nss_ctx, &nrmo->sub.freq_ack);
		break;

	case NSS_RX_METADATA_TYPE_CORE_STATS:
		nss_rx_metadata_nss_core_stats(nss_ctx, &nrmo->sub.core_stats);
		break;

	case NSS_RX_METADATA_TYPE_TUN6RD_STATS_SYNC:
		nss_rx_metadata_tun6rd_stats_sync(nss_ctx, &nrmo->sub.tun6rd_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_TUNIPIP6_STATS_SYNC:
		nss_rx_metadata_tunipip6_stats_sync(nss_ctx, &nrmo->sub.tunipip6_stats_sync);
		break;

	case NSS_RX_METADATA_TYPE_IPSEC_EVENTS_SYNC:
		nss_rx_metadata_ipsec_events_sync(nss_ctx, &nrmo->sub.ipsec_events_sync);
		break;

	case NSS_RX_METADATA_TYPE_SHAPER_RESPONSE:
		nss_rx_metadata_shaper_response(nss_ctx, &nrmo->sub.shaper_response);
		break;

	case NSS_RX_METADATA_TYPE_CRYPTO_SYNC:
		nss_rx_metadata_crypto_sync(nss_ctx, &nrmo->sub.crypto_sync);
		break;

	default:
		/*
		 * WARN: Unknown metadata type
		 */
		nss_warning("%p: Unknown NRMO %d received from NSS, nbuf->data=%p", nss_ctx, nrmo->type, nbuf->data);
	}
}

/*
 * nss_rx_handle_crypto_buf()
 *	Create a nss entry to accelerate the given connection
 */
void nss_rx_handle_crypto_buf(struct nss_ctx_instance *nss_ctx, uint32_t buf, uint32_t paddr, uint32_t len)
{
	void *ctx = nss_ctx->nss_top->crypto_ctx;
	nss_crypto_data_callback_t cb = nss_ctx->nss_top->crypto_data_callback;

	nss_assert(cb != 0);
	if (likely(cb) && likely(ctx)) {
		cb(ctx, (void *)buf, paddr, len);
	}
}

/*
 * nss_tx_create_ipv4_rule()
 *	Create a nss entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv4_rule(void *ctx, struct nss_ipv4_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv4_rule_create *nirc;

	nss_info("%p: Create IPv4: %pI4:%d (%pI4:%d), %pI4:%d (%pI4:%d), p: %d\n", nss_ctx,
		&unic->src_ip, unic->src_port, &unic->src_ip_xlate, unic->src_port_xlate,
		&unic->dest_ip, unic->dest_port, &unic->dest_ip_xlate, unic->dest_port_xlate, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE;

	nirc = &ntmo->sub.ipv4_rule_create;
	nirc->protocol = (uint8_t)unic->protocol;
	nirc->qos_tag = unic->qos_tag;

	nirc->flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nirc->flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nirc->flow_interface_num = unic->src_interface_num;
	nirc->flow_ip = unic->src_ip;
	nirc->flow_ip_xlate = unic->src_ip_xlate;
	nirc->flow_ident = (uint32_t)unic->src_port;
	nirc->flow_ident_xlate = (uint32_t)unic->src_port_xlate;
	nirc->flow_window_scale = unic->flow_window_scale;
	nirc->flow_max_window = unic->flow_max_window;
	nirc->flow_end = unic->flow_end;
	nirc->flow_max_end = unic->flow_max_end;
	nirc->flow_mtu = unic->from_mtu;
	memcpy(nirc->flow_mac, unic->src_mac, 6);
	nirc->ingress_vlan_tag = unic->ingress_vlan_tag;

	nirc->return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nirc->return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nirc->return_interface_num = unic->dest_interface_num;
	nirc->return_ip = unic->dest_ip;
	nirc->return_ip_xlate = unic->dest_ip_xlate;
	nirc->return_ident = (uint32_t)unic->dest_port;
	nirc->return_ident_xlate = (uint32_t)unic->dest_port_xlate;
	nirc->return_window_scale = unic->return_window_scale;
	nirc->return_max_window = unic->return_max_window;
	nirc->return_end = unic->return_end;
	nirc->return_max_end = unic->return_max_end;
	nirc->return_mtu = unic->to_mtu;
	if (nirc->return_ip != nirc->return_ip_xlate || nirc->return_ident != nirc->return_ident_xlate) {
		memcpy(nirc->return_mac, unic->dest_mac_xlate, 6);
	} else {
		memcpy(nirc->return_mac, unic->dest_mac, 6);
	}

	nirc->egress_vlan_tag = unic->egress_vlan_tag;

	nirc->flags = 0;
	if (unic->flags & NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_ROUTED) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipv4_rule1()
 *	Create a nss entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv4_rule1(void *ctx, struct nss_ipv4_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object1 *ntmo;
	struct nss_ipv4_rule_create1 *nirc;

	nss_info("%p: Create IPv4: %pI4:%d (%pI4:%d), %pI4:%d (%pI4:%d), p: %d\n", nss_ctx,
		&unic->src_ip, unic->src_port, &unic->src_ip_xlate, unic->src_port_xlate,
		&unic->dest_ip, unic->dest_port, &unic->dest_ip_xlate, unic->dest_port_xlate, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object1 *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object1));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV4_RULE_CREATE1;

	nirc = &ntmo->sub.ipv4_rule_create;
	nirc->protocol = (uint8_t)unic->protocol;
	nirc->qos_tag = unic->qos_tag;

	nirc->flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nirc->flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nirc->flow_interface_num = unic->src_interface_num;
	nirc->flow_ip = unic->src_ip;
	nirc->flow_ip_xlate = unic->src_ip_xlate;
	nirc->flow_ident = (uint32_t)unic->src_port;
	nirc->flow_ident_xlate = (uint32_t)unic->src_port_xlate;
	nirc->flow_window_scale = unic->flow_window_scale;
	nirc->flow_max_window = unic->flow_max_window;
	nirc->flow_end = unic->flow_end;
	nirc->flow_max_end = unic->flow_max_end;
	nirc->flow_mtu = unic->from_mtu;
	memcpy(nirc->flow_mac, unic->src_mac, 6);
	nirc->ingress_vlan_tag = unic->ingress_vlan_tag;

	nirc->return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nirc->return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nirc->return_interface_num = unic->dest_interface_num;
	nirc->return_ip = unic->dest_ip;
	nirc->return_ip_xlate = unic->dest_ip_xlate;
	nirc->return_ident = (uint32_t)unic->dest_port;
	nirc->return_ident_xlate = (uint32_t)unic->dest_port_xlate;
	nirc->return_window_scale = unic->return_window_scale;
	nirc->return_max_window = unic->return_max_window;
	nirc->return_end = unic->return_end;
	nirc->return_max_end = unic->return_max_end;
	nirc->return_mtu = unic->to_mtu;
	if (nirc->return_ip != nirc->return_ip_xlate || nirc->return_ident != nirc->return_ident_xlate) {
		memcpy(nirc->return_mac, unic->dest_mac_xlate, 6);
	} else {
		memcpy(nirc->return_mac, unic->dest_mac, 6);
	}

	nirc->egress_vlan_tag = unic->egress_vlan_tag;

	nirc->flags = 0;
	if (unic->flags & NSS_IPV4_CREATE_FLAG_NO_SEQ_CHECK) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_BRIDGE_FLOW) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_ROUTED) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_ROUTED;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_DSCP_MARKING) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_VLAN_MARKING) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_VLAN_MARKING;
	}

	/*
	 * Initialize DSCP and VLAN marking data
	 */
	nirc->dscp_itag = unic->dscp_itag ;
	nirc->dscp_imask = unic->dscp_imask;
	nirc->dscp_omask = unic->dscp_omask ;
	nirc->dscp_oval = unic->dscp_oval ;
	nirc->vlan_imask = unic->vlan_imask;
	nirc->vlan_itag = unic->vlan_itag;
	nirc->vlan_omask = unic->vlan_omask ;
	nirc->vlan_oval = unic->vlan_oval ;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}


/*
 * nss_tx_destroy_ipv4_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_tx_destroy_ipv4_rule(void *ctx, struct nss_ipv4_destroy *unid)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv4_rule_destroy *nird;

	nss_info("%p: Destroy IPv4: %pI4:%d, %pI4:%d, p: %d\n", nss_ctx,
		&unid->src_ip, unid->src_port, &unid->dest_ip, unid->dest_port, unid->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPv4' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPv4' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV4_RULE_DESTROY;

	nird = &ntmo->sub.ipv4_rule_destroy;
	nird->protocol = (uint8_t)unid->protocol;
	nird->flow_ip = unid->src_ip;
	nird->flow_ident = (uint32_t)unid->src_port;
	nird->return_ip = unid->dest_ip;
	nird->return_ident = (uint32_t)unid->dest_port;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPv4' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipv6_rule()
 *	Create a NSS entry to accelerate the given connection
 */
nss_tx_status_t nss_tx_create_ipv6_rule(void *ctx, struct nss_ipv6_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv6_rule_create *nirc;

	nss_info("%p: Create IPv6: %pI6:%d, %pI6:%d, p: %d\n", nss_ctx,
		unic->src_ip, unic->src_port, unic->dest_ip, unic->dest_port, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv6' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv6' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV6_RULE_CREATE;

	nirc = &ntmo->sub.ipv6_rule_create;
	nirc->protocol = (uint8_t)unic->protocol;
	nirc->qos_tag = unic->qos_tag;

	nirc->flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nirc->flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nirc->flow_interface_num = unic->src_interface_num;
	nirc->flow_ip[0] = unic->src_ip[0];
	nirc->flow_ip[1] = unic->src_ip[1];
	nirc->flow_ip[2] = unic->src_ip[2];
	nirc->flow_ip[3] = unic->src_ip[3];
	nirc->flow_ident = (uint32_t)unic->src_port;
	nirc->flow_window_scale = unic->flow_window_scale;
	nirc->flow_max_window = unic->flow_max_window;
	nirc->flow_end = unic->flow_end;
	nirc->flow_max_end = unic->flow_max_end;
	nirc->flow_mtu = unic->from_mtu;
	memcpy(nirc->flow_mac, unic->src_mac, 6);
	nirc->ingress_vlan_tag = unic->ingress_vlan_tag;

	nirc->return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nirc->return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nirc->return_interface_num = unic->dest_interface_num;
	nirc->return_ip[0] = unic->dest_ip[0];
	nirc->return_ip[1] = unic->dest_ip[1];
	nirc->return_ip[2] = unic->dest_ip[2];
	nirc->return_ip[3] = unic->dest_ip[3];
	nirc->return_ident = (uint32_t)unic->dest_port;
	nirc->return_window_scale = unic->return_window_scale;
	nirc->return_max_window = unic->return_max_window;
	nirc->return_end = unic->return_end;
	nirc->return_max_end = unic->return_max_end;
	nirc->return_mtu = unic->to_mtu;
	memcpy(nirc->return_mac, unic->dest_mac, 6);

	nirc->egress_vlan_tag = unic->egress_vlan_tag;

	nirc->flags = 0;
	if (unic->flags & NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (unic->flags & NSS_IPV6_CREATE_FLAG_BRIDGE_FLOW) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (unic->flags & NSS_IPV6_CREATE_FLAG_ROUTED) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_ROUTED;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv6' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_create_ipv6_rule1()
 *	Create a NSS entry to accelerate the given connection
 *  This function has been just added to serve the puropose of backward compatibility
 */
nss_tx_status_t nss_tx_create_ipv6_rule1(void *ctx, struct nss_ipv6_create *unic)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object1 *ntmo;
	struct nss_ipv6_rule_create1 *nirc;

	nss_info("%p: Create IPv6: %pI6:%d, %pI6:%d, p: %d\n", nss_ctx,
		unic->src_ip, unic->src_port, unic->dest_ip, unic->dest_port, unic->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Create IPv6' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Create IPv6' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object1 *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object1));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV6_RULE_CREATE1;

	nirc = &ntmo->sub.ipv6_rule_create;
	nirc->protocol = (uint8_t)unic->protocol;
	nirc->qos_tag = unic->qos_tag;

	nirc->flow_pppoe_session_id = unic->flow_pppoe_session_id;
	memcpy(nirc->flow_pppoe_remote_mac, unic->flow_pppoe_remote_mac, ETH_ALEN);
	nirc->flow_interface_num = unic->src_interface_num;
	nirc->flow_ip[0] = unic->src_ip[0];
	nirc->flow_ip[1] = unic->src_ip[1];
	nirc->flow_ip[2] = unic->src_ip[2];
	nirc->flow_ip[3] = unic->src_ip[3];
	nirc->flow_ident = (uint32_t)unic->src_port;
	nirc->flow_window_scale = unic->flow_window_scale;
	nirc->flow_max_window = unic->flow_max_window;
	nirc->flow_end = unic->flow_end;
	nirc->flow_max_end = unic->flow_max_end;
	nirc->flow_mtu = unic->from_mtu;
	memcpy(nirc->flow_mac, unic->src_mac, 6);
	nirc->ingress_vlan_tag = unic->ingress_vlan_tag;

	nirc->return_pppoe_session_id = unic->return_pppoe_session_id;
	memcpy(nirc->return_pppoe_remote_mac, unic->return_pppoe_remote_mac, ETH_ALEN);
	nirc->return_interface_num = unic->dest_interface_num;
	nirc->return_ip[0] = unic->dest_ip[0];
	nirc->return_ip[1] = unic->dest_ip[1];
	nirc->return_ip[2] = unic->dest_ip[2];
	nirc->return_ip[3] = unic->dest_ip[3];
	nirc->return_ident = (uint32_t)unic->dest_port;
	nirc->return_window_scale = unic->return_window_scale;
	nirc->return_max_window = unic->return_max_window;
	nirc->return_end = unic->return_end;
	nirc->return_max_end = unic->return_max_end;
	nirc->return_mtu = unic->to_mtu;
	memcpy(nirc->return_mac, unic->dest_mac, 6);

	nirc->egress_vlan_tag = unic->egress_vlan_tag;

	nirc->flags = 0;
	if (unic->flags & NSS_IPV6_CREATE_FLAG_NO_SEQ_CHECK) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_NO_SEQ_CHECK;
	}

	if (unic->flags & NSS_IPV6_CREATE_FLAG_BRIDGE_FLOW) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_BRIDGE_FLOW;
	}

	if (unic->flags & NSS_IPV6_CREATE_FLAG_ROUTED) {
		nirc->flags |= NSS_IPV6_RULE_CREATE_FLAG_ROUTED;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_DSCP_MARKING) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_DSCP_MARKING;
	}

	if (unic->flags & NSS_IPV4_CREATE_FLAG_VLAN_MARKING) {
		nirc->flags |= NSS_IPV4_RULE_CREATE_FLAG_VLAN_MARKING;
	}

	/*
	 * Initialize DSCP and VLAN marking data
	 */
	nirc->dscp_itag = unic->dscp_itag ;
	nirc->dscp_imask = unic->dscp_imask;
	nirc->dscp_omask = unic->dscp_omask ;
	nirc->dscp_oval = unic->dscp_oval ;
	nirc->vlan_imask = unic->vlan_imask;
	nirc->vlan_itag = unic->vlan_itag;
	nirc->vlan_omask = unic->vlan_omask ;
	nirc->vlan_oval = unic->vlan_oval ;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPv6' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_destroy_ipv6_rule()
 *	Destroy the given connection in the NSS
 */
nss_tx_status_t nss_tx_destroy_ipv6_rule(void *ctx, struct nss_ipv6_destroy *unid)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipv6_rule_destroy *nird;

	nss_info("%p: Destroy IPv6: %pI6:%d, %pI6:%d, p: %d\n", nss_ctx,
		unid->src_ip, unid->src_port, unid->dest_ip, unid->dest_port, unid->protocol);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Destroy IPv6' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Destroy IPv6' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_IPV6_RULE_DESTROY;

	nird = &ntmo->sub.ipv6_rule_destroy;
	nird->protocol = (uint8_t)unid->protocol;
	nird->flow_ip[0] = unid->src_ip[0];
	nird->flow_ip[1] = unid->src_ip[1];
	nird->flow_ip[2] = unid->src_ip[2];
	nird->flow_ip[3] = unid->src_ip[3];
	nird->flow_ident = (uint32_t)unid->src_port;
	nird->return_ip[0] = unid->dest_ip[0];
	nird->return_ip[1] = unid->dest_ip[1];
	nird->return_ip[2] = unid->dest_ip[2];
	nird->return_ip[3] = unid->dest_ip[3];
	nird->return_ident = (uint32_t)unid->dest_port;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Destroy IPv6' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_ipsec_rule
 *	Send  ipsec rule to NSS.
 */
nss_tx_status_t nss_tx_ipsec_rule(void *ctx, uint32_t interface_num, uint32_t type, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_ipsec_rule *nir;

	nss_info("%p: IPsec rule %d for if %d\n", nss_ctx, type, interface_num);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'IPsec' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	if (NSS_NBUF_PAYLOAD_SIZE < (len + sizeof(uint32_t) + sizeof(struct nss_ipsec_rule))) {
		return NSS_TX_FAILURE_TOO_LARGE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'IPsec' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, (sizeof(struct nss_tx_metadata_object) + len));
	ntmo->type = NSS_TX_METADATA_TYPE_IPSEC_RULE;

	nir = &ntmo->sub.ipsec_rule;
	nir->interface_num = interface_num;
	nir->type = type;
	nir->len = len;
	memcpy(nir->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Create IPsec Encap' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_buf ()
 *	Send packet to physical interface owned by NSS
 */
nss_tx_status_t nss_tx_phys_if_buf(void *ctx, struct sk_buff *os_buf, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	int32_t status;

	nss_trace("%p: Phys If Tx packet, id:%d, data=%p", nss_ctx, if_num, os_buf->data);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Tx' packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_buffer(nss_ctx, if_num, os_buf, NSS_IF_DATA_QUEUE, H2N_BUFFER_PACKET, 0);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Unable to enqueue 'Phys If Tx' packet\n", nss_ctx);
		if (status == NSS_CORE_STATUS_FAILURE_QUEUE) {
			return NSS_TX_FAILURE_QUEUE;
		}

		return NSS_TX_FAILURE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].desc_ring.int_bit,
									NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_PACKET]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_open()
 *	Send open command to physical interface
 */
nss_tx_status_t nss_tx_phys_if_open(void *ctx, uint32_t tx_desc_ring, uint32_t rx_desc_ring, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_open *nio;

	nss_info("%p: Phys If Open, id:%d, TxDesc: %x, RxDesc: %x\n", nss_ctx, if_num, tx_desc_ring, rx_desc_ring);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Open' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Open' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_OPEN;

	nio = &ntmo->sub.if_open;
	nio->interface_num = if_num;
	nio->tx_desc_ring = tx_desc_ring;
	nio->rx_desc_ring = rx_desc_ring;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Open' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_phys_if_close()
 *	Send close command to physical interface
 */
nss_tx_status_t nss_tx_phys_if_close(void *ctx, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_close *nic;

	nss_info("%p: Phys If Close, id:%d \n", nss_ctx, if_num);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Close' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Close' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_CLOSE;

	nic = &ntmo->sub.if_close;
	nic->interface_num = if_num;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_info("%p: Unable to enqueue 'Phys If Close' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_link_state()
 *	Send link state to physical interface
 */
nss_tx_status_t nss_tx_phys_if_link_state(void *ctx, uint32_t link_state, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_link_state_notify *nils;

	nss_info("%p: Phys If Link State, id:%d, State: %x\n", nss_ctx, if_num, link_state);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If Link State' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Link State' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_LINK_STATE_NOTIFY;

	nils = &ntmo->sub.if_link_state_notify;
	nils->interface_num = if_num;
	nils->state = link_state;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Link State' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_mac_addr()
 *	Send a MAC address to physical interface
 */
nss_tx_status_t nss_tx_phys_if_mac_addr(void *ctx, uint8_t *addr, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_mac_address_set *nmas;

	nss_info("%p: Phys If MAC Address, id:%d\n", nss_ctx, if_num);
	nss_assert(addr != 0);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Phys If MAC Address' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If MAC Address' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_MAC_ADDR_SET;

	nmas = &ntmo->sub.mac_address_set;
	nmas->interface_num = if_num;
	memcpy(nmas->mac_addr, addr, ETH_ALEN);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Mac Address' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_change_mtu()
 *	Send a MTU change command
 */
nss_tx_status_t nss_tx_phys_if_change_mtu(void *ctx, uint32_t mtu, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status, i;
	uint16_t max_mtu;
	struct nss_tx_metadata_object *ntmo;
	struct nss_if_mtu_change *nimc;

	nss_info("%p: Phys If Change MTU, id:%d, mtu=%d\n", nss_ctx, if_num, mtu);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Phys If Change MTU' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_INTERFACE_MTU_CHANGE;

	nimc = &ntmo->sub.if_mtu_change;
	nimc->interface_num = if_num;
	nimc->min_buf_size = (uint16_t)mtu + NSS_NBUF_ETH_EXTRA;

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Phys If Change MTU' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_ctx->phys_if_mtu[if_num] = (uint16_t)mtu;
	max_mtu = nss_ctx->phys_if_mtu[0];
	for (i = 1; i < NSS_MAX_PHYSICAL_INTERFACES; i++) {
		if (max_mtu < nss_ctx->phys_if_mtu[i]) {
		       max_mtu = nss_ctx->phys_if_mtu[i];
		}
	}

	if (max_mtu <= NSS_ETH_NORMAL_FRAME_MTU) {
		max_mtu = NSS_ETH_NORMAL_FRAME_MTU;
	} else if (max_mtu <= NSS_ETH_MINI_JUMBO_FRAME_MTU) {
		max_mtu = NSS_ETH_MINI_JUMBO_FRAME_MTU;
	} else if (max_mtu <= NSS_ETH_FULL_JUMBO_FRAME_MTU) {
		max_mtu = NSS_ETH_FULL_JUMBO_FRAME_MTU;
	}

	nss_ctx->max_buf_size = ((max_mtu + ETH_HLEN + SMP_CACHE_BYTES - 1) & ~(SMP_CACHE_BYTES - 1)) + NSS_NBUF_PAD_EXTRA;

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_phys_if_get_napi_ctx()
 *	Get napi context
 */
nss_tx_status_t nss_tx_phys_if_get_napi_ctx(void *ctx, struct napi_struct **napi_ctx)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;

	nss_info("%p: Get interrupt context, GMAC\n", nss_ctx);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		return NSS_TX_FAILURE_NOT_READY;
	}

	*napi_ctx = &nss_ctx->int_ctx[0].napi;

	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_crypto_if_open()
 *	NSS crypto configure API.
 */
nss_tx_status_t nss_tx_crypto_if_open(void *ctx, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_crypto_config *nco;

	nss_info("%p: Crypto If Config: buf: %p, len: %d\n", nss_ctx, buf, len);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Crypto If Config' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Crypto If Config' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_CRYPTO_CONFIG;

	nco = &ntmo->sub.crypto_config;
	nco->len = len;
	memcpy(nco->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Crypto If Open' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_crypto_if_buf()
 *	NSS crypto Tx API. Sends a crypto buffer to NSS.
 */
nss_tx_status_t nss_tx_crypto_if_buf(void *ctx, void *buf, uint32_t buf_paddr, uint16_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	int32_t status;

	nss_trace("%p: Crypto If Tx, buf=%p", nss_ctx, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Crypto If Tx' packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	status = nss_core_send_crypto(nss_ctx, buf, buf_paddr, len);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Unable to enqueue 'Crypto If Tx' packet", nss_ctx);
		if (status == NSS_CORE_STATUS_FAILURE_QUEUE) {
			return NSS_TX_FAILURE_QUEUE;
		}

		return NSS_TX_FAILURE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CRYPTO_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_profiler_if_buf()
 *	NSS profiler Tx API
 */
nss_tx_status_t nss_tx_profiler_if_buf(void *ctx, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_profiler_tx *npt;

	nss_trace("%p: Profiler If Tx, buf=%p", nss_ctx, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Profiler If Tx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	if (NSS_NBUF_PAYLOAD_SIZE < (len + sizeof(uint32_t) + sizeof(struct nss_profiler_tx))) {
		return NSS_TX_FAILURE_TOO_LARGE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Profiler If Tx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_PROFILER_TX;

	npt = &ntmo->sub.profiler_tx;
	npt->len = len;
	memcpy(npt->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Profiler If Tx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_generic_if_buf()
 *	NSS Generic rule Tx API
 */
nss_tx_status_t nss_tx_generic_if_buf(void *ctx, uint32_t if_num, uint8_t *buf, uint32_t len)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_generic_if_params *ngip;

	nss_trace("%p: Generic If Tx, interface = %d, buf=%p", nss_ctx, if_num, buf);

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: 'Generic If Tx' rule dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	if (NSS_NBUF_PAYLOAD_SIZE < (len + sizeof(uint32_t) + sizeof(struct nss_generic_if_params))) {
		return NSS_TX_FAILURE_TOO_LARGE;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: 'Generic If Tx' rule dropped as command allocation failed", nss_ctx);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_GENERIC_IF_PARAMS;

	ngip = &ntmo->sub.generic_if_params;
	ngip->interface_num = if_num;
	ngip->len = len;
	memcpy(ngip->buf, buf, len);

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Generic If Tx' rule\n", nss_ctx);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_tx_virt_if_recvbuf()
 *	HLOS interface has received a packet which we redirect to the NSS, if appropriate to do so.
 */
nss_tx_status_t nss_tx_virt_if_recvbuf(void *ctx, struct sk_buff *os_buf, uint32_t nwifi)
{
	int32_t status;
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.ipv4_handler_id];
	int32_t if_num = (int32_t)ctx;
	uint32_t bufftype;

	if (unlikely(nss_ctl_redirect == 0) || unlikely(os_buf->vlan_tci)) {
		return NSS_TX_FAILURE_NOT_SUPPORTED;
	}

	nss_assert(NSS_IS_IF_TYPE(VIRTUAL, if_num));
	nss_trace("%p: Virtual Rx packet, if_num:%d, skb:%p", nss_ctx, if_num, os_buf);

	/*
	 * Get the NSS context that will handle this packet and check that it is initialised and ready
	 */
	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Virtual Rx packet dropped as core not ready", nss_ctx);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Sanity check the SKB to ensure that it's suitable for us
	 */
	if (unlikely(os_buf->len <= ETH_HLEN)) {
		nss_warning("%p: Virtual Rx packet: %p too short", nss_ctx, os_buf);
		return NSS_TX_FAILURE_TOO_SHORT;
	}

	if (unlikely(skb_shinfo(os_buf)->nr_frags != 0)) {
		/*
		 * TODO: If we have a connection matching rule for this skbuff,
		 * do we need to flush it??
		 */
		nss_warning("%p: Delivering the packet to Linux because of fragmented skb: %p\n", nss_ctx, os_buf);
		return NSS_TX_FAILURE_NOT_SUPPORTED;
	}

	if (nwifi) {
		bufftype = H2N_BUFFER_NATIVE_WIFI;
	} else {
		bufftype = H2N_BUFFER_PACKET;
  	   /*
	    * NSS expects to see buffer from Ethernet header onwards
	    * Assumption: eth_type_trans has been done by WLAN driver
	    *
	    */
		skb_push(os_buf, ETH_HLEN);
	}

	/*
	 * Direct the buffer to the NSS
	 */
	status = nss_core_send_buffer(nss_ctx, if_num, os_buf, NSS_IF_DATA_QUEUE, bufftype, H2N_BIT_FLAG_VIRTUAL_BUFFER);
	if (unlikely(status != NSS_CORE_STATUS_SUCCESS)) {
		nss_warning("%p: Virtual Rx packet unable to enqueue\n", nss_ctx);
		if (!nwifi) {
			skb_pull(os_buf, ETH_HLEN);
		}
		return NSS_TX_FAILURE_QUEUE;
	}

	/*
	 * Kick the NSS awake so it can process our new entry.
	 */
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_DATA_QUEUE].desc_ring.int_bit,
						NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);
	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_PACKET]);
	return NSS_TX_SUCCESS;
}

/**
 * @brief Forward virtual interface packets
 *    -This function expects packet with L3 header and eth_type_trans
 *     has been called before calling this api
 *
 *
 * @param nss_ctx NSS context (provided during registeration)
 * @param os_buf OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
nss_tx_status_t nss_tx_virt_if_rxbuf(void *ctx, struct sk_buff *os_buf)
{

	return nss_tx_virt_if_recvbuf(ctx, os_buf, 0);
}

/**
 * @brief Forward Native wifi packet from virtual interface
 *    -Expects packet with qca-nwifi format
 * @param nss_ctx NSS context (provided during registeration)
 * @param os_buf OS buffer (e.g. skbuff)
 * @return nss_tx_status_t Tx status
 */
nss_tx_status_t nss_tx_virt_if_rx_nwifibuf(void *ctx, struct sk_buff *os_buf)
{

	return nss_tx_virt_if_recvbuf(ctx, os_buf, 1);
}


/*
 * nss_get_interface_number()
 *	Return the interface number of the NSS net_device.
 *
 * Returns -1 on failure or the interface number of dev is an NSS net_device.
 */
int32_t nss_get_interface_number(void *ctx, void *dev)
{
	int i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Interface number could not be found as core not ready", nss_ctx);
		return -1;
	}

	nss_assert(dev != 0);

	/*
	 * Check physical interface table
	 */
	for (i = 0; i < NSS_MAX_NET_INTERFACES; i++) {
		if (dev == ((struct nss_ctx_instance *)nss_ctx)->nss_top->if_ctx[i]) {
			return i;
		}
	}

	nss_warning("%p: Interface number could not be found as interface has not registered yet", nss_ctx);
	return -1;
}

/*
 * nss_get_interface_dev()
 *	Return the net_device for NSS interface id.
 *
 * Returns NULL on failure or the net_device for NSS interface id.
 */
void *nss_get_interface_dev(void *ctx, uint32_t if_num)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Interface device could not be found as core not ready", nss_ctx);
		return NULL;
	}

	if (unlikely(if_num >= NSS_MAX_NET_INTERFACES)) {
		return NULL;
	}

	return nss_ctx->nss_top->if_ctx[if_num];
}

/*
 * nss_get_state()
 *	return the NSS initialization state
 */
nss_state_t nss_get_state(void *ctx)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	nss_state_t state = NSS_STATE_UNINITIALIZED;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	spin_lock_bh(&nss_top_main.lock);
	if (nss_ctx->state == NSS_CORE_STATE_INITIALIZED) {
		state = NSS_STATE_INITIALIZED;
	}
	spin_unlock_bh(&nss_top_main.lock);

	return state;
}

/*
 * nss_get_frequency_mgr()
 */
void *nss_get_frequency_mgr(void)
{
	return (void *)&nss_top_main.nss[nss_top_main.frequency_handler_id];
}

/*
 * nss_register_ipv4_mgr()
 */
void *nss_register_ipv4_mgr(nss_ipv4_callback_t event_callback)
{
	nss_top_main.ipv4_callback = event_callback;
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_unregister_ipv4_mgr()
 */
void nss_unregister_ipv4_mgr(void)
{
	nss_top_main.ipv4_callback = NULL;
}

/*
 * nss_get_ipv4_mgr_ctx()
 */
void *nss_get_ipv4_mgr_ctx(void)
{
	return (void *)&nss_top_main.nss[nss_top_main.ipv4_handler_id];
}

/*
 * nss_register_ipv6_mgr()
 *	Called to register an IPv6 connection manager with this driver
 */
void *nss_register_ipv6_mgr(nss_ipv6_callback_t event_callback)
{
	nss_top_main.ipv6_callback = event_callback;
	return (void *)&nss_top_main.nss[nss_top_main.ipv6_handler_id];
}

/*
 * nss_unregister_ipv6_mgr()
 *	Called to unregister an IPv6 connection manager
 */
void nss_unregister_ipv6_mgr(void)
{
	nss_top_main.ipv6_callback = NULL;
}

/*
 * nss_register_connection_expire_all()
 */
void nss_register_connection_expire_all(nss_connection_expire_all_callback_t event_callback)
{
	nss_top_main.conn_expire = event_callback;
}

/*
 * nss_unregister_connection_expire_all()
 */
void nss_unregister_connection_expire_all(void)
{
	nss_top_main.conn_expire = NULL;
}

/*
 * nss_register_queue_decongestion()
 *	Register for queue decongestion event
 */
nss_cb_register_status_t nss_register_queue_decongestion(void *ctx, nss_queue_decongestion_callback_t event_callback, void *app_ctx)
{
	uint32_t i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	spin_lock_bh(&nss_ctx->decongest_cb_lock);

	/*
	 * Find vacant location in callback table
	 */
	for (i = 0; i< NSS_MAX_CLIENTS; i++) {
		if (nss_ctx->queue_decongestion_callback[i] == NULL) {
			nss_ctx->queue_decongestion_callback[i] = event_callback;
			nss_ctx->queue_decongestion_ctx[i] = app_ctx;
			spin_unlock_bh(&nss_ctx->decongest_cb_lock);
			return NSS_CB_REGISTER_SUCCESS;
		}
	}

	spin_unlock_bh(&nss_ctx->decongest_cb_lock);
	return NSS_CB_REGISTER_FAILED;
}

/*
 * nss_unregister_queue_decongestion()
 *	Unregister for queue decongestion event
 */
nss_cb_unregister_status_t nss_unregister_queue_decongestion(void *ctx, nss_queue_decongestion_callback_t event_callback)
{
	uint32_t i;
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;

	NSS_VERIFY_CTX_MAGIC(nss_ctx);
	spin_lock_bh(&nss_ctx->decongest_cb_lock);

	/*
	 * Find actual location in callback table
	 */
	for (i = 0; i< NSS_MAX_CLIENTS; i++) {
		if (nss_ctx->queue_decongestion_callback[i] == event_callback) {
			nss_ctx->queue_decongestion_callback[i] = NULL;
			nss_ctx->queue_decongestion_ctx[i] = NULL;
			spin_unlock_bh(&nss_ctx->decongest_cb_lock);
			return NSS_CB_UNREGISTER_SUCCESS;
		}
	}

	spin_unlock_bh(&nss_ctx->decongest_cb_lock);
	return NSS_CB_UNREGISTER_FAILED;
}

/*
 * nss_register_crypto_mgr()
 */
void *nss_register_crypto_if(nss_crypto_data_callback_t crypto_data_callback, void *ctx)
{
	nss_top_main.crypto_ctx = ctx;
	nss_top_main.crypto_data_callback = crypto_data_callback;

	return (void *)&nss_top_main.nss[nss_top_main.crypto_handler_id];
}

/*
 * nss_register_crypto_sync_if()
 */
void nss_register_crypto_sync_if(nss_crypto_sync_callback_t crypto_sync_callback, void *ctx)
{
	nss_top_main.crypto_ctx = ctx;
	nss_top_main.crypto_sync_callback = crypto_sync_callback;
}

/*
 * nss_unregister_crypto_mgr()
 */
void nss_unregister_crypto_if(void)
{
	nss_top_main.crypto_data_callback = NULL;
	nss_top_main.crypto_sync_callback = NULL;
	nss_top_main.crypto_ctx = NULL;
}

/*
 * nss_register_phys_if()
 */
void *nss_register_phys_if(uint32_t if_num,
				nss_phys_if_rx_callback_t rx_callback,
				nss_phys_if_event_callback_t event_callback, struct net_device *if_ctx)
{
	uint8_t id = nss_top_main.phys_if_handler_id[if_num];
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[id];

	nss_assert(if_num <= NSS_MAX_PHYSICAL_INTERFACES);

	nss_top_main.if_ctx[if_num] = (void *)if_ctx;
	nss_top_main.if_rx_callback[if_num] = rx_callback;
	nss_top_main.phys_if_event_callback[if_num] = event_callback;

	nss_ctx->phys_if_mtu[if_num] = NSS_ETH_NORMAL_FRAME_MTU;
	return (void *)nss_ctx;
}

/*
 * nss_unregister_phys_if()
 */
void nss_unregister_phys_if(uint32_t if_num)
{
	nss_assert(if_num < NSS_MAX_PHYSICAL_INTERFACES);

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.phys_if_event_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.nss[0].phys_if_mtu[if_num] = 0;
	nss_top_main.nss[1].phys_if_mtu[if_num] = 0;
}

/*
 * nss_virt_if_get_interface_num()
 *	Get interface number for a virtual interface
 */
int32_t nss_virt_if_get_interface_num(void *if_ctx)
{
	int32_t if_num = (int32_t)if_ctx;
	nss_assert(NSS_IS_IF_TYPE(VIRTUAL, if_num));
	return if_num;
}

/*
 * nss_create_virt_if()
 */
void *nss_create_virt_if(struct net_device *if_ctx)
{
	int32_t if_num, status;
	struct sk_buff *nbuf;
	struct nss_tx_metadata_object *ntmo;
	struct nss_virtual_interface_create *nvic;
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.ipv4_handler_id];

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("Interface could not be created as core not ready");
		return NULL;
	}

	/*
	 * Check if net_device is Ethernet type
	 */
	if (if_ctx->type != ARPHRD_ETHER) {
		nss_warning("%p:Register virtual interface %p: type incorrect: %d ", nss_ctx, if_ctx, if_ctx->type);
		return NULL;
	}

	/*
	 * Find a free virtual interface
	 */
	spin_lock_bh(&nss_top_main.lock);
	for (if_num = NSS_MAX_PHYSICAL_INTERFACES; if_num < NSS_MAX_DEVICE_INTERFACES; ++if_num) {
		if (!nss_top_main.if_ctx[if_num]) {
			/*
			 * Use this redirection interface
			 */
			nss_top_main.if_ctx[if_num] = (void *)if_ctx;
			break;
		}
	}

	spin_unlock_bh(&nss_top_main.lock);
	if (if_num == NSS_MAX_DEVICE_INTERFACES) {
		/*
		 * No available virtual contexts
		 */
		nss_warning("%p:Register virtual interface %p: no contexts available:", nss_ctx, if_ctx);
		return NULL;
	}

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: Register virtual interface %p: command allocation failed", nss_ctx, if_ctx);
		return NULL;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_CREATE;
	nvic = &ntmo->sub.virtual_interface_create;
	nvic->interface_num = if_num;
	nvic->flags = 0;
	memcpy(nvic->mac_addr, if_ctx->dev_addr, ETH_HLEN);
	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'Register virtual interface' rule\n", nss_ctx);
		return NULL;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
		NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	/*
	 * Hold a reference to the net_device
	 */
	dev_hold(if_ctx);
	nss_info("%p:Registered virtual interface %d: context %p", nss_ctx, if_num, if_ctx);

	/*
	 * The context returned is the virtual interface # which is, essentially, the index into the if_ctx
	 * array that is holding the net_device pointer
	 */
	return (void *)if_num;
}

/*
 * nss_destroy_virt_if()
 */
nss_tx_status_t nss_destroy_virt_if(void *ctx)
{
	int32_t status, if_num;
	struct sk_buff *nbuf;
	struct nss_tx_metadata_object *ntmo;
	struct nss_virtual_interface_destroy *nvid;
	struct net_device *dev;
	struct nss_ctx_instance *nss_ctx = &nss_top_main.nss[nss_top_main.ipv4_handler_id];

	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("Interface could not be destroyed as core not ready");
		return NSS_TX_FAILURE_NOT_READY;
	}

	if_num = (int32_t)ctx;
	nss_assert(NSS_IS_IF_TYPE(VIRTUAL, if_num));

	spin_lock_bh(&nss_top_main.lock);
	if (!nss_top_main.if_ctx[if_num]) {
		spin_unlock_bh(&nss_top_main.lock);
		nss_warning("%p: Unregister virtual interface %d: no context", nss_ctx, if_num);
		return NSS_TX_FAILURE_BAD_PARAM;
	}

	/*
	 * Set this context to NULL
	 */
	dev = nss_top_main.if_ctx[if_num];
	nss_top_main.if_ctx[if_num] = NULL;
	spin_unlock_bh(&nss_top_main.lock);
	nss_info("%p:Unregister virtual interface %d (%p)", nss_ctx, if_num, dev);
	dev_put(dev);

	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: Unregister virtual interface %d: command allocation failed", nss_ctx, if_num);
		return NSS_TX_FAILURE;
	}

	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_VIRTUAL_INTERFACE_DESTROY;
	nvid = &ntmo->sub.virtual_interface_destroy;
	nvid->interface_num = if_num;
	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unable to enqueue 'unregister virtual interface' rule\n", nss_ctx);
		return NSS_TX_FAILURE_QUEUE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
		NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	return NSS_TX_SUCCESS;
}

/*
 * nss_register_ipsec_if()
 */
void *nss_register_ipsec_if(uint32_t if_num,
				nss_ipsec_data_callback_t ipsec_data_cb,
				void *if_ctx)
{
	nss_assert((if_num >= NSS_MAX_PHYSICAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_ctx[if_num] = if_ctx;
	nss_top_main.if_rx_callback[if_num] = ipsec_data_cb;

	return (void *)&nss_top_main.nss[nss_top_main.ipsec_handler_id];
}

/*
 * nss_register_ipsec_event_if()
 */
void nss_register_ipsec_event_if(uint32_t if_num, nss_ipsec_event_callback_t ipsec_event_cb)
{
	nss_assert((if_num >= NSS_MAX_PHYSICAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.ipsec_event_callback = ipsec_event_cb;
}

/*
 * nss_unregister_ipsec_if()
 */
void nss_unregister_ipsec_if(uint32_t if_num)
{
	nss_assert((if_num >= NSS_MAX_PHYSICAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.ipsec_event_callback = NULL;
}

/*
 * nss_register_tun6rd_if()
 */
void *nss_register_tun6rd_if(uint32_t if_num,
				nss_tun6rd_callback_t tun6rd_callback,
				nss_tun6rd_if_event_callback_t event_callback, void *if_ctx)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_ctx[if_num] = if_ctx;
	nss_top_main.if_rx_callback[if_num] = tun6rd_callback;
	nss_top_main.tun6rd_if_event_callback = event_callback;

	return (void *)&nss_top_main.nss[nss_top_main.tun6rd_handler_id];
}

/*
 * nss_unregister_tun6rd_if()
 */
void nss_unregister_tun6rd_if(uint32_t if_num)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.tun6rd_if_event_callback = NULL;
}

/*
 * nss_register_tunipip6_if()
 */
void *nss_register_tunipip6_if(uint32_t if_num,
				nss_tunipip6_callback_t tunipip6_callback,
				nss_tunipip6_if_event_callback_t event_callback, void *if_ctx)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_ctx[if_num] = if_ctx;
	nss_top_main.if_rx_callback[if_num] = tunipip6_callback;
	nss_top_main.tunipip6_if_event_callback = event_callback;

	return (void *)&nss_top_main.nss[nss_top_main.tunipip6_handler_id];
}

/*
 * nss_unregister_tunipip6_if()
 */
void nss_unregister_tunipip6_if(uint32_t if_num)
{
	nss_assert((if_num >= NSS_MAX_VIRTUAL_INTERFACES) && (if_num < NSS_MAX_NET_INTERFACES));

	nss_top_main.if_rx_callback[if_num] = NULL;
	nss_top_main.if_ctx[if_num] = NULL;
	nss_top_main.tunipip6_if_event_callback = NULL;
}

/*
 * nss_register_profiler_if()
 */
void *nss_register_profiler_if(nss_profiler_callback_t profiler_callback, nss_core_id_t core_id, void *ctx)
{
	nss_assert(core_id < NSS_CORE_MAX);

	nss_top_main.profiler_ctx[core_id] = ctx;
	nss_top_main.profiler_callback[core_id] = profiler_callback;

	return (void *)&nss_top_main.nss[core_id];
}

/*
 * nss_unregister_profiler_if()
 */
void nss_unregister_profiler_if(nss_core_id_t core_id)
{
	nss_assert(core_id < NSS_CORE_MAX);

	nss_top_main.profiler_callback[core_id] = NULL;
	nss_top_main.profiler_ctx[core_id] = NULL;
}

/*
 * nss_register_shaping()
 *	Register to obtain an NSS context for basic shaping operations
 */
void *nss_register_shaping(void)
{
	if (nss_top_main.shaping_handler_id == (uint8_t)-1) {
		nss_warning("%p: SHAPING IS NOT ENABLED", __func__);
		return NULL;
	}
	return (void *)&nss_top_main.nss[nss_top_main.shaping_handler_id];
}

/*
 * nss_unregister_shaping()
 *	Unregister an NSS shaping context
 */
void nss_unregister_shaping(void *nss_ctx)
{
}

/*
 * nss_shaper_config_send()
 *	Issue a config message to the shaping subsystem of the NSS.
 */
nss_tx_status_t nss_shaper_config_send(void *ctx, struct nss_shaper_configure *config)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *) ctx;
	struct sk_buff *nbuf;
	int32_t status;
	struct nss_tx_metadata_object *ntmo;
	struct nss_tx_shaper_configure *ntsc;

	nss_info("%p:Shaper config: %p send:  if_num: %u i_shaper: %u, type: %d, owner: %p\n", nss_ctx,
		config, config->interface_num, config->i_shaper, config->type, config->owner);
	NSS_VERIFY_CTX_MAGIC(nss_ctx);

	/*
	 * Core should be ready
	 */
	if (unlikely(nss_ctx->state != NSS_CORE_STATE_INITIALIZED)) {
		nss_warning("%p: Shaper config: %p core not ready", nss_ctx, config);
		return NSS_TX_FAILURE_NOT_READY;
	}

	/*
	 * Allocate buffer for command
	 */
	nbuf = dev_alloc_skb(NSS_NBUF_PAYLOAD_SIZE);
	if (unlikely(!nbuf)) {
		spin_lock_bh(&nss_ctx->nss_top->stats_lock);
		nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_NBUF_ALLOC_FAILS]++;
		spin_unlock_bh(&nss_ctx->nss_top->stats_lock);
		nss_warning("%p: Shaper config: %p alloc fail", nss_ctx, config);
		return NSS_TX_FAILURE;
	}

	/*
	 * Hold the module until we are done with the request
	 */
	if (!try_module_get(config->owner)) {
		nss_warning("%p: Shaper config: %p module shutting down: %p", nss_ctx, config, config->owner);
		return NSS_TX_FAILURE;
	}

	/*
	 * Copy the HLOS API structures command into the NSS metadata object command.
	 */
	nss_info("%p: config type: %d", nss_ctx, config->type);
	ntmo = (struct nss_tx_metadata_object *)skb_put(nbuf, sizeof(struct nss_tx_metadata_object));
	ntmo->type = NSS_TX_METADATA_TYPE_SHAPER_CONFIGURE;
	ntsc = &ntmo->sub.shaper_configure;

	ntsc->opaque1 = (uint32_t)config->cb;
	ntsc->opaque2 = (uint32_t)config->app_data;
	ntsc->opaque3 = (uint32_t)config->owner;
	ntsc->i_shaper = config->i_shaper;
	ntsc->interface_num = config->interface_num;

	switch(config->type) {
	case NSS_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER:
		nss_info("%p: Assign shaper num: %u", nss_ctx, config->mt.assign_shaper.shaper_num);
		ntsc->mt.assign_shaper.shaper_num = config->mt.assign_shaper.shaper_num;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_ASSIGN_SHAPER;
		break;
	case NSS_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE:
		nss_info("%p: Alloc shaper node type: %d, qos_tag: %x",
				nss_ctx, config->mt.alloc_shaper_node.node_type, config->mt.alloc_shaper_node.qos_tag);
		ntsc->mt.alloc_shaper_node.node_type = config->mt.alloc_shaper_node.node_type;
		ntsc->mt.alloc_shaper_node.qos_tag = config->mt.alloc_shaper_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_ALLOC_SHAPER_NODE;
		break;
	case NSS_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE:
		nss_info("%p: Free shaper node qos_tag: %x",
				nss_ctx, config->mt.alloc_shaper_node.qos_tag);
		ntsc->mt.free_shaper_node.qos_tag = config->mt.free_shaper_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_FREE_SHAPER_NODE;
		break;
	case NSS_SHAPER_CONFIG_TYPE_PRIO_ATTACH:
		nss_info("%p: Prio node: %x, attach: %x, priority: %u",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.prio_attach.child_qos_tag, config->mt.shaper_node_config.snc.prio_attach.priority);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.prio_attach.child_qos_tag = config->mt.shaper_node_config.snc.prio_attach.child_qos_tag;
		ntsc->mt.shaper_node_config.snc.prio_attach.priority = config->mt.shaper_node_config.snc.prio_attach.priority;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_PRIO_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_PRIO_DETACH:
		nss_info("%p: Prio node: %x, detach @ priority: %u",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.prio_detach.priority);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.prio_detach.priority = config->mt.shaper_node_config.snc.prio_detach.priority;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_PRIO_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM:
		nss_info("%p: Shaper node: %x", nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.codel_param.qlen_max = config->mt.shaper_node_config.snc.codel_param.qlen_max;
		ntsc->mt.shaper_node_config.snc.codel_param.cap.interval = config->mt.shaper_node_config.snc.codel_param.cap.interval;
		ntsc->mt.shaper_node_config.snc.codel_param.cap.target = config->mt.shaper_node_config.snc.codel_param.cap.target;
		ntsc->mt.shaper_node_config.snc.codel_param.cap.mtu = config->mt.shaper_node_config.snc.codel_param.cap.mtu;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_CODEL_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_TBL_ATTACH:
		nss_info("%p: Tbl node: %x attach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.tbl_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.tbl_attach.child_qos_tag = config->mt.shaper_node_config.snc.tbl_attach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_TBL_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_TBL_DETACH:
		nss_info("%p: Tbl node: %x, detach",
				nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_TBL_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM:
		nss_info("%p: Tbl node: %x configure", nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.tbl_param.qlen_bytes = config->mt.shaper_node_config.snc.tbl_param.qlen_bytes;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.rate = config->mt.shaper_node_config.snc.tbl_param.lap_cir.rate;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.burst = config->mt.shaper_node_config.snc.tbl_param.lap_cir.burst;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.max_size = config->mt.shaper_node_config.snc.tbl_param.lap_cir.max_size;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit = config->mt.shaper_node_config.snc.tbl_param.lap_cir.short_circuit;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.rate = config->mt.shaper_node_config.snc.tbl_param.lap_pir.rate;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.burst = config->mt.shaper_node_config.snc.tbl_param.lap_pir.burst;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.max_size = config->mt.shaper_node_config.snc.tbl_param.lap_pir.max_size;
		ntsc->mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit = config->mt.shaper_node_config.snc.tbl_param.lap_pir.short_circuit;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_TBL_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_ATTACH:
		nss_info("%p: Bf node: %x attach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.bf_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_attach.child_qos_tag = config->mt.shaper_node_config.snc.bf_attach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_DETACH:
		nss_info("%p: Bf node: %x, detach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.bf_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_detach.child_qos_tag = config->mt.shaper_node_config.snc.bf_detach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH:
		nss_info("%p: Bf group node: %x attach: %x",
				nss_ctx, config->mt.shaper_node_config.qos_tag,
				config->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag = config->mt.shaper_node_config.snc.bf_group_attach.child_qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_ATTACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH:
		nss_info("%p: Bf group node: %x, detach",
				nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_DETACH;
		break;
	case NSS_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM:
		nss_info("%p: Bf node: %x configure", nss_ctx, config->mt.shaper_node_config.qos_tag);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.bf_group_param.quantum = config->mt.shaper_node_config.snc.bf_group_param.quantum;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.rate = config->mt.shaper_node_config.snc.bf_group_param.lap.rate;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.burst = config->mt.shaper_node_config.snc.bf_group_param.lap.burst;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.max_size = config->mt.shaper_node_config.snc.bf_group_param.lap.max_size;
		ntsc->mt.shaper_node_config.snc.bf_group_param.lap.short_circuit = config->mt.shaper_node_config.snc.bf_group_param.lap.short_circuit;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_BF_GROUP_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_SET_DEFAULT:
		nss_info("%p: Set default node qos_tag: %x",
				nss_ctx, config->mt.set_default_node.qos_tag);
		ntsc->mt.set_default_node.qos_tag = config->mt.set_default_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_SET_DEFAULT;
		break;
	case NSS_SHAPER_CONFIG_TYPE_SET_ROOT:
		nss_info("%p: Set root node qos_tag: %x",
				nss_ctx, config->mt.set_root_node.qos_tag);
		ntsc->mt.set_root_node.qos_tag = config->mt.set_root_node.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_SET_ROOT;
		break;
	case NSS_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER:
		nss_info("%p: UNassign shaper num: %u", nss_ctx, config->mt.unassign_shaper.shaper_num);
		ntsc->mt.unassign_shaper.shaper_num = config->mt.unassign_shaper.shaper_num;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_UNASSIGN_SHAPER;
		break;
	case NSS_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM:
		nss_info("%p: fifo parameter set: %u, drop mode: %d", nss_ctx, config->mt.shaper_node_config.snc.fifo_param.limit,
				config->mt.shaper_node_config.snc.fifo_param.drop_mode);
		ntsc->mt.shaper_node_config.qos_tag = config->mt.shaper_node_config.qos_tag;
		ntsc->mt.shaper_node_config.snc.fifo_param.limit = config->mt.shaper_node_config.snc.fifo_param.limit;
		ntsc->mt.shaper_node_config.snc.fifo_param.drop_mode = (nss_tx_shaper_config_fifo_drop_mode_t)config->mt.shaper_node_config.snc.fifo_param.drop_mode;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_FIFO_CHANGE_PARAM;
		break;
	case NSS_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET:
		nss_info("%p: Get basic statistics for: %u", nss_ctx, config->mt.shaper_node_basic_stats_get.qos_tag);
		ntsc->mt.shaper_node_basic_stats_get.qos_tag = config->mt.shaper_node_basic_stats_get.qos_tag;
		ntsc->type = NSS_TX_SHAPER_CONFIG_TYPE_SHAPER_NODE_BASIC_STATS_GET;
		break;
	default:
		/*
		 * Release module
		 */
		module_put(config->owner);
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Unknown type: %d", nss_ctx, config->type);
		return NSS_TX_FAILURE;
	}

	status = nss_core_send_buffer(nss_ctx, 0, nbuf, NSS_IF_CMD_QUEUE, H2N_BUFFER_CTRL, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		/*
		 * Release module
		 */
		module_put(config->owner);
		dev_kfree_skb_any(nbuf);
		nss_warning("%p: Shaper config: %p Unable to enqueue\n", nss_ctx, config);
		return NSS_TX_FAILURE;
	}

	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_register_shaper_bounce_interface()
 *	Register for performing shaper bounce operations for interface shaper
 */
void *nss_register_shaper_bounce_interface(uint32_t if_num, nss_shaper_bounced_callback_t cb, void *app_data, struct module *owner)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_shaper_bounce_registrant *reg;

	nss_info("Shaper bounce interface register: %u, cb: %p, app_data: %p, owner: %p",
			if_num, cb, app_data, owner);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	/*
 	 * Shaping enabled?
	 */
	if (nss_top_main.shaping_handler_id == (uint8_t)-1) {
		nss_warning("%p: SHAPING IS NOT ENABLED", __func__);
		return NULL;
	}

	/*
	 * Can we hold the module?
	 */
	if (!try_module_get(owner)) {
		nss_warning("%p: Unable to hold owner", __func__);
		return NULL;
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must not have existing registrant
	 */
	reg = &nss_top->bounce_interface_registrants[if_num];
	if (reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		module_put(owner);
		nss_warning("Already registered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Register
	 */
	reg->bounced_callback = cb;
	reg->app_data = app_data;
	reg->owner = owner;
	reg->registered = true;
	spin_unlock_bh(&nss_top->lock);

	return (void *)&nss_top->nss[nss_top->shaping_handler_id];
}

/*
 * nss_unregister_shaper_bounce_interface()
 *	Unregister for shaper bounce operations for interface shaper
 */
void nss_unregister_shaper_bounce_interface(uint32_t if_num)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_shaper_bounce_registrant *reg;
	struct module *owner;

	nss_info("Shaper bounce interface unregister: %u", if_num);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must have existing registrant
	 */
	reg = &nss_top->bounce_interface_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("Already unregistered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Unegister
	 */
	owner = reg->owner;
	reg->owner = NULL;
	reg->registered = false;
	spin_unlock_bh(&nss_top->lock);

	module_put(owner);
}

/*
 * nss_register_shaper_bounce_bridge()
 *	Register for performing shaper bounce operations for bridge shaper
 */
void *nss_register_shaper_bounce_bridge(uint32_t if_num, nss_shaper_bounced_callback_t cb, void *app_data, struct module *owner)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_ctx_instance *nss_ctx;
	struct nss_shaper_bounce_registrant *reg;

	nss_info("Shaper bounce bridge register: %u, cb: %p, app_data: %p, owner: %p",
			if_num, cb, app_data, owner);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	/*
 	 * Shaping enabled?
	 */
	if (nss_top_main.shaping_handler_id == (uint8_t)-1) {
		nss_warning("%p: SHAPING IS NOT ENABLED", __func__);
		return NULL;
	}

	/*
	 * Can we hold the module?
	 */
	if (!try_module_get(owner)) {
		nss_warning("%p: Unable to hold owner", __func__);
		return NULL;
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must not have existing registrant
	 */
	reg = &nss_top->bounce_bridge_registrants[if_num];
	if (reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		module_put(owner);
		nss_warning("Already registered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Register
	 */
	reg->bounced_callback = cb;
	reg->app_data = app_data;
	reg->owner = owner;
	reg->registered = true;
	spin_unlock_bh(&nss_top->lock);

	nss_ctx = &nss_top->nss[nss_top->shaping_handler_id];
	return (void *)nss_ctx;
}

/*
 * nss_unregister_shaper_bounce_bridge()
 *	Unregister for shaper bounce operations for bridge shaper
 */
void nss_unregister_shaper_bounce_bridge(uint32_t if_num)
{
	struct nss_top_instance *nss_top = &nss_top_main;
	struct nss_shaper_bounce_registrant *reg;
	struct module *owner;

	nss_info("Shaper bounce bridge unregister: %u", if_num);

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}

	spin_lock_bh(&nss_top->lock);

	/*
	 * Must have existing registrant
	 */
	reg = &nss_top->bounce_bridge_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("Already unregistered: %u", if_num);
		BUG_ON(false);
	}

	/*
	 * Wait until any bounce callback that is active is finished
	 */
	while (reg->callback_active) {
		spin_unlock_bh(&nss_top->stats_lock);
		yield();
		spin_lock_bh(&nss_top->stats_lock);
	}

	/*
	 * Unegister
	 */
	owner = reg->owner;
	reg->owner = NULL;
	reg->registered = false;
	spin_unlock_bh(&nss_top->lock);

	module_put(owner);
}

/*
 * nss_shaper_bounce_interface_packet()
 *	Bounce a packet to the NSS for interface shaping.
 *
 * You must have registered for interface bounce shaping to call this.
 */
nss_tx_status_t nss_shaper_bounce_interface_packet(void *ctx, uint32_t if_num, struct sk_buff *skb)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_shaper_bounce_registrant *reg;
	int32_t status;

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}


	/*
	 * Must have existing registrant
	 */
	spin_lock_bh(&nss_top->lock);
	reg = &nss_top->bounce_interface_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("unregistered: %u", if_num);
		return NSS_TX_FAILURE;
	}
	spin_unlock_bh(&nss_top->lock);

	status = nss_core_send_buffer(nss_ctx, if_num, skb, 0, H2N_BUFFER_SHAPER_BOUNCE_INTERFACE, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		return NSS_TX_FAILURE;
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_shaper_bounce_bridge_packet()
 *	Bounce a packet to the NSS for bridge shaping.
 *
 * You must have registered for bridge bounce shaping to call this.
 */
nss_tx_status_t nss_shaper_bounce_bridge_packet(void *ctx, uint32_t if_num, struct sk_buff *skb)
{
	struct nss_ctx_instance *nss_ctx = (struct nss_ctx_instance *)ctx;
	struct nss_top_instance *nss_top = nss_ctx->nss_top;
	struct nss_shaper_bounce_registrant *reg;
	int32_t status;
	uint32_t nr_frags;

	/*
	 * Must be valid interface number
	 */
	if (if_num >= NSS_MAX_NET_INTERFACES) {
		nss_warning("Invalid if_num: %u", if_num);
		BUG_ON(false);
	}


	/*
	 * Must have existing registrant
	 */
	spin_lock_bh(&nss_top->lock);
	reg = &nss_top->bounce_bridge_registrants[if_num];
	if (!reg->registered) {
		spin_unlock_bh(&nss_top->stats_lock);
		nss_warning("unregistered: %u", if_num);
		return NSS_TX_FAILURE;
	}
	spin_unlock_bh(&nss_top->lock);

	/*
	 * We defrag the skb in HLOS since packets have to be bounced back to
	 * the driver after bridge shaping. The driver will assert (opaque = 0)
	 * if it sees a fragmented packet coming back up.
	 *
	 * TODO: Implementing SG list in NSS will help us get rid of this?
	 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags != 0) {
		struct sk_buff *old_skb = skb;

		skb = skb_copy(skb, GFP_KERNEL);
		if (!skb) {
			return NSS_TX_FAILURE;
		}
		dev_kfree_skb_any(old_skb);
	}

	nss_info("%s: Bridge bounce skb: %p, if_num: %u, ctx: %p", __func__, skb, if_num, nss_ctx);
	status = nss_core_send_buffer(nss_ctx, if_num, skb, NSS_IF_CMD_QUEUE, H2N_BUFFER_SHAPER_BOUNCE_BRIDGE, 0);
	if (status != NSS_CORE_STATUS_SUCCESS) {
		nss_info("%s: Bridge bounce core send rejected", __func__);
		return NSS_TX_FAILURE;
	}
	nss_hal_send_interrupt(nss_ctx->nmap, nss_ctx->h2n_desc_rings[NSS_IF_CMD_QUEUE].desc_ring.int_bit,
								NSS_REGS_H2N_INTR_STATUS_DATA_COMMAND_QUEUE);

	NSS_PKT_STATS_INCREMENT(nss_ctx, &nss_ctx->nss_top->stats_drv[NSS_STATS_DRV_TX_CMD_REQ]);
	return NSS_TX_SUCCESS;
}

/*
 * nss_interface_is_virtual()
 * 	Return true if the interface number is a virtual NSS interface
 */
bool nss_interface_is_virtual(void *nss_ctx, int32_t interface_num)
{
	return (NSS_IS_IF_TYPE(VIRTUAL, interface_num));
}

EXPORT_SYMBOL(nss_virt_if_get_interface_num);
EXPORT_SYMBOL(nss_interface_is_virtual);
EXPORT_SYMBOL(nss_shaper_bounce_bridge_packet);
EXPORT_SYMBOL(nss_shaper_bounce_interface_packet);
EXPORT_SYMBOL(nss_unregister_shaper_bounce_interface);
EXPORT_SYMBOL(nss_register_shaper_bounce_interface);
EXPORT_SYMBOL(nss_unregister_shaper_bounce_bridge);
EXPORT_SYMBOL(nss_register_shaper_bounce_bridge);
EXPORT_SYMBOL(nss_register_shaping);
EXPORT_SYMBOL(nss_unregister_shaping);
EXPORT_SYMBOL(nss_shaper_config_send);

EXPORT_SYMBOL(nss_get_interface_number);
EXPORT_SYMBOL(nss_get_interface_dev);
EXPORT_SYMBOL(nss_get_state);

EXPORT_SYMBOL(nss_register_connection_expire_all);
EXPORT_SYMBOL(nss_unregister_connection_expire_all);

EXPORT_SYMBOL(nss_register_queue_decongestion);
EXPORT_SYMBOL(nss_unregister_queue_decongestion);

EXPORT_SYMBOL(nss_register_ipv4_mgr);
EXPORT_SYMBOL(nss_unregister_ipv4_mgr);
EXPORT_SYMBOL(nss_tx_create_ipv4_rule);
EXPORT_SYMBOL(nss_tx_create_ipv4_rule1);
EXPORT_SYMBOL(nss_tx_destroy_ipv4_rule);

EXPORT_SYMBOL(nss_register_ipv6_mgr);
EXPORT_SYMBOL(nss_unregister_ipv6_mgr);
EXPORT_SYMBOL(nss_tx_create_ipv6_rule);
EXPORT_SYMBOL(nss_tx_create_ipv6_rule1);
EXPORT_SYMBOL(nss_tx_destroy_ipv6_rule);

EXPORT_SYMBOL(nss_register_crypto_if);
EXPORT_SYMBOL(nss_register_crypto_sync_if);
EXPORT_SYMBOL(nss_unregister_crypto_if);
EXPORT_SYMBOL(nss_tx_crypto_if_buf);
EXPORT_SYMBOL(nss_tx_crypto_if_open);

EXPORT_SYMBOL(nss_register_phys_if);
EXPORT_SYMBOL(nss_unregister_phys_if);
EXPORT_SYMBOL(nss_tx_phys_if_buf);
EXPORT_SYMBOL(nss_tx_phys_if_open);
EXPORT_SYMBOL(nss_tx_phys_if_close);
EXPORT_SYMBOL(nss_tx_phys_if_link_state);
EXPORT_SYMBOL(nss_tx_phys_if_change_mtu);
EXPORT_SYMBOL(nss_tx_phys_if_mac_addr);
EXPORT_SYMBOL(nss_tx_phys_if_get_napi_ctx);

EXPORT_SYMBOL(nss_create_virt_if);
EXPORT_SYMBOL(nss_destroy_virt_if);
EXPORT_SYMBOL(nss_tx_virt_if_rxbuf);
EXPORT_SYMBOL(nss_tx_virt_if_rx_nwifibuf);

EXPORT_SYMBOL(nss_register_ipsec_if);
EXPORT_SYMBOL(nss_register_ipsec_event_if);
EXPORT_SYMBOL(nss_unregister_ipsec_if);
EXPORT_SYMBOL(nss_tx_ipsec_rule);

EXPORT_SYMBOL(nss_register_tun6rd_if);
EXPORT_SYMBOL(nss_unregister_tun6rd_if);

EXPORT_SYMBOL(nss_register_tunipip6_if);
EXPORT_SYMBOL(nss_unregister_tunipip6_if);

EXPORT_SYMBOL(nss_register_profiler_if);
EXPORT_SYMBOL(nss_unregister_profiler_if);
EXPORT_SYMBOL(nss_tx_profiler_if_buf);

EXPORT_SYMBOL(nss_get_ipv4_mgr_ctx);

EXPORT_SYMBOL(nss_tx_generic_if_buf);
