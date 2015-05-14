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
 * nss_stats.c
 *	NSS stats APIs
 *
 */

#include "nss_core.h"

/*
 * Maximum string length:
 * This should be equal to maximum string size of any stats
 * inclusive of stats value
 */
#define NSS_STATS_MAX_STR_LENGTH 96

/*
 * Global variables/extern declarations
 */
extern struct nss_top_instance nss_top_main;

/*
 * Statistics structures
 */

/*
 * nss_stats_str_ipv4
 *	IPv4 stats strings
 */
static int8_t *nss_stats_str_ipv4[NSS_STATS_IPV4_MAX] = {
	"rx_pkts",
	"rx_bytes",
	"tx_pkts",
	"tx_bytes",
	"create_requests",
	"create_collisions",
	"create_invalid_interface",
	"destroy_requests",
	"destroy_misses",
	"hash_hits",
	"hash_reorders",
	"flushes",
	"evictions"
};

/*
 * nss_stats_str_ipv6
 *	IPv6 stats strings
 */
static int8_t *nss_stats_str_ipv6[NSS_STATS_IPV6_MAX] = {
	"rx_pkts",
	"rx_bytes",
	"tx_pkts",
	"tx_bytes",
	"create_requests",
	"create_collisions",
	"create_invalid_interface",
	"destroy_requests",
	"destroy_misses",
	"hash_hits",
	"hash_reorders",
	"flushes",
	"evictions",
};

/*
 * nss_stats_str_pbuf
 *	Pbuf stats strings
 */
static int8_t *nss_stats_str_pbuf[NSS_STATS_PBUF_MAX] = {
	"pbuf_fails",
	"payload_fails"
};

/*
 * nss_stats_str_n2h
 *	N2H stats strings
 */
static int8_t *nss_stats_str_n2h[NSS_STATS_N2H_MAX] = {
	"queue_dropped",
	"ticks",
	"worst_ticks",
	"iterations"
};

/*
 * nss_stats_str_drv
 *	Host driver stats strings
 */
static int8_t *nss_stats_str_drv[NSS_STATS_DRV_MAX] = {
	"nbuf_alloc_errors",
	"tx_queue_full[0]",
	"tx_queue_full[1]",
	"tx_buffers_empty",
	"tx_buffers_pkt",
	"tx_buffers_cmd",
	"tx_buffers_crypto",
	"rx_buffers_empty",
	"rx_buffers_pkt",
	"rx_buffers_cmd_resp",
	"rx_buffers_status_sync",
	"rx_buffers_crypto",
	"rx_buffers_virtual"
};

/*
 * nss_stats_str_pppoe
 *	PPPoE stats strings
 */
static int8_t *nss_stats_str_pppoe[NSS_STATS_PPPOE_MAX] = {
	"create_requests",
	"create_failures",
	"destroy_requests",
	"destroy_misses"
};

/*
 * nss_stats_str_gmac
 *	GMAC stats strings
 */
static int8_t *nss_stats_str_gmac[NSS_STATS_GMAC_MAX] = {
	"ticks",
	"worst_ticks",
	"iterations"
};

/*
 * nss_stats_str_if_host
 *	Interface stats strings for host
 */
static int8_t *nss_stats_str_if_host[NSS_STATS_IF_HOST_MAX] = {
	"rx_packets",
	"rx_bytes",
	"tx_packets",
	"tx_bytes",

};

/*
 * nss_stats_str_if_ipv4
 *	Interface stats strings for ipv4
 */
static int8_t *nss_stats_str_if_ipv4[NSS_STATS_IF_IPV4_MAX] = {
	"rx_packets",
	"rx_bytes",
	"tx_packets",
	"tx_bytes"
};

/*
 * nss_stats_str_if_ipv6
 *	Interface stats strings for ipv6
 */
static int8_t *nss_stats_str_if_ipv6[NSS_STATS_IF_IPV6_MAX] = {
	"rx_packets",
	"rx_bytes",
	"tx_packets",
	"tx_bytes"
};

/*
 * nss_stats_str_if_exception_unknown
 *	Interface stats strings for unknown exceptions
 */
static int8_t *nss_stats_str_if_exception_unknown[NSS_EXCEPTION_EVENT_UNKNOWN_MAX] = {
	"UNKNOWN_L2_PROTOCOL"
};

/*
 * nss_stats_str_if_exception_ipv4
 *	Interface stats strings for ipv4 exceptions
 */
static int8_t *nss_stats_str_if_exception_ipv4[NSS_EXCEPTION_EVENT_IPV4_MAX] = {
	"IPV4_ICMP_HEADER_INCOMPLETE",
	"IPV4_ICMP_UNHANDLED_TYPE",
	"IPV4_ICMP_IPV4_HEADER_INCOMPLETE",
	"IPV4_ICMP_IPV4_UDP_HEADER_INCOMPLETE",
	"IPV4_ICMP_IPV4_TCP_HEADER_INCOMPLETE",
	"IPV4_ICMP_IPV4_UNKNOWN_PROTOCOL",
	"IPV4_ICMP_NO_ICME",
	"IPV4_ICMP_FLUSH_TO_HOST",
	"IPV4_TCP_HEADER_INCOMPLETE",
	"IPV4_TCP_NO_ICME",
	"IPV4_TCP_IP_OPTION",
	"IPV4_TCP_IP_FRAGMENT",
	"IPV4_TCP_SMALL_TTL",
	"IPV4_TCP_NEEDS_FRAGMENTATION",
	"IPV4_TCP_FLAGS",
	"IPV4_TCP_SEQ_EXCEEDS_RIGHT_EDGE",
	"IPV4_TCP_SMALL_DATA_OFFS",
	"IPV4_TCP_BAD_SACK",
	"IPV4_TCP_BIG_DATA_OFFS",
	"IPV4_TCP_SEQ_BEFORE_LEFT_EDGE",
	"IPV4_TCP_ACK_EXCEEDS_RIGHT_EDGE",
	"IPV4_TCP_ACK_BEFORE_LEFT_EDGE",
	"IPV4_UDP_HEADER_INCOMPLETE",
	"IPV4_UDP_NO_ICME",
	"IPV4_UDP_IP_OPTION",
	"IPV4_UDP_IP_FRAGMENT",
	"IPV4_UDP_SMALL_TTL",
	"IPV4_UDP_NEEDS_FRAGMENTATION",
	"IPV4_WRONG_TARGET_MAC",
	"IPV4_HEADER_INCOMPLETE",
	"IPV4_BAD_TOTAL_LENGTH",
	"IPV4_BAD_CHECKSUM",
	"IPV4_NON_INITIAL_FRAGMENT",
	"IPV4_DATAGRAM_INCOMPLETE",
	"IPV4_OPTIONS_INCOMPLETE",
	"IPV4_UNKNOWN_PROTOCOL",
	"IPV4_ESP_HEADER_INCOMPLETE",
	"IPV4_ESP_NO_ICME",
	"IPV4_ESP_IP_OPTION",
	"IPV4_ESP_IP_FRAGMENT",
	"IPV4_ESP_SMALL_TTL",
	"IPV4_ESP_NEEDS_FRAGMENTATION",
	"IPV4_INGRESS_VID_MISMATCH",
	"IPV4_6RD_NO_ICME",
	"IPV4_6RD_IP_OPTION",
	"IPV4_6RD_IP_FRAGMENT",
	"IPV4_6RD_NEEDS_FRAGMENTATION"
};

/*
 * nss_stats_str_if_exception_ipv6
 *	Interface stats strings for ipv6 exceptions
 */
static int8_t *nss_stats_str_if_exception_ipv6[NSS_EXCEPTION_EVENT_IPV6_MAX] = {
	"IPV6_ICMP_HEADER_INCOMPLETE",
	"IPV6_ICMP_UNHANDLED_TYPE",
	"IPV6_ICMP_IPV6_HEADER_INCOMPLETE",
	"IPV6_ICMP_IPV6_UDP_HEADER_INCOMPLETE",
	"IPV6_ICMP_IPV6_TCP_HEADER_INCOMPLETE",
	"IPV6_ICMP_IPV6_UNKNOWN_PROTOCOL",
	"IPV6_ICMP_NO_ICME",
	"IPV6_ICMP_FLUSH_TO_HOST",
	"IPV6_TCP_HEADER_INCOMPLETE",
	"IPV6_TCP_NO_ICME",
	"IPV6_TCP_SMALL_HOP_LIMIT",
	"IPV6_TCP_NEEDS_FRAGMENTATION",
	"IPV6_TCP_FLAGS",
	"IPV6_TCP_SEQ_EXCEEDS_RIGHT_EDGE",
	"IPV6_TCP_SMALL_DATA_OFFS",
	"IPV6_TCP_BAD_SACK",
	"IPV6_TCP_BIG_DATA_OFFS",
	"IPV6_TCP_SEQ_BEFORE_LEFT_EDGE",
	"IPV6_TCP_ACK_EXCEEDS_RIGHT_EDGE",
	"IPV6_TCP_ACK_BEFORE_LEFT_EDGE",
	"IPV6_UDP_HEADER_INCOMPLETE",
	"IPV6_UDP_NO_ICME",
	"IPV6_UDP_SMALL_HOP_LIMIT",
	"IPV6_UDP_NEEDS_FRAGMENTATION",
	"IPV6_WRONG_TARGET_MAC",
	"IPV6_HEADER_INCOMPLETE",
	"IPV6_UNKNOWN_PROTOCOL",
	"IPV6_INGRESS_VID_MISMATCH"
};

/*
 * nss_stats_str_if_exception_pppoe
 *	Interface stats strings for PPPoE exceptions
 */
static int8_t *nss_stats_str_if_exception_pppoe[NSS_EXCEPTION_EVENT_PPPOE_MAX] = {
	"PPPOE_WRONG_VERSION_OR_TYPE",
	"PPPOE_WRONG_CODE",
	"PPPOE_HEADER_INCOMPLETE",
	"PPPOE_UNSUPPORTED_PPP_PROTOCOL"
};

/*
 * nss_stats_ipv4_read()
 *	Read IPV4 stats
 */
static ssize_t nss_stats_ipv4_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_IPV4_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_IPV4_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al,"ipv4 stats start:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_IPV4_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_ipv4[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_IPV4_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_ipv4[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,"\nipv4 stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_ipv6_read()
 *	Read IPv6 stats
 */
static ssize_t nss_stats_ipv6_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_IPV6_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_IPV6_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al,"ipv6 stats start:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_IPV6_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_ipv6[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_IPV6_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_ipv6[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nipv6 stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_pbuf_read()
 *	Read pbuf manager stats
 */
static ssize_t nss_stats_pbuf_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_PBUF_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_PBUF_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "pbuf_mgr stats start:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_PBUF_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_pbuf[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_PBUF_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_pbuf[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\npbuf_mgr stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_n2h_read()
 *	Read N2H stats
 */
static ssize_t nss_stats_n2h_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_N2H_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_N2H_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "n2h stats start:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_N2H_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_n2h[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_N2H_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_n2h[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nn2h stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_drv_read()
 *	Read HLOS driver stats
 */
static ssize_t nss_stats_drv_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_DRV_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_DRV_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "drv stats start:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_DRV_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_drv[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_DRV_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_drv[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ndrv stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_pppoe_read()
 *	Read PPPoE stats
 */
static ssize_t nss_stats_pppoe_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	int32_t i;

	/*
	 * max output lines = #stats + start tag line + end tag line + three blank lines
	 */
	uint32_t max_output_lines = NSS_STATS_PPPOE_MAX + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_PPPOE_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "pppoe stats start:\n\n");
	spin_lock_bh(&nss_top_main.stats_lock);
	for (i = 0; (i < NSS_STATS_PPPOE_MAX); i++) {
		stats_shadow[i] = nss_top_main.stats_pppoe[i];
	}

	spin_unlock_bh(&nss_top_main.stats_lock);

	for (i = 0; (i < NSS_STATS_PPPOE_MAX); i++) {
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_pppoe[i], stats_shadow[i]);
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\npppoe stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_gmac_read()
 *	Read GMAC stats
 */
static ssize_t nss_stats_gmac_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i, id;

	/*
	 * max output lines = ((#stats + start tag + one blank) * #GMACs) + start/end tag + 3 blank
	 */
	uint32_t max_output_lines = ((NSS_STATS_GMAC_MAX + 2) * NSS_MAX_PHYSICAL_INTERFACES) + 5;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * max_output_lines;
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	stats_shadow = kzalloc(NSS_STATS_GMAC_MAX * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "gmac stats start:\n\n");

	for (id = 0; id < NSS_MAX_PHYSICAL_INTERFACES; id++) {
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_STATS_GMAC_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_gmac[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "GMAC ID: %d\n", id);
		for (i = 0; (i < NSS_STATS_GMAC_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_gmac[i], stats_shadow[i]);
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,"\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\ngmac stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}

/*
 * nss_stats_if_read()
 *	Read interface stats
 */
static ssize_t nss_stats_if_read(struct file *fp, char __user *ubuf, size_t sz, loff_t *ppos)
{
	uint32_t i, k, id;
	void *ifctx;

	/*
	 * max output lines per interface =
	 * (#ipv4 stats + start tag + blank line) +
	 * (#ipv6 stats + start tag + blank line) +
	 * (#host stats + start tag + blank line) +
	 * (#unknown exception stats + start tag + blank line) +
	 * (#ipv4 exception + start tag + blank line) +
	 * (#ipv6 exception + start tag + blank line) +
	 * (#pppoe exception + start tag + blank line) + interface start tag
	 *
	 * max output lines =
	 * (max output lines per interface * #interfaces) +
	 * (start tag + end tag + 3 blank lines)
	 */
	uint32_t max_output_lines_interface = ((NSS_STATS_IF_IPV4_MAX + 2) + (NSS_STATS_IF_IPV6_MAX + 2) +
					(NSS_STATS_IF_HOST_MAX + 2) + (NSS_EXCEPTION_EVENT_UNKNOWN_MAX + 2) +
					(NSS_EXCEPTION_EVENT_IPV4_MAX + 2) + (NSS_EXCEPTION_EVENT_IPV6_MAX + 2) +
					(NSS_EXCEPTION_EVENT_PPPOE_MAX + 2)) + 1;
	size_t size_al = NSS_STATS_MAX_STR_LENGTH * ((max_output_lines_interface * NSS_MAX_NET_INTERFACES) + 5);
	size_t size_wr = 0;
	ssize_t bytes_read = 0;
	uint64_t *stats_shadow;
	uint64_t pppoe_stats_shadow[NSS_PPPOE_NUM_SESSION_PER_INTERFACE][NSS_EXCEPTION_EVENT_PPPOE_MAX];

	char *lbuf = kzalloc(size_al, GFP_KERNEL);
	if (unlikely(lbuf == NULL)) {
		nss_warning("Could not allocate memory for local statistics buffer");
		return 0;
	}

	/*
	 * WARNING: We are only allocating memory for 64 stats counters per stats type
	 *		Developers must ensure that number of counters are not more than 64
	 */

	if ( (NSS_STATS_IF_IPV4_MAX > 64) ||
			(NSS_STATS_IF_IPV6_MAX > 64) ||
			(NSS_STATS_IF_HOST_MAX > 64) ||
			(NSS_EXCEPTION_EVENT_UNKNOWN_MAX > 64) ||
			(NSS_EXCEPTION_EVENT_IPV4_MAX > 64) ||
			(NSS_EXCEPTION_EVENT_IPV6_MAX > 64) ||
			(NSS_EXCEPTION_EVENT_PPPOE_MAX > 64)) {
		nss_warning("Size of shadow stats structure is not enough to copy all stats");
	}

	stats_shadow = kzalloc(64 * 8, GFP_KERNEL);
	if (unlikely(stats_shadow == NULL)) {
		nss_warning("Could not allocate memory for local shadow buffer");
		kfree(lbuf);
		return 0;
	}

	size_wr = scnprintf(lbuf, size_al, "if stats start:\n\n");

	for (id = NSS_DEVICE_IF_START; id < NSS_MAX_DEVICE_INTERFACES; id++) {

		spin_lock_bh(&nss_top_main.lock);
		ifctx = nss_top_main.if_ctx[id];
		spin_unlock_bh(&nss_top_main.lock);

		if (!ifctx) {
			continue;
		}

		/*
		 * Host Stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_STATS_IF_HOST_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_if_host[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Interface ID: %d\n", id);
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Host:\n");
		for (i = 0; (i < NSS_STATS_IF_HOST_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_if_host[i], stats_shadow[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * IPv4 stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_STATS_IF_IPV4_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_if_ipv4[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "IPv4:\n");
		for (i = 0; (i < NSS_STATS_IF_IPV4_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_if_ipv4[i], stats_shadow[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * IPv6 stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_STATS_IF_IPV6_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_if_ipv6[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "IPv6:\n");
		for (i = 0; (i < NSS_STATS_IF_IPV6_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n", nss_stats_str_if_ipv6[i], stats_shadow[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * Unknown exception stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_EXCEPTION_EVENT_UNKNOWN_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_if_exception_unknown[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Exception Unknown:\n");
		for (i = 0; (i < NSS_EXCEPTION_EVENT_UNKNOWN_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n",
					nss_stats_str_if_exception_unknown[i],
					stats_shadow[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * IPv4 exception stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV4_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_if_exception_ipv4[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Exception IPv4:\n");
		for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV4_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n",
					nss_stats_str_if_exception_ipv4[i],
					stats_shadow[i]);
		}

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");

		/*
		 * IPv6 exception stats
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV6_MAX); i++) {
			stats_shadow[i] = nss_top_main.stats_if_exception_ipv6[id][i];
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Exception IPv6:\n");
		for (i = 0; (i < NSS_EXCEPTION_EVENT_IPV6_MAX); i++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
					"%s = %llu\n",
					nss_stats_str_if_exception_ipv6[i],
					stats_shadow[i]);
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");


		/*
		 * Exception PPPoE
		 */
		spin_lock_bh(&nss_top_main.stats_lock);
		for (k = 0; k < NSS_PPPOE_NUM_SESSION_PER_INTERFACE; k++) {
			for (i = 0; (i < NSS_EXCEPTION_EVENT_PPPOE_MAX); i++) {
				pppoe_stats_shadow[k][i] = nss_top_main.stats_if_exception_pppoe[id][k][i];
			}
		}

		spin_unlock_bh(&nss_top_main.stats_lock);

		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "Exception PPPoE:\n");
		for (k = 0; k < NSS_PPPOE_NUM_SESSION_PER_INTERFACE; k++) {
			size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "%d. Session\n", k);
			for (i = 0; (i < NSS_EXCEPTION_EVENT_PPPOE_MAX); i++) {
				size_wr += scnprintf(lbuf + size_wr, size_al - size_wr,
						"%s = %llu\n",
						nss_stats_str_if_exception_pppoe[i],
						pppoe_stats_shadow[k][i]);
			}
		}
		size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\n");
	}

	size_wr += scnprintf(lbuf + size_wr, size_al - size_wr, "\nif stats end\n\n");
	bytes_read = simple_read_from_buffer(ubuf, sz, ppos, lbuf, strlen(lbuf));
	kfree(lbuf);
	kfree(stats_shadow);

	return bytes_read;
}


#define NSS_STATS_DECLARE_FILE_OPERATIONS(name) \
static const struct file_operations nss_stats_##name##_ops = { \
	.open = simple_open, \
	.read = nss_stats_##name##_read, \
	.llseek = generic_file_llseek, \
};

/*
 * nss_ipv4_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ipv4)

/*
 * ipv6_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(ipv6)

/*
 * pbuf_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(pbuf)

/*
 * n2h_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(n2h)
/*
 * drv_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(drv)

/*
 * pppoe_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(pppoe)

/*
 * gmac_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(gmac)

/*
 * if_stats_ops
 */
NSS_STATS_DECLARE_FILE_OPERATIONS(if)

/*
 * nss_stats_init()
 * 	Enable NSS statistics
 */
void nss_stats_init(void)
{
	/*
	 * NSS driver entry
	 */
	nss_top_main.top_dentry = debugfs_create_dir("qca-nss-drv", NULL);
	if (unlikely(nss_top_main.top_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv directory in debugfs");

		/*
		 * Non availability of debugfs directory is not a catastrophy
		 * We can still go ahead with other initialization
		 */
		return;
	}

	nss_top_main.stats_dentry = debugfs_create_dir("stats", nss_top_main.top_dentry);
	if (unlikely(nss_top_main.stats_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv directory in debugfs");

		/*
		 * Non availability of debugfs directory is not a catastrophy
		 * We can still go ahead with rest of initialization
		 */
		return;
	}

	/*
	 * Create files to obtain statistics
	 */

	/*
	 * ipv4_stats
	 */
	nss_top_main.ipv4_dentry = debugfs_create_file("ipv4", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_ipv4_ops);
	if (unlikely(nss_top_main.ipv4_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ipv4 file in debugfs");
		return;
	}

	/*
	 * ipv6_stats
	 */
	nss_top_main.ipv6_dentry = debugfs_create_file("ipv6", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_ipv6_ops);
	if (unlikely(nss_top_main.ipv6_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/ipv6 file in debugfs");
		return;
	}

	/*
	 * pbuf_stats
	 */
	nss_top_main.pbuf_dentry = debugfs_create_file("pbuf_mgr", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_pbuf_ops);
	if (unlikely(nss_top_main.pbuf_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/pbuf file in debugfs");
		return;
	}

	/*
	 * n2h_stats
	 */
	nss_top_main.n2h_dentry = debugfs_create_file("n2h", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_n2h_ops);
	if (unlikely(nss_top_main.n2h_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/n2h directory in debugfs");
		return;
	}

	/*
	 * drv_stats
	 */
	nss_top_main.drv_dentry = debugfs_create_file("drv", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_drv_ops);
	if (unlikely(nss_top_main.drv_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/drv directory in debugfs");
		return;
	}

	/*
	 * pppoe_stats
	 */
	nss_top_main.pppoe_dentry = debugfs_create_file("pppoe", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_pppoe_ops);
	if (unlikely(nss_top_main.pppoe_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/pppoe file in debugfs");
		return;
	}

	/*
	 * gmac_stats
	 */
	nss_top_main.gmac_dentry = debugfs_create_file("gmac", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_gmac_ops);
	if (unlikely(nss_top_main.gmac_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/gmac file in debugfs");
		return;
	}

	/*
	 * interface_stats
	 */
	nss_top_main.if_dentry = debugfs_create_file("interface", 0400,
						nss_top_main.stats_dentry, &nss_top_main, &nss_stats_if_ops);
	if (unlikely(nss_top_main.if_dentry == NULL)) {
		nss_warning("Failed to create qca-nss-drv/stats/interface file in debugfs");
		return;
	}
}


/*
 * nss_stats_clean()
 * 	Cleanup NSS statistics files
 */
void nss_stats_clean(void)
{
	/*
	 * Remove debugfs tree
	 */
	if (likely(nss_top_main.top_dentry != NULL)) {
		debugfs_remove_recursive(nss_top_main.top_dentry);
	}
}
