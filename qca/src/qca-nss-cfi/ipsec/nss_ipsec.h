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
#ifndef __NSS_IPSEC_H
#define __NSS_IPSEC_H

#define NSS_IPSEC_ENCAP_INTERFACE NSS_IPSEC_ENCAP_IF_NUMBER
#define NSS_IPSEC_DECAP_INTERFACE NSS_IPSEC_DECAP_IF_NUMBER

#define NSS_IPSEC_DBG_DUMP_LIMIT 64
#define NSS_IPSEC_MAX_IV_LEN 16
#define NSS_IPSEC_TBL_MAX_SHIFT 8
#define NSS_IPSEC_TBL_MAX_ENTRIES (1 << NSS_IPSEC_TBL_MAX_SHIFT)
#define NSS_IPSEC_IPHDR_SZ sizeof(struct nss_ipsec_ipv4_hdr)
#define NSS_IPSEC_ESPHDR_SZ sizeof(struct nss_ipsec_esp_hdr)

#define NSS_IPSEC_TCP_HDR_FLAG_FIN 0x01
#define NSS_IPSEC_TCP_HDR_FLAG_SYN 0x02
#define NSS_IPSEC_TCP_HDR_FLAG_RST 0x04
#define NSS_IPSEC_TCP_HDR_FLAG_PSH 0x08
#define NSS_IPSEC_TCP_HDR_FLAG_ACK 0x10
#define NSS_IPSEC_TCP_HDR_FLAG_URG 0x20

/**
 * @brief IPsec rule types
 */
enum nss_ipsec_rule_op {
	NSS_IPSEC_RULE_OP_NONE = 0,	/**< nothing to do */
	NSS_IPSEC_RULE_OP_ADD = 1,	/**< add rule to the table */
	NSS_IPSEC_RULE_OP_DEL = 2,	/**< delete rule from the table */
	NSS_IPSEC_RULE_OP_DEL_SID = 3,	/**< flush all rules for a crypto_sid */
	NSS_IPSEC_RULE_OP_DEL_ALL = 4,	/**< remove all rules from table */
	NSS_IPSEC_RULE_OP_MAX
};

/**
 * @brief IPsec tbl types
 */
enum nss_ipsec_tbl_type {
	NSS_IPSEC_TBL_TYPE_NONE = 0,
	NSS_IPSEC_TBL_TYPE_ENCAP = 1,
	NSS_IPSEC_TBL_TYPE_DECAP = 2,
	NSS_IPSEC_TBL_TYPE_MAX
};

/**
 * @brief IPsec trable entry state
 */
enum nss_ipsec_tbl_entry {
	NSS_IPSEC_TBL_ENTRY_DELETED = 0,
	NSS_IPSEC_TBL_ENTRY_PASSIVE = 1,
	NSS_IPSEC_TBL_ENTRY_ACTIVE = 2,
};

/**
 * @brief IPv4 header
 */
struct nss_ipsec_ipv4_hdr {
        uint8_t ver_ihl;	/**< version and header length */
        uint8_t tos;		/**< type of service */
        uint16_t tot_len;	/**< total length of the payload */
        uint16_t id;		/**< packet sequence number */
        uint16_t frag_off;	/**< fragmentation offset */
        uint8_t ttl;		/**< time to live */
        uint8_t protocol;	/**< next header protocol (TCP, UDP, ESP etc.) */
        uint16_t checksum;	/**< IP checksum */
        uint32_t src_ip;	/**< source IP address */
        uint32_t dst_ip;	/**< destination IP address */
};

/**
 * @brief ESP (Encapsulating Security Payload) header
 */
struct nss_ipsec_esp_hdr {
	uint32_t spi;				/**< security Parameter Index */
	uint32_t seq_no;			/**< esp sequence number */
	uint8_t iv[NSS_IPSEC_MAX_IV_LEN];	/**< iv for esp header */
};

/**
 * @brief TCP (Transmission Control Protocol)  header
 */
struct nss_ipsec_tcp_hdr {
	uint16_t src_port;	/**< source port */
	uint16_t dst_port;	/**< destination port */
	uint32_t seq_no;	/**< tcp sequence number */
	uint32_t ack_no;	/**< acknowledgment number */
	uint16_t flags;		/**< tcp flags */
	uint16_t window_size;	/**< tcp window size */
	uint16_t checksum;	/**< tcp checksum */
	uint16_t urgent;	/**< location where urgent data ends */
};

/**
 * @brief UDP header
 */
struct nss_ipsec_udp_hdr {
	uint16_t src_port;	/**< source port */
	uint16_t dst_port;	/**< destination port */
	uint16_t len;		/**< payload length */
	uint16_t checksum;	/**< udp checksum */
};

/**
 * @brief IPsec rule selector
 */
struct nss_ipsec_rule_sel {
	uint32_t dst_ip;
	uint32_t src_ip;
	uint32_t spi;

	uint16_t dst_port;
	uint16_t src_port;

	uint8_t proto;
	uint8_t res[3];
};

/**
 * @brief IPsec rule data
 */
struct nss_ipsec_rule_data {
	struct nss_ipsec_ipv4_hdr ip;
	struct nss_ipsec_esp_hdr esp;
	uint32_t crypto_sid;
};

/**
 * @brief IPsec rule entry
 */
struct nss_ipsec_rule_entry {
	struct nss_ipsec_rule_sel sel;
	struct nss_ipsec_rule_data data;

	uint8_t aging;
	uint8_t res[3];
};

/**
 * @brief IPsec rule push message
 */
struct nss_ipsec_rule_push {
	struct nss_ipsec_rule_sel sel;			/**< rule selector */
	struct nss_ipsec_rule_data data;		/**< rule data */
};

/**
 * @brief IPsec rule sync message
 */
struct nss_ipsec_rule_sync {
	struct nss_ipsec_rule_sel sel;			/**< rule selector */
	struct nss_ipsec_rule_data data;		/**< rule data*/

	union {
		uint32_t num;				/**< table index */
		uint8_t map[NSS_IPSEC_TBL_MAX_ENTRIES];	/**< table index map */
	}index;
};

/**
 * @brief IPsec rule structure
 */
struct nss_ipsec_rule {
	uint32_t op;					/**< rule operation */

	union {
		struct nss_ipsec_rule_push push;	/**< push rule object */
		struct nss_ipsec_rule_sync sync;	/**< sync rule object */
	} type;
};

#endif /* __NSS_IPSEC_IF_H */
