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
#ifndef __NSS_CRYPTO_IF_H
#define __NSS_CRYPTO_IF_H

/*
 * @file API interface definitions for crypto driver
 */

#define NSS_CRYPTO_BITS2BYTES(x)	(x / 8)	/**< Bits to Bytes */
#define NSS_CRYPTO_BYTES2BITS(x)	(x * 8)	/**< Bytes to bits */
#define NSS_CRYPTO_MAX_QDEPTH		256	/**< H/W queue depth per pipe */
#define NSS_CRYPTO_MAX_IDXS		16	/**< Max supported sessions */
#define NSS_CRYPTO_MAX_CACHED_IDXS	4	/**< Max supported sessions */
#define NSS_CRYPTO_ENGINES		4	/**< Max engines available */
#define NSS_CRYPTO_BAM_PP		4 	/**< BAM Pipe Pairs */

/**
 * @brief Crypto status for all nss_crypto_XXX api's
 */
typedef enum nss_crypto_status {
	NSS_CRYPTO_STATUS_OK,		/**< OK */
	NSS_CRYPTO_STATUS_FAIL,		/**< general failure status */
	NSS_CRYPTO_STATUS_EINVAL,	/**< invalid parameters */
	NSS_CRYPTO_STATUS_EBUSY,	/**< resource unavailable */
	NSS_CRYPTO_STATUS_ERESTART,	/**< resource unavailable, defer the operation */
	NSS_CRYPTO_STATUS_ENOMEM,	/**< out of memory */
	NSS_CRYPTO_STATUS_ENOSUPP,	/**< unsupported configuration */
} nss_crypto_status_t;

/**
 * @brief max key lengths for supported algorithms
 */
enum nss_crypto_max_keylen {
	NSS_CRYPTO_MAX_KEYLEN_AES = 32,		/**< max key size for AES (bytes) */
	NSS_CRYPTO_MAX_KEYLEN_SHA1 = 20,	/**< max key size for SHA1 (bytes) */
	NSS_CRYPTO_MAX_KEYLEN_SHA256 = 32,	/**< max key size for SHA256 (bytes) */
	NSS_CRYPTO_MAX_KEYLEN_DES = 24,		/**< max key size for DES */
};

/**
 * @brief max IV lengths for algorithms supported by the H/W
 */
enum nss_crypto_max_ivlen {
	NSS_CRYPTO_MAX_IVLEN_DES = 8,		/**< max IV size for DES (bytes) */
	NSS_CRYPTO_MAX_IVLEN_AES = 16,		/**< max IV size for AES (bytes) */
};

/**
 * @brief max hash generated for a HMAC algorithm.
 */
enum nss_crypto_max_hashlen {
	NSS_CRYPTO_MAX_HASHLEN_SHA1 = 20,	/**< max hash size for SHA1 (bytes) */
	NSS_CRYPTO_MAX_HASHLEN_SHA256 = 32,	/**< max hash size for SHA256 (bytes) */
};

/**
 * @brief hash sizes supported by H/W.
 */
enum nss_crypto_hash {
	NSS_CRYPTO_HASH_SHA96 = 12,		/**< 96-bit hash size */
	NSS_CRYPTO_HASH_SHA128 = 16,		/**< 128-bit hash size */
	NSS_CRYPTO_HASH_SHA160 = 20,		/**< 160-bit hash size */
	NSS_CRYPTO_HASH_SHA256 = 32		/**< 256-bit hash size */
};

/**
 * @brief supported cipher algorithms
 */
enum nss_crypto_cipher {
	NSS_CRYPTO_CIPHER_NONE = 0,		/**< Cipher not required*/
	NSS_CRYPTO_CIPHER_AES,			/**< AES, CBC for 128-bit & 256-bit key sizes*/
	NSS_CRYPTO_CIPHER_DES,			/**< DES, CBC for 64-bit key size */
	NSS_CRYPTO_CIPHER_MAX
};

/**
 * @brief supported authentication algorithms
 */
enum nss_crypto_auth {
	NSS_CRYPTO_AUTH_NONE = 0,		/**< Authentication not required*/
	NSS_CRYPTO_AUTH_SHA1_HMAC,		/**< SHA1_HMAC,160-bit key*/
	NSS_CRYPTO_AUTH_SHA256_HMAC,		/**< SHA256_HMAC,256-bit key*/
	NSS_CRYPTO_AUTH_MAX
};

/**
 * @brief crypto buffer request type
 */
enum nss_crypto_buf_req_type {
	NSS_CRYPTO_BUF_REQ_DECRYPT = 0x0001,		/**< decryption request*/
	NSS_CRYPTO_BUF_REQ_ENCRYPT = 0x0002,		/**< encryption request*/
	NSS_CRYPTO_BUF_REQ_AUTH = 0x0004,		/**< authentication request */
	NSS_CRYPTO_BUF_REQ_HOST = 0x0100,		/**< request originated from host */
	NSS_CRYPTO_BUF_REQ_IPSEC = 0x0200		/**< request originates from IPsec fast path */
};

/**
 * @brief crypto config msg type
 */
enum nss_crypto_config_type {
	NSS_CRYPTO_CONFIG_TYPE_NONE = 0,		/**< No config */
	NSS_CRYPTO_CONFIG_TYPE_OPEN_ENG,		/**< open engine config */
	NSS_CRYPTO_CONFIG_TYPE_CLOSE_ENG,		/**< close engine config */
	NSS_CRYPTO_CONFIG_TYPE_RESET_SESSION,		/**< reset session state config */
	NSS_CRYPTO_CONFIG_TYPE_MAX
};

enum nss_crypto_sync_type {
	NSS_CRYPTO_SYNC_TYPE_NONE = 0,			/**< sync type none */
	NSS_CRYPTO_SYNC_TYPE_OPEN_ENG = 1,		/**< open engine sync */
	NSS_CRYPTO_SYNC_TYPE_CLOSE_ENG = 2,		/**< close engine sync */
	NSS_CRYPTO_SYNC_TYPE_STATS = 3,			/**< stats sync */
	NSS_CRYPTO_SYNC_TYPE_MAX
};

struct nss_crypto_buf;
/**
 * @brief Cipher/Auth operation completion callback function type
 */
typedef void (*nss_crypto_comp_t)(struct nss_crypto_buf *buf);

/**
 * @brief describe a cipher key
 */
struct nss_crypto_key {
	uint32_t algo;			/**< algorithm for Cipher or Auth*/
	uint32_t key_len;		/**< key length */
	uint8_t *key;			/**< location of the key stored in memory */
};

/**
 * @brief crypto session index type
 */
struct nss_crypto_idx {
	uint16_t pp_num; 		/**< pipe pair index number */
	uint16_t cmd0_len;		/**< cmd0 block length, as this varies per session */
	uint32_t cblk_paddr;		/**< cmd block phy_addr */
};

/**
 * @brief open engine message sent to NSS when each is probed
 */
struct nss_crypto_config_eng {
	uint32_t eng_id;				/**< engine number to open */
	uint32_t bam_pbase;				/**< BAM base addr (physical) */
	uint32_t crypto_pbase;				/**< Crypto base addr (physical) */
	uint32_t desc_paddr[NSS_CRYPTO_BAM_PP];		/**< pipe desc addr (physical) */
	struct nss_crypto_idx idx[NSS_CRYPTO_MAX_IDXS];	/**< allocated ession indexes */
};

/**
 * @brief Reset session related state in NSS
 */
struct nss_crypto_config_session {
	uint32_t idx;					/*< session idx on which will be reset */
};

/**
 * @brief Config message sent to NSS
 */
struct nss_crypto_config {
	uint32_t type;					/*< Config type */

	union {
		struct nss_crypto_config_eng eng;		/*< open engine msg structure */
		struct nss_crypto_config_session session;	/*< reset stats msg structure */
	} msg;
};

/**
 * @brief crypto statistics
 */
struct nss_crypto_stats {
	uint32_t queued;	/**< no. of queued frames */
	uint32_t completed;	/**< no. of completed frames */
	uint32_t dropped;	/**< no. of dropped frames */
};

/**
 * @brief statistic sync structure
 */
struct nss_crypto_sync_stats {
	struct nss_crypto_stats eng[NSS_CRYPTO_ENGINES];	/**< engine stats */
	struct nss_crypto_stats idx[NSS_CRYPTO_MAX_IDXS];	/**< session stats */
	struct nss_crypto_stats total;				/**< Total stats */
};

/**
 * @brief engine sync structure
 */
struct nss_crypto_sync_eng {
	uint32_t eng_id;			/**< Engine number */
};

/**
 * @brief crypto sync message
 */
struct nss_crypto_sync {
	uint32_t type;				/**< sync message type */

	union {
		struct nss_crypto_sync_eng eng;	/**< engine configuration sync */
		struct nss_crypto_sync_stats stats;	/**< statistics sync */
	} msg;
};

/**
 * @brief crypto request buffer for doing operation with the crypto driver
 *
 *        Buffer elements and its use within data
 *
 *        <-- skip ---><-- cipher len --><-- hash len ->
 *        +------+----+-----------------+--------------+----------------------+
 *        |      | IV |     CIPHER      |     HASH     | extra space for H/W  |
 *        +------+----+-----------------+--------------+----------------------+
 *        <-------- hash offset ------->
 *        <----------------- data len ----------------->
 *      				<------- 128 bytes of tailroom ------->
 */
struct nss_crypto_buf {
	/* private fields*/
	struct nss_crypto_buf *next;	/**< next buffer */
	uint32_t ctx_0;			/**< private context(0) per buf */
	uint32_t ctx_1;			/**< private context(1) per buf */
	uint32_t state;			/**< buffer operation specific state */

	/* public fields*/
	uint32_t cb_ctx;		/**< completion callback context */
	nss_crypto_comp_t cb_fn;	/**< completion callback function */

	uint32_t session_idx;		/**< session index */

	uint8_t *data;			/**< Data address (virtual) */
	uint32_t data_paddr;		/**< Data address (physical) */

	uint16_t hash_offset;		/**< location inside data where HASH is generated */
	uint16_t iv_offset;		/**< location inside data where IV is available */

	uint16_t data_len;		/**< Data length */
	uint16_t hash_len;		/**< hash length */
	uint16_t iv_len;		/**< IV length */


	uint16_t cipher_len;		/**< Length of data to encrypt */
	uint16_t cipher_skip;		/**< start encrypt/decrypt from here */

	uint16_t auth_len;		/**< bytes to authenticate inside data */
	uint16_t auth_skip;		/**< skip bytes from data to start authenticating */

	uint16_t req_type;		/**< nss_crypto_req_type */

	uint16_t magic;			/**< crypto magic number for validation checks */

	uint8_t pad[6];			/**< 32-byte cacheline alignment */
};

/**
 * @brief Set crypto buffer request type.
 *
 * @param buf[IN] crypto buffer
 * @param req_type[IN] request type
 */
static inline void nss_crypto_buf_set_req_type(struct nss_crypto_buf *buf, uint16_t req_type)
{
	buf->req_type = req_type;
}

/**
 * @brief Get crypto buffer request type.
 *
 * @param buf[IN] crypto buffer
 *
 * @return req_type
 */
static inline uint16_t nss_crypto_buf_get_req_type(struct nss_crypto_buf *buf)
{
	return buf->req_type;
}

/**
 * @brief Find out crypto buffer request type is set or not.
 *
 * @param buf[IN] crypto buffer
 * @param req_type[IN] request type
 *
 * @return 1 or 0 depending on whether req type is set or not.
 */
static inline bool nss_crypto_buf_check_req_type(struct nss_crypto_buf *buf, uint16_t req_type)
{
	return ((buf->req_type & req_type) == req_type);
}

typedef void *nss_crypto_user_ctx_t;	/**< crypto driver user's context */
typedef void *nss_crypto_handle_t;	/**< crypto driver handle for its users */

/**
 * @brief handler called when the crypto device is ready, this is
 * 	  provide the user the crypto handle for future transactions
 */
typedef nss_crypto_user_ctx_t (*nss_crypto_attach_t)(nss_crypto_handle_t crypto);

/**
 * @brief handler called when the crypto device has stopped
 */
typedef void (*nss_crypto_detach_t)(nss_crypto_user_ctx_t ctx);


/**
 * @brief register user attach/detach routines to the crypto driver
 *
 * @param attach[IN] called when device is ready
 * @param detach[IN] called when device has stopped or user has unregistered
 */
void nss_crypto_register_user(nss_crypto_attach_t attach, nss_crypto_detach_t detach);

/**
 * @brief unregister user from the list of crypto device users
 *
 * @param crypto[IN] handle of the crypto device
 *
 * @note detach will be called before this returns
 */
void nss_crypto_unregister_user(nss_crypto_handle_t crypto);

/**
 * @brief get a crypto operation buffer from the pool
 *
 * @param crypto[IN] crypto device handle
 *
 * @return NULL means out of memory
 *
 */
struct nss_crypto_buf *nss_crypto_buf_alloc(nss_crypto_handle_t crypto);

/**
 * @brief return the crypto operation buffer to the pool
 *
 * @param buf[IN] buffer
 */
void nss_crypto_buf_free(nss_crypto_handle_t crypto, struct nss_crypto_buf *buf);

/**
 * @brief Allocate a new session index, this should create the necessary state
 *        across all the layers
 *
 * @param crypto[IN] crypto device handle
 * @param cipher[IN] cipher specific elements {cipher_algo, key & key_length}
 * @param auth[IN] auth specific elememts {auth_algo, key & key_length}
 * @param session_idx[OUT] session index for the crypto transform
 *
 * @return status of the call
 *
 * ENOMEM implies out of index
 * ENOSUPP implies unsupported configuration
 *
 */
nss_crypto_status_t nss_crypto_session_alloc(nss_crypto_handle_t crypto, struct nss_crypto_key *cipher, struct nss_crypto_key *auth,
						uint32_t *session_idx);

/**
 * @brief Free an existing session, this flushes all state related to the session
 *        including keys, algorithms
 *
 * @param crypto[IN] crypto device handle
 * @param session_idx[IN] session index to free
 *
 * @return status of the call
 *
 * @note When changing/altering the configuration of a session such as new keys,
 *       algorithm etc. the procedure should be to free the older session and
 *       then allocate a newer session with the new parameters
 */
nss_crypto_status_t nss_crypto_session_free(nss_crypto_handle_t crypto, uint32_t session_idx);

/**
 * @brief Apply cipher (as in encrypt or decrypt) and or authenticate the given
 *        buf
 *
 * @param crypto[IN] crypto device handle
 * @param buf[IN] buffer for crypto operation
 *
 * @return status of the call
 * @note completion callback will happen after the crypto operation on the
 *       buffer has completed
 */
nss_crypto_status_t nss_crypto_transform_payload(nss_crypto_handle_t crypto, struct nss_crypto_buf *buf);

#endif /* __NSS_CRYPTO_IF_H */
