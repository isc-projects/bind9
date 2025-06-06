/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*
 * Rate limit DNS responses.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include <isc/attributes.h>

#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/types.h>

/*
 * Memory allocation or other failures.
 */
#define DNS_RRL_LOG_FAIL ISC_LOG_WARNING
/*
 * dropped or slipped responses.
 */
#define DNS_RRL_LOG_DROP ISC_LOG_INFO
/*
 * Major events in dropping or slipping.
 */
#define DNS_RRL_LOG_DEBUG1 ISC_LOG_DEBUG(3)
/*
 * Limit computations.
 */
#define DNS_RRL_LOG_DEBUG2 ISC_LOG_DEBUG(4)
/*
 * Even less interesting.
 */
#define DNS_RRL_LOG_DEBUG3 ISC_LOG_DEBUG(9)

#define DNS_RRL_LOG_ERR_LEN 64
#define DNS_RRL_LOG_BUF_LEN                                        \
	(sizeof("would continue limiting") + DNS_RRL_LOG_ERR_LEN + \
	 sizeof(" responses to ") + ISC_NETADDR_FORMATSIZE +       \
	 sizeof("/128 for IN ") + DNS_RDATATYPE_FORMATSIZE +       \
	 DNS_NAME_FORMATSIZE)

typedef struct dns_rrl_hash dns_rrl_hash_t;

/*
 * Response types.
 */
typedef enum {
	DNS_RRL_RTYPE_FREE = 0,
	DNS_RRL_RTYPE_QUERY,
	DNS_RRL_RTYPE_REFERRAL,
	DNS_RRL_RTYPE_NODATA,
	DNS_RRL_RTYPE_NXDOMAIN,
	DNS_RRL_RTYPE_ERROR,
	DNS_RRL_RTYPE_ALL,
	DNS_RRL_RTYPE_TCP,
} dns_rrl_rtype_t;

/*
 * A rate limit bucket key.
 * This should be small to limit the total size of the database.
 * The hash of the qname should be wide enough to make the probability
 * of collisions among requests from a single IP address block less than 50%.
 * We need a 32-bit hash value for 10000 qps (e.g. random qnames forged
 * by attacker) to collide with legitimate qnames from the target with
 * probability at most 1%.
 */
#define DNS_RRL_MAX_PREFIX 64
typedef union dns_rrl_key dns_rrl_key_t;
struct dns__rrl_key {
	uint32_t	ip[DNS_RRL_MAX_PREFIX / 32];
	uint32_t	qname_hash;
	dns_rdatatype_t qtype;
	uint8_t		qclass;
	unsigned int	rtype : 4; /* dns_rrl_rtype_t */
	unsigned int	ipv6  : 1;
};
union dns_rrl_key {
	struct dns__rrl_key s;
	uint16_t	    w[sizeof(struct dns__rrl_key) / sizeof(uint16_t)];
};

/*
 * A rate-limit entry.
 * This should be small to limit the total size of the table of entries.
 */
typedef struct dns_rrl_entry dns_rrl_entry_t;
typedef ISC_LIST(dns_rrl_entry_t) dns_rrl_bin_t;
struct dns_rrl_entry {
	ISC_LINK(dns_rrl_entry_t) lru;
	ISC_LINK(dns_rrl_entry_t) hlink;
	dns_rrl_key_t key;
#define DNS_RRL_RESPONSE_BITS 24
	signed int responses : DNS_RRL_RESPONSE_BITS;
#define DNS_RRL_QNAMES_BITS 8
	unsigned int log_qname : DNS_RRL_QNAMES_BITS;

#define DNS_RRL_TS_GEN_BITS 2
	unsigned int ts_gen : DNS_RRL_TS_GEN_BITS;
	unsigned int ts_valid : 1;
#define DNS_RRL_HASH_GEN_BITS 1
	unsigned int hash_gen : DNS_RRL_HASH_GEN_BITS;
	unsigned int logged : 1;
#define DNS_RRL_LOG_BITS 11
	unsigned int log_secs : DNS_RRL_LOG_BITS;

#define DNS_RRL_TS_BITS 12
	unsigned int ts : DNS_RRL_TS_BITS;

#define DNS_RRL_MAX_SLIP 10
	unsigned int slip_cnt : 4;
};

#define DNS_RRL_MAX_TIME_TRAVEL 5
#define DNS_RRL_FOREVER		(1 << DNS_RRL_TS_BITS)
#define DNS_RRL_MAX_TS		(DNS_RRL_FOREVER - 1)

#define DNS_RRL_MAX_RESPONSES ((1 << (DNS_RRL_RESPONSE_BITS - 1)) - 1)
#define DNS_RRL_MAX_WINDOW    3600
#if DNS_RRL_MAX_WINDOW >= DNS_RRL_MAX_TS
#error "DNS_RRL_MAX_WINDOW is too large"
#endif /* if DNS_RRL_MAX_WINDOW >= DNS_RRL_MAX_TS */
#define DNS_RRL_MAX_RATE 1000
#if DNS_RRL_MAX_RATE >= (DNS_RRL_MAX_RESPONSES / DNS_RRL_MAX_WINDOW)
#error "DNS_RRL_MAX_rate is too large"
#endif /* if DNS_RRL_MAX_RATE >= (DNS_RRL_MAX_RESPONSES / DNS_RRL_MAX_WINDOW) \
	*/

#if (1 << DNS_RRL_LOG_BITS) >= DNS_RRL_FOREVER
#error DNS_RRL_LOG_BITS is too big
#endif /* if (1 << DNS_RRL_LOG_BITS) >= DNS_RRL_FOREVER */
#define DNS_RRL_MAX_LOG_SECS 1800
#if DNS_RRL_MAX_LOG_SECS >= (1 << DNS_RRL_LOG_BITS)
#error "DNS_RRL_MAX_LOG_SECS is too large"
#endif /* if DNS_RRL_MAX_LOG_SECS >= (1 << DNS_RRL_LOG_BITS) */
#define DNS_RRL_STOP_LOG_SECS 60
#if DNS_RRL_STOP_LOG_SECS >= (1 << DNS_RRL_LOG_BITS)
#error "DNS_RRL_STOP_LOG_SECS is too large"
#endif /* if DNS_RRL_STOP_LOG_SECS >= (1 << DNS_RRL_LOG_BITS) */

/*
 * A hash table of rate-limit entries.
 */
struct dns_rrl_hash {
	isc_stdtime_t check_time;
	unsigned int  gen : DNS_RRL_HASH_GEN_BITS;
	int	      length;
	dns_rrl_bin_t bins[] ISC_ATTR_COUNTED_BY(length);
};

/*
 * A block of rate-limit entries.
 */
typedef struct dns_rrl_block dns_rrl_block_t;
struct dns_rrl_block {
	ISC_LINK(dns_rrl_block_t) link;
	uint32_t	count;
	dns_rrl_entry_t entries[] ISC_ATTR_COUNTED_BY(count);
};

/*
 * A rate limited qname buffer.
 */
typedef struct dns_rrl_qname_buf dns_rrl_qname_buf_t;
struct dns_rrl_qname_buf {
	ISC_LINK(dns_rrl_qname_buf_t) link;
	const dns_rrl_entry_t *e;
	unsigned int	       index;
	dns_fixedname_t	       qname;
};

typedef struct dns_rrl_rate dns_rrl_rate_t;
struct dns_rrl_rate {
	int	    r;
	int	    scaled;
	const char *str;
};

/*
 * Per-view query rate limit parameters and a pointer to database.
 */
typedef struct dns_rrl dns_rrl_t;
struct dns_rrl {
	isc_mutex_t lock;
	isc_mem_t  *mctx;

	bool	       log_only;
	dns_rrl_rate_t responses_per_second;
	dns_rrl_rate_t referrals_per_second;
	dns_rrl_rate_t nodata_per_second;
	dns_rrl_rate_t nxdomains_per_second;
	dns_rrl_rate_t errors_per_second;
	dns_rrl_rate_t all_per_second;
	dns_rrl_rate_t slip;
	int	       window;
	double	       qps_scale;
	int	       max_entries;

	dns_acl_t *exempt;

	int num_entries;

	int	      qps_responses;
	isc_stdtime_t qps_time;
	double	      qps;

	unsigned int probes;
	unsigned int searches;

	ISC_LIST(dns_rrl_block_t) blocks;
	ISC_LIST(dns_rrl_entry_t) lru;

	dns_rrl_hash_t *hash;
	dns_rrl_hash_t *old_hash;
	unsigned int	hash_gen;

	unsigned int ts_gen;
#define DNS_RRL_TS_BASES (1 << DNS_RRL_TS_GEN_BITS)
	isc_stdtime_t ts_bases[DNS_RRL_TS_BASES];

	int	 ipv4_prefixlen;
	uint32_t ipv4_mask;
	int	 ipv6_prefixlen;
	uint32_t ipv6_mask[4];

	isc_stdtime_t	 log_stops_time;
	dns_rrl_entry_t *last_logged;
	int		 num_logged;
	int		 num_qnames;
	ISC_LIST(dns_rrl_qname_buf_t) qname_free;
#define DNS_RRL_QNAMES (1 << DNS_RRL_QNAMES_BITS)
	dns_rrl_qname_buf_t *qnames[DNS_RRL_QNAMES];
};

typedef enum {
	DNS_RRL_RESULT_OK,
	DNS_RRL_RESULT_DROP,
	DNS_RRL_RESULT_SLIP,
} dns_rrl_result_t;

dns_rrl_result_t
dns_rrl(dns_view_t *view, dns_zone_t *zone, const isc_sockaddr_t *client_addr,
	bool is_tcp, dns_rdataclass_t rdclass, dns_rdatatype_t qtype,
	const dns_name_t *qname, isc_result_t resp_result, isc_stdtime_t now,
	bool wouldlog, char *log_buf, unsigned int log_buf_len);

void
dns_rrl_view_destroy(dns_view_t *view);

isc_result_t
dns_rrl_init(dns_rrl_t **rrlp, dns_view_t *view, int min_entries);
