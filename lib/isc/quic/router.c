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

#include <stdint.h>

#include <ngtcp2/ngtcp2.h>

#include <isc/attributes.h>
#include <isc/hash.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/quic.h>
#include <isc/safe.h>
#include <isc/urcu.h>
#include <isc/util.h>

typedef struct cid_entry cid_entry_t;
typedef struct reset_entry_t reset_entry_t;

struct cid_entry {
	struct cds_lfht_node node;
	struct rcu_head rcu_head;
	isc_mem_t *mctx;
	isc_quic_conn_t *value;
	isc_tid_t tid;
	size_t length;
	uint8_t data[] ISC_ATTR_COUNTED_BY(length);
};

struct reset_entry_t {
	struct cds_lfht_node node;
	struct rcu_head rcu_head;
	isc_mem_t *mctx;
	isc_tid_t tid;
	isc_quic_conn_t *value;
	uint8_t token[ISC_QUIC_STATELESS_TOKEN_LENGTH];
};

struct isc_quic_router {
	uint32_t magic;
	isc_refcount_t references;
	isc_mem_t *mctx;
	size_t cidlen;
	struct cds_lfht *cid_ht;
	struct cds_lfht *reset_ht;
};

constexpr uint32_t router_magic = ISC_MAGIC('Q', 'U', 'I', 'r');

/*
 * Header Form bit, set on Long header packets and clear on Short header
 * (1-RTT) packets (RFC9000, Section 17). ngtcp2 only exposes this in a
 * private header, so it is defined locally.
 */
constexpr uint8_t quic_long_header_bit = 0x80;
constexpr unsigned long ht_init_size = (1 << 4); /* Must be power of 2 */
constexpr unsigned long ht_min_size = (1 << 4);	 /* Must be power of 2 */

STATIC_ASSERT(ISC_QUIC_CID_MIN_LENGTH == NGTCP2_MIN_CIDLEN,
	      "QUIC minimum CID length mismatches with the definition "
	      "inside ngtcp2");

STATIC_ASSERT(ISC_QUIC_CID_MAX_LENGTH == NGTCP2_MAX_CIDLEN,
	      "QUIC maximum CID length mismatches with the definition "
	      "inside ngtcp2");

STATIC_ASSERT(ISC_QUIC_STATELESS_TOKEN_LENGTH ==
		      NGTCP2_STATELESS_RESET_TOKENLEN,
	      "QUIC stateless token length mismatches with the definition "
	      "inside ngtcp2");

static int
cid_match(struct cds_lfht_node *node, const void *key) {
	cid_entry_t *entry = caa_container_of(node, cid_entry_t, node);
	const isc_constregion_t *data = key;
	return (entry->length == data->length) &&
	       (memcmp(entry->data, data->base, entry->length) == 0);
}

static void
cid_free(struct rcu_head *rcu_head) {
	cid_entry_t *entry = caa_container_of(rcu_head, cid_entry_t, rcu_head);
	isc_quic_conn_unref(entry->value);
	isc_mem_putanddetach(&entry->mctx, entry,
			     STRUCT_FLEX_SIZE(entry, data, entry->length));
}

static int
reset_match(struct cds_lfht_node *node, const void *key) {
	reset_entry_t *entry = caa_container_of(node, reset_entry_t, node);
	return isc_safe_memequal(entry->token, key,
				 ISC_QUIC_STATELESS_TOKEN_LENGTH);
}

static void
reset_free(struct rcu_head *rcu_head) {
	reset_entry_t *entry = caa_container_of(rcu_head, reset_entry_t,
						rcu_head);
	isc_quic_conn_unref(entry->value);
	isc_mem_putanddetach(&entry->mctx, entry, sizeof(*entry));
}

static void
destroy(isc_quic_router_t *router) {
	struct cds_lfht_iter iter;
	reset_entry_t *r;
	cid_entry_t *c;

	cds_lfht_for_each_entry(router->cid_ht, &iter, c, node) {
		INSIST(!cds_lfht_del(router->cid_ht, &c->node));
		call_rcu(&c->rcu_head, cid_free);
	}
	RUNTIME_CHECK(!cds_lfht_destroy(router->cid_ht, NULL));

	cds_lfht_for_each_entry(router->reset_ht, &iter, r, node) {
		INSIST(!cds_lfht_del(router->reset_ht, &r->node));
		call_rcu(&r->rcu_head, reset_free);
	}
	RUNTIME_CHECK(!cds_lfht_destroy(router->reset_ht, NULL));

	router->magic = 0;

	isc_mem_putanddetach(&router->mctx, router, sizeof(*router));
}

ISC_REFCOUNT_IMPL(isc_quic_router, destroy);

void
isc_quic_router_create(isc_mem_t *mctx, size_t cidlen,
		       isc_quic_router_t **routerp) {
	isc_quic_router_t *router;

	REQUIRE(routerp != NULL && *routerp == NULL);
	REQUIRE(cidlen >= ISC_QUIC_CID_MIN_LENGTH &&
		cidlen <= ISC_QUIC_CID_MAX_LENGTH);

	router = isc_mem_get(mctx, sizeof(*router));
	*router = (isc_quic_router_t){
		.magic = router_magic,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.mctx = isc_mem_ref(mctx),
		.cidlen = cidlen,
		.cid_ht = cds_lfht_new(
			ht_init_size, ht_min_size, 0,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL),
		.reset_ht = cds_lfht_new(
			ht_init_size, ht_min_size, 0,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL),
	};
	INSIST(router->cid_ht != NULL);
	INSIST(router->reset_ht != NULL);

	*routerp = router;
}

isc_result_t
isc_quic_router_add_cid(isc_quic_router_t *router, isc_constregion_t cid,
			isc_tid_t tid, void *conn) {
	struct cds_lfht_node *node;
	cid_entry_t *entry;
	uint32_t hash;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(cid.base != NULL && cid.length >= ISC_QUIC_CID_MIN_LENGTH &&
		cid.length <= ISC_QUIC_CID_MAX_LENGTH);
	REQUIRE(tid >= 0);

	hash = isc_hash32(cid.base, cid.length, true);

	entry = isc_mem_get(router->mctx,
			    STRUCT_FLEX_SIZE(entry, data, cid.length));
	*entry = (cid_entry_t){
		.value = conn,
		.mctx = isc_mem_ref(router->mctx),
		.tid = tid,
		.length = cid.length,
	};
	memmove(entry->data, cid.base, cid.length);

	/* The routing table holds a reference for as long as it stores conn. */
	isc_quic_conn_ref(conn);

	rcu_read_lock();
	node = cds_lfht_add_unique(router->cid_ht, hash, cid_match, &cid,
				   &entry->node);
	rcu_read_unlock();

	if (node != &entry->node) {
		isc_quic_conn_unref(conn);
		isc_mem_putanddetach(&entry->mctx, entry,
				     STRUCT_FLEX_SIZE(entry, data, cid.length));
		return ISC_R_EXISTS;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_router_get_cid(isc_quic_router_t *router, isc_constregion_t cid,
			isc_tid_t *tidp, isc_quic_conn_t **connp) {
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	isc_result_t result;
	cid_entry_t *entry;
	uint32_t hash;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(cid.base != NULL && cid.length >= ISC_QUIC_CID_MIN_LENGTH &&
		cid.length <= ISC_QUIC_CID_MAX_LENGTH);

	hash = isc_hash32(cid.base, cid.length, true);

	rcu_read_lock();
	cds_lfht_lookup(router->cid_ht, hash, cid_match, &cid, &iter);
	node = cds_lfht_iter_get_node(&iter);
	entry = cds_lfht_entry(node, cid_entry_t, node);
	if (entry == NULL) {
		result = ISC_R_NOTFOUND;
	} else {
		result = ISC_R_SUCCESS;
		if (connp != NULL) {
			isc_quic_conn_ref(entry->value);
			*connp = entry->value;
		}
		SET_IF_NOT_NULL(tidp, entry->tid);
	}
	rcu_read_unlock();

	return result;
}

isc_result_t
isc_quic_router_del_cid(isc_quic_router_t *router, isc_constregion_t cid) {
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	isc_result_t result;
	cid_entry_t *entry;
	uint32_t hash;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(cid.base != NULL && cid.length >= ISC_QUIC_CID_MIN_LENGTH &&
		cid.length <= ISC_QUIC_CID_MAX_LENGTH);

	hash = isc_hash32(cid.base, cid.length, true);

	rcu_read_lock();
	cds_lfht_lookup(router->cid_ht, hash, cid_match, &cid, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node == NULL) {
		result = ISC_R_NOTFOUND;
	} else if (cds_lfht_del(router->cid_ht, node) != 0) {
		/* Another thread removed the same entry first. */
		result = ISC_R_NOTFOUND;
	} else {
		entry = caa_container_of(node, cid_entry_t, node);
		call_rcu(&entry->rcu_head, cid_free);
		result = ISC_R_SUCCESS;
	}
	rcu_read_unlock();

	return result;
}

isc_result_t
isc_quic_router_add_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[restrict ISC_QUIC_STATELESS_TOKEN_LENGTH],
	isc_tid_t tid, void *conn) {
	struct cds_lfht_node *node;
	reset_entry_t *entry;
	uint32_t hash;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(token != NULL);
	REQUIRE(tid >= 0);

	hash = isc_hash32(token, ISC_QUIC_STATELESS_TOKEN_LENGTH, true);

	entry = isc_mem_get(router->mctx, sizeof(*entry));
	*entry = (reset_entry_t){
		.value = conn,
		.mctx = isc_mem_ref(router->mctx),
		.tid = tid,
	};
	memmove(entry->token, token, ISC_QUIC_STATELESS_TOKEN_LENGTH);

	/* The routing table holds a reference for as long as it stores conn. */
	isc_quic_conn_ref(conn);

	rcu_read_lock();
	node = cds_lfht_add_unique(router->reset_ht, hash, reset_match, token,
				   &entry->node);
	rcu_read_unlock();

	if (node != &entry->node) {
		isc_quic_conn_unref(conn);
		isc_mem_putanddetach(&entry->mctx, entry, sizeof(*entry));
		return ISC_R_EXISTS;
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_quic_router_get_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[const restrict ISC_QUIC_STATELESS_TOKEN_LENGTH],
	isc_tid_t *tidp, isc_quic_conn_t **connp) {
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	reset_entry_t *entry;
	isc_result_t result;
	uint32_t hash;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(token != NULL);

	hash = isc_hash32(token, NGTCP2_STATELESS_RESET_TOKENLEN, true);

	rcu_read_lock();
	cds_lfht_lookup(router->reset_ht, hash, reset_match, token, &iter);
	node = cds_lfht_iter_get_node(&iter);
	entry = cds_lfht_entry(node, reset_entry_t, node);
	if (entry == NULL) {
		result = ISC_R_NOTFOUND;
	} else {
		result = ISC_R_SUCCESS;
		SET_IF_NOT_NULL(tidp, entry->tid);
		if (connp != NULL) {
			isc_quic_conn_ref(entry->value);
			*connp = entry->value;
		}
	}
	rcu_read_unlock();

	return result;
}

isc_result_t
isc_quic_router_del_stateless_reset(
	isc_quic_router_t *router,
	const uint8_t token[const restrict ISC_QUIC_STATELESS_TOKEN_LENGTH]) {
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	isc_result_t result;
	reset_entry_t *entry;
	uint32_t hash;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(token != NULL);

	hash = isc_hash32(token, NGTCP2_STATELESS_RESET_TOKENLEN, true);

	rcu_read_lock();
	cds_lfht_lookup(router->reset_ht, hash, reset_match, token, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node == NULL) {
		result = ISC_R_NOTFOUND;
	} else if (cds_lfht_del(router->reset_ht, node) != 0) {
		/* Another thread removed the same entry first. */
		result = ISC_R_NOTFOUND;
	} else {
		entry = caa_container_of(node, reset_entry_t, node);
		call_rcu(&entry->rcu_head, reset_free);
		result = ISC_R_SUCCESS;
	}
	rcu_read_unlock();

	return result;
}

isc_result_t
isc_quic_router_handle_packet(isc_quic_router_t *router,
			      isc_constregion_t packet,
			      isc_quic_version_t *versionp,
			      isc_constregion_t *dcidp,
			      isc_constregion_t *scidp, isc_tid_t *tidp,
			      isc_quic_conn_t **connp) {
	isc_constregion_t dcid, scid;
	ngtcp2_version_cid version;
	const uint8_t *token;
	int r;

	REQUIRE(router != NULL && router->magic == router_magic);
	REQUIRE(packet.base != NULL && packet.length != 0);
	REQUIRE(dcidp != NULL && scidp != NULL);
	REQUIRE(connp != NULL && *connp == NULL);

	r = ngtcp2_pkt_decode_version_cid(&version, packet.base, packet.length,
					  router->cidlen);
	switch (r) {
	case 0:
		break;
	case NGTCP2_ERR_VERSION_NEGOTIATION:
		SET_IF_NOT_NULL(versionp, ISC_QUIC_VERSION_UNKNOWN);
		/*
		 * ngtcp2 populates all fields of `version` on this path so
		 * the caller can build the Version Negotiation response.
		 */
		*dcidp = (isc_constregion_t){ version.dcidlen, version.dcid };
		*scidp = (isc_constregion_t){ version.scidlen, version.scid };
		return ISC_R_NOTIMPLEMENTED;
	case NGTCP2_ERR_INVALID_ARGUMENT:
	default:
		/*
		 * The default is technically not necessary since ngtcp2 prefers
		 * to add a new function version instead but this is an easy
		 * reassurance.
		 */
		SET_IF_NOT_NULL(versionp, ISC_QUIC_VERSION_INVALID);
		return ISC_R_INVALIDPROTO;
	}

	switch (version.version) {
	case NGTCP2_PROTO_VER_V1:
		SET_IF_NOT_NULL(versionp, ISC_QUIC_VERSION_V1);
		break;
	case NGTCP2_PROTO_VER_V2:
		SET_IF_NOT_NULL(versionp, ISC_QUIC_VERSION_V2);
		break;
	default:
		SET_IF_NOT_NULL(versionp, ISC_QUIC_VERSION_UNKNOWN);
		break;
	}

	dcid = (isc_constregion_t){ version.dcidlen, version.dcid };
	scid = (isc_constregion_t){ version.scidlen, version.scid };

	*dcidp = dcid;
	*scidp = scid;

	if (version.version == 0) {
		/*
		 * A zero version is reported both for a Short header (1-RTT)
		 * packet and for a received Version Negotiation packet (Long
		 * header). The Header Form bit (RFC9000, Section 17) tells them
		 * apart: only a Short header packet can be a Stateless Reset.
		 */
		if ((((const uint8_t *)packet.base)[0] &
		     quic_long_header_bit) != 0)
		{
			return ISC_R_IGNORE;
		}

		/*
		 * A Stateless Reset is at least
		 * NGTCP2_MIN_STATELESS_RESET_RANDLEN + the token length long
		 * (RFC9000, Section 10.3).
		 */
		if (packet.length < NGTCP2_MIN_STATELESS_RESET_RANDLEN +
					    ISC_QUIC_STATELESS_TOKEN_LENGTH)
		{
			return ISC_R_IGNORE;
		}

		token = (const uint8_t *)packet.base + packet.length -
			ISC_QUIC_STATELESS_TOKEN_LENGTH;

		if (isc_quic_router_get_stateless_reset(router, token, tidp,
							connp) == ISC_R_SUCCESS)
		{
			return ISC_R_CONNECTIONRESET;
		}

		/* Not a Stateless Reset: fall through to the CID lookup. */
	}

	/*
	 * The DCID length is taken from the wire and, for a supported version,
	 * is only bounded above by ngtcp2.  Guard the lookup so an out-of-range
	 * (e.g. zero-length) DCID does not trip the REQUIRE in get_cid().
	 */
	if (dcid.length >= ISC_QUIC_CID_MIN_LENGTH &&
	    dcid.length <= ISC_QUIC_CID_MAX_LENGTH &&
	    isc_quic_router_get_cid(router, dcid, tidp, connp) == ISC_R_SUCCESS)
	{
		return ISC_R_SUCCESS;
	}

	if (version.version == 0) {
		/*
		 * A Short header (1-RTT) packet for a connection we do not
		 * know, and not a known Stateless Reset either: the caller
		 * MAY answer with a Stateless Reset (RFC9000, Section 10.3).
		 * ngtcp2_accept() only ever accepts a Long header Initial,
		 * so there is nothing further to try.
		 */
		return ISC_R_UNEXPECTED;
	}

	if (ngtcp2_accept(NULL, packet.base, packet.length) != 0) {
		return ISC_R_IGNORE;
	}

	return ISC_R_NOTFOUND;
}
