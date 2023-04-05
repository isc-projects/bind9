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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/mem.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/catz.h>
#include <dns/db.h>
#include <dns/diff.h>
#include <dns/dispatch.h>
#include <dns/journal.h>
#include <dns/log.h>
#include <dns/message.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/result.h>
#include <dns/soa.h>
#include <dns/transport.h>
#include <dns/tsig.h>
#include <dns/view.h>
#include <dns/xfrin.h>
#include <dns/zone.h>

#include <dst/dst.h>

/*
 * Incoming AXFR and IXFR.
 */

/*%
 * It would be non-sensical (or at least obtuse) to use FAIL() with an
 * ISC_R_SUCCESS code, but the test is there to keep the Solaris compiler
 * from complaining about "end-of-loop code not reached".
 */
#define FAIL(code)                           \
	do {                                 \
		result = (code);             \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto failure;        \
	} while (0)

/*%
 * The states of the *XFR state machine.  We handle both IXFR and AXFR
 * with a single integrated state machine because they cannot be distinguished
 * immediately - an AXFR response to an IXFR request can only be detected
 * when the first two (2) response RRs have already been received.
 */
typedef enum {
	XFRST_SOAQUERY,
	XFRST_GOTSOA,
	XFRST_INITIALSOA,
	XFRST_FIRSTDATA,
	XFRST_IXFR_DELSOA,
	XFRST_IXFR_DEL,
	XFRST_IXFR_ADDSOA,
	XFRST_IXFR_ADD,
	XFRST_IXFR_END,
	XFRST_AXFR,
	XFRST_AXFR_END
} xfrin_state_t;

/*%
 * Incoming zone transfer context.
 */

struct dns_xfrin {
	unsigned int magic;
	isc_mem_t *mctx;
	dns_zone_t *zone;
	dns_view_t *view;

	isc_refcount_t references;

	atomic_bool shuttingdown;

	isc_result_t shutdown_result;

	dns_name_t name; /*%< Name of zone to transfer */
	dns_rdataclass_t rdclass;

	dns_messageid_t id;

	/*%
	 * Requested transfer type (dns_rdatatype_axfr or
	 * dns_rdatatype_ixfr).  The actual transfer type
	 * may differ due to IXFR->AXFR fallback.
	 */
	dns_rdatatype_t reqtype;

	isc_sockaddr_t primaryaddr;
	isc_sockaddr_t sourceaddr;

	dns_dispatch_t *disp;
	dns_dispentry_t *dispentry;

	/*% Buffer for IXFR/AXFR request message */
	isc_buffer_t qbuffer;
	unsigned char qbuffer_data[512];

	/*%
	 * Whether the zone originally had a database attached at the time this
	 * transfer context was created.  Used by xfrin_destroy() when making
	 * logging decisions.
	 */
	bool zone_had_db;

	dns_db_t *db;
	dns_dbversion_t *ver;
	dns_diff_t diff; /*%< Pending database changes */
	int difflen;	 /*%< Number of pending tuples */

	xfrin_state_t state;
	uint32_t end_serial;
	bool is_ixfr;

	unsigned int nmsg;  /*%< Number of messages recvd */
	unsigned int nrecs; /*%< Number of records recvd */
	uint64_t nbytes;    /*%< Number of bytes received */

	unsigned int maxrecords; /*%< The maximum number of
				  *   records set for the zone */

	isc_time_t start; /*%< Start time of the transfer */
	isc_time_t end;	  /*%< End time of the transfer */

	dns_tsigkey_t *tsigkey; /*%< Key used to create TSIG */
	isc_buffer_t *lasttsig; /*%< The last TSIG */
	dst_context_t *tsigctx; /*%< TSIG verification context */
	unsigned int sincetsig; /*%< recvd since the last TSIG */

	dns_transport_t *transport;

	dns_xfrindone_t done;

	/*%
	 * AXFR- and IXFR-specific data.  Only one is used at a time
	 * according to the is_ixfr flag, so this could be a union,
	 * but keeping them separate makes it a bit simpler to clean
	 * things up when destroying the context.
	 */
	dns_rdatacallbacks_t axfr;

	struct {
		uint32_t request_serial;
		uint32_t current_serial;
		dns_journal_t *journal;
	} ixfr;

	dns_rdata_t firstsoa;
	unsigned char *firstsoa_data;

	isc_tlsctx_cache_t *tlsctx_cache;

	isc_timer_t *max_time_timer;
	isc_timer_t *max_idle_timer;
};

#define XFRIN_MAGIC    ISC_MAGIC('X', 'f', 'r', 'I')
#define VALID_XFRIN(x) ISC_MAGIC_VALID(x, XFRIN_MAGIC)

/**************************************************************************/
/*
 * Forward declarations.
 */

static void
xfrin_create(isc_mem_t *mctx, dns_zone_t *zone, dns_db_t *db,
	     dns_name_t *zonename, dns_rdataclass_t rdclass,
	     dns_rdatatype_t reqtype, const isc_sockaddr_t *primaryaddr,
	     const isc_sockaddr_t *sourceaddr, dns_tsigkey_t *tsigkey,
	     dns_transport_t *transport, isc_tlsctx_cache_t *tlsctx_cache,
	     dns_xfrin_t **xfrp);

static isc_result_t
axfr_init(dns_xfrin_t *xfr);
static isc_result_t
axfr_makedb(dns_xfrin_t *xfr, dns_db_t **dbp);
static isc_result_t
axfr_putdata(dns_xfrin_t *xfr, dns_diffop_t op, dns_name_t *name, dns_ttl_t ttl,
	     dns_rdata_t *rdata);
static isc_result_t
axfr_apply(dns_xfrin_t *xfr);
static isc_result_t
axfr_commit(dns_xfrin_t *xfr);
static isc_result_t
axfr_finalize(dns_xfrin_t *xfr);

static isc_result_t
ixfr_init(dns_xfrin_t *xfr);
static isc_result_t
ixfr_apply(dns_xfrin_t *xfr);
static isc_result_t
ixfr_putdata(dns_xfrin_t *xfr, dns_diffop_t op, dns_name_t *name, dns_ttl_t ttl,
	     dns_rdata_t *rdata);
static isc_result_t
ixfr_commit(dns_xfrin_t *xfr);

static isc_result_t
xfr_rr(dns_xfrin_t *xfr, dns_name_t *name, uint32_t ttl, dns_rdata_t *rdata);

static isc_result_t
xfrin_start(dns_xfrin_t *xfr);

static void
xfrin_connect_done(isc_result_t result, isc_region_t *region, void *arg);
static isc_result_t
xfrin_send_request(dns_xfrin_t *xfr);
static void
xfrin_send_done(isc_result_t eresult, isc_region_t *region, void *arg);
static void
xfrin_recv_done(isc_result_t result, isc_region_t *region, void *arg);

static void
xfrin_destroy(dns_xfrin_t *xfr);

static void
xfrin_timedout(void *);
static void
xfrin_idledout(void *);
static void
xfrin_fail(dns_xfrin_t *xfr, isc_result_t result, const char *msg);
static isc_result_t
render(dns_message_t *msg, isc_mem_t *mctx, isc_buffer_t *buf);

static void
xfrin_logv(dns_xfrin_t *xff, int level, const char *zonetext,
	   const isc_sockaddr_t *primaryaddr, const char *fmt, va_list ap)
	ISC_FORMAT_PRINTF(5, 0);

static void
xfrin_log(dns_xfrin_t *xfr, int level, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);

/**************************************************************************/
/*
 * AXFR handling
 */

static isc_result_t
axfr_init(dns_xfrin_t *xfr) {
	isc_result_t result;

	xfr->is_ixfr = false;

	if (xfr->db != NULL) {
		dns_db_detach(&xfr->db);
	}

	CHECK(axfr_makedb(xfr, &xfr->db));
	dns_rdatacallbacks_init(&xfr->axfr);
	CHECK(dns_db_beginload(xfr->db, &xfr->axfr));
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

static isc_result_t
axfr_makedb(dns_xfrin_t *xfr, dns_db_t **dbp) {
	isc_result_t result;

	result = dns_db_create(xfr->mctx, /* XXX */
			       "rbt",	  /* XXX guess */
			       &xfr->name, dns_dbtype_zone, xfr->rdclass, 0,
			       NULL, /* XXX guess */
			       dbp);
	if (result == ISC_R_SUCCESS) {
		dns_zone_rpz_enable_db(xfr->zone, *dbp);
		dns_zone_catz_enable_db(xfr->zone, *dbp);
	}
	return (result);
}

static isc_result_t
axfr_putdata(dns_xfrin_t *xfr, dns_diffop_t op, dns_name_t *name, dns_ttl_t ttl,
	     dns_rdata_t *rdata) {
	isc_result_t result;

	dns_difftuple_t *tuple = NULL;

	if (rdata->rdclass != xfr->rdclass) {
		return (DNS_R_BADCLASS);
	}

	CHECK(dns_zone_checknames(xfr->zone, name, rdata));
	CHECK(dns_difftuple_create(xfr->diff.mctx, op, name, ttl, rdata,
				   &tuple));
	dns_diff_append(&xfr->diff, &tuple);
	if (++xfr->difflen > 100) {
		CHECK(axfr_apply(xfr));
	}
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

/*
 * Store a set of AXFR RRs in the database.
 */
static isc_result_t
axfr_apply(dns_xfrin_t *xfr) {
	isc_result_t result;
	uint64_t records;

	CHECK(dns_diff_load(&xfr->diff, xfr->axfr.add, xfr->axfr.add_private));
	xfr->difflen = 0;
	dns_diff_clear(&xfr->diff);
	if (xfr->maxrecords != 0U) {
		result = dns_db_getsize(xfr->db, xfr->ver, &records, NULL);
		if (result == ISC_R_SUCCESS && records > xfr->maxrecords) {
			result = DNS_R_TOOMANYRECORDS;
			goto failure;
		}
	}
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

static isc_result_t
axfr_commit(dns_xfrin_t *xfr) {
	isc_result_t result;

	CHECK(axfr_apply(xfr));
	CHECK(dns_db_endload(xfr->db, &xfr->axfr));
	CHECK(dns_zone_verifydb(xfr->zone, xfr->db, NULL));

	result = ISC_R_SUCCESS;
failure:
	return (result);
}

static isc_result_t
axfr_finalize(dns_xfrin_t *xfr) {
	isc_result_t result;

	CHECK(dns_zone_replacedb(xfr->zone, xfr->db, true));

	result = ISC_R_SUCCESS;
failure:
	return (result);
}

/**************************************************************************/
/*
 * IXFR handling
 */

static isc_result_t
ixfr_init(dns_xfrin_t *xfr) {
	isc_result_t result;
	char *journalfile = NULL;

	if (xfr->reqtype != dns_rdatatype_ixfr) {
		xfrin_log(xfr, ISC_LOG_ERROR,
			  "got incremental response to AXFR request");
		return (DNS_R_FORMERR);
	}

	xfr->is_ixfr = true;
	INSIST(xfr->db != NULL);
	xfr->difflen = 0;

	journalfile = dns_zone_getjournal(xfr->zone);
	if (journalfile != NULL) {
		CHECK(dns_journal_open(xfr->mctx, journalfile,
				       DNS_JOURNAL_CREATE, &xfr->ixfr.journal));
	}

	result = ISC_R_SUCCESS;
failure:
	return (result);
}

static isc_result_t
ixfr_putdata(dns_xfrin_t *xfr, dns_diffop_t op, dns_name_t *name, dns_ttl_t ttl,
	     dns_rdata_t *rdata) {
	isc_result_t result;
	dns_difftuple_t *tuple = NULL;

	if (rdata->rdclass != xfr->rdclass) {
		return (DNS_R_BADCLASS);
	}

	if (op == DNS_DIFFOP_ADD) {
		CHECK(dns_zone_checknames(xfr->zone, name, rdata));
	}
	CHECK(dns_difftuple_create(xfr->diff.mctx, op, name, ttl, rdata,
				   &tuple));
	dns_diff_append(&xfr->diff, &tuple);
	if (++xfr->difflen > 100) {
		CHECK(ixfr_apply(xfr));
	}
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

/*
 * Apply a set of IXFR changes to the database.
 */
static isc_result_t
ixfr_apply(dns_xfrin_t *xfr) {
	isc_result_t result;
	uint64_t records;

	if (xfr->ver == NULL) {
		CHECK(dns_db_newversion(xfr->db, &xfr->ver));
		if (xfr->ixfr.journal != NULL) {
			CHECK(dns_journal_begin_transaction(xfr->ixfr.journal));
		}
	}
	CHECK(dns_diff_apply(&xfr->diff, xfr->db, xfr->ver));
	if (xfr->maxrecords != 0U) {
		result = dns_db_getsize(xfr->db, xfr->ver, &records, NULL);
		if (result == ISC_R_SUCCESS && records > xfr->maxrecords) {
			result = DNS_R_TOOMANYRECORDS;
			goto failure;
		}
	}
	if (xfr->ixfr.journal != NULL) {
		result = dns_journal_writediff(xfr->ixfr.journal, &xfr->diff);
		if (result != ISC_R_SUCCESS) {
			goto failure;
		}
	}
	dns_diff_clear(&xfr->diff);
	xfr->difflen = 0;
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

static isc_result_t
ixfr_commit(dns_xfrin_t *xfr) {
	isc_result_t result;

	CHECK(ixfr_apply(xfr));
	if (xfr->ver != NULL) {
		CHECK(dns_zone_verifydb(xfr->zone, xfr->db, xfr->ver));
		/* XXX enter ready-to-commit state here */
		if (xfr->ixfr.journal != NULL) {
			CHECK(dns_journal_commit(xfr->ixfr.journal));
		}
		dns_db_closeversion(xfr->db, &xfr->ver, true);
		dns_zone_markdirty(xfr->zone);
	}
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

/**************************************************************************/
/*
 * Common AXFR/IXFR protocol code
 */

/*
 * Handle a single incoming resource record according to the current
 * state.
 */
static isc_result_t
xfr_rr(dns_xfrin_t *xfr, dns_name_t *name, uint32_t ttl, dns_rdata_t *rdata) {
	isc_result_t result;

	xfr->nrecs++;

	if (rdata->type == dns_rdatatype_none ||
	    dns_rdatatype_ismeta(rdata->type))
	{
		FAIL(DNS_R_FORMERR);
	}

	/*
	 * Immediately reject the entire transfer if the RR that is currently
	 * being processed is an SOA record that is not placed at the zone
	 * apex.
	 */
	if (rdata->type == dns_rdatatype_soa &&
	    !dns_name_equal(&xfr->name, name))
	{
		char namebuf[DNS_NAME_FORMATSIZE];
		dns_name_format(name, namebuf, sizeof(namebuf));
		xfrin_log(xfr, ISC_LOG_DEBUG(3), "SOA name mismatch: '%s'",
			  namebuf);
		FAIL(DNS_R_NOTZONETOP);
	}

redo:
	switch (xfr->state) {
	case XFRST_SOAQUERY:
		if (rdata->type != dns_rdatatype_soa) {
			xfrin_log(xfr, ISC_LOG_ERROR,
				  "non-SOA response to SOA query");
			FAIL(DNS_R_FORMERR);
		}
		xfr->end_serial = dns_soa_getserial(rdata);
		if (!DNS_SERIAL_GT(xfr->end_serial, xfr->ixfr.request_serial) &&
		    !dns_zone_isforced(xfr->zone))
		{
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "requested serial %u, "
				  "primary has %u, not updating",
				  xfr->ixfr.request_serial, xfr->end_serial);
			FAIL(DNS_R_UPTODATE);
		}
		xfr->state = XFRST_GOTSOA;
		break;

	case XFRST_GOTSOA:
		/*
		 * Skip other records in the answer section.
		 */
		break;

	case XFRST_INITIALSOA:
		if (rdata->type != dns_rdatatype_soa) {
			xfrin_log(xfr, ISC_LOG_ERROR,
				  "first RR in zone transfer must be SOA");
			FAIL(DNS_R_FORMERR);
		}
		/*
		 * Remember the serial number in the initial SOA.
		 * We need it to recognize the end of an IXFR.
		 */
		xfr->end_serial = dns_soa_getserial(rdata);
		if (xfr->reqtype == dns_rdatatype_ixfr &&
		    !DNS_SERIAL_GT(xfr->end_serial, xfr->ixfr.request_serial) &&
		    !dns_zone_isforced(xfr->zone))
		{
			/*
			 * This must be the single SOA record that is
			 * sent when the current version on the primary
			 * is not newer than the version in the request.
			 */
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "requested serial %u, "
				  "primary has %u, not updating",
				  xfr->ixfr.request_serial, xfr->end_serial);
			FAIL(DNS_R_UPTODATE);
		}
		xfr->firstsoa = *rdata;
		if (xfr->firstsoa_data != NULL) {
			isc_mem_free(xfr->mctx, xfr->firstsoa_data);
		}
		xfr->firstsoa_data = isc_mem_allocate(xfr->mctx, rdata->length);
		memcpy(xfr->firstsoa_data, rdata->data, rdata->length);
		xfr->firstsoa.data = xfr->firstsoa_data;
		xfr->state = XFRST_FIRSTDATA;
		break;

	case XFRST_FIRSTDATA:
		/*
		 * If the transfer begins with one SOA record, it is an AXFR,
		 * if it begins with two SOAs, it is an IXFR.
		 */
		if (xfr->reqtype == dns_rdatatype_ixfr &&
		    rdata->type == dns_rdatatype_soa &&
		    xfr->ixfr.request_serial == dns_soa_getserial(rdata))
		{
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "got incremental response");
			CHECK(ixfr_init(xfr));
			xfr->state = XFRST_IXFR_DELSOA;
		} else {
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "got nonincremental response");
			CHECK(axfr_init(xfr));
			xfr->state = XFRST_AXFR;
		}
		goto redo;

	case XFRST_IXFR_DELSOA:
		INSIST(rdata->type == dns_rdatatype_soa);
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_DEL, name, ttl, rdata));
		xfr->state = XFRST_IXFR_DEL;
		break;

	case XFRST_IXFR_DEL:
		if (rdata->type == dns_rdatatype_soa) {
			uint32_t soa_serial = dns_soa_getserial(rdata);
			xfr->state = XFRST_IXFR_ADDSOA;
			xfr->ixfr.current_serial = soa_serial;
			goto redo;
		}
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_DEL, name, ttl, rdata));
		break;

	case XFRST_IXFR_ADDSOA:
		INSIST(rdata->type == dns_rdatatype_soa);
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		xfr->state = XFRST_IXFR_ADD;
		break;

	case XFRST_IXFR_ADD:
		if (rdata->type == dns_rdatatype_soa) {
			uint32_t soa_serial = dns_soa_getserial(rdata);
			if (soa_serial == xfr->end_serial) {
				CHECK(ixfr_commit(xfr));
				xfr->state = XFRST_IXFR_END;
				break;
			} else if (soa_serial != xfr->ixfr.current_serial) {
				xfrin_log(xfr, ISC_LOG_ERROR,
					  "IXFR out of sync: "
					  "expected serial %u, got %u",
					  xfr->ixfr.current_serial, soa_serial);
				FAIL(DNS_R_FORMERR);
			} else {
				CHECK(ixfr_commit(xfr));
				xfr->state = XFRST_IXFR_DELSOA;
				goto redo;
			}
		}
		if (rdata->type == dns_rdatatype_ns &&
		    dns_name_iswildcard(name))
		{
			FAIL(DNS_R_INVALIDNS);
		}
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		break;

	case XFRST_AXFR:
		/*
		 * Old BINDs sent cross class A records for non IN classes.
		 */
		if (rdata->type == dns_rdatatype_a &&
		    rdata->rdclass != xfr->rdclass &&
		    xfr->rdclass != dns_rdataclass_in)
		{
			break;
		}
		CHECK(axfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		if (rdata->type == dns_rdatatype_soa) {
			/*
			 * Use dns_rdata_compare instead of memcmp to
			 * allow for case differences.
			 */
			if (dns_rdata_compare(rdata, &xfr->firstsoa) != 0) {
				xfrin_log(xfr, ISC_LOG_ERROR,
					  "start and ending SOA records "
					  "mismatch");
				FAIL(DNS_R_FORMERR);
			}
			CHECK(axfr_commit(xfr));
			xfr->state = XFRST_AXFR_END;
			break;
		}
		break;
	case XFRST_AXFR_END:
	case XFRST_IXFR_END:
		FAIL(DNS_R_EXTRADATA);
		FALLTHROUGH;
	default:
		UNREACHABLE();
	}
	result = ISC_R_SUCCESS;
failure:
	return (result);
}

isc_result_t
dns_xfrin_create(dns_zone_t *zone, dns_rdatatype_t xfrtype,
		 const isc_sockaddr_t *primaryaddr,
		 const isc_sockaddr_t *sourceaddr, dns_tsigkey_t *tsigkey,
		 dns_transport_t *transport, isc_tlsctx_cache_t *tlsctx_cache,
		 isc_mem_t *mctx, dns_xfrindone_t done, dns_xfrin_t **xfrp) {
	dns_name_t *zonename = dns_zone_getorigin(zone);
	dns_xfrin_t *xfr = NULL;
	isc_result_t result;
	dns_db_t *db = NULL;

	REQUIRE(xfrp != NULL && *xfrp == NULL);
	REQUIRE(done != NULL);
	REQUIRE(isc_sockaddr_getport(primaryaddr) != 0);
	REQUIRE(zone != NULL);
	REQUIRE(dns_zone_getview(zone) != NULL);
	REQUIRE(dns_zone_gettid(zone) == isc_tid());

	(void)dns_zone_getdb(zone, &db);

	if (xfrtype == dns_rdatatype_soa || xfrtype == dns_rdatatype_ixfr) {
		REQUIRE(db != NULL);
	}

	xfrin_create(mctx, zone, db, zonename, dns_zone_getclass(zone), xfrtype,
		     primaryaddr, sourceaddr, tsigkey, transport, tlsctx_cache,
		     &xfr);

	if (db != NULL) {
		xfr->zone_had_db = true;
	}

	xfr->done = done;

	isc_refcount_init(&xfr->references, 1);

	/*
	 * Set *xfrp now, before calling xfrin_start(), otherwise it's
	 * possible the 'done' callback could be run before *xfrp
	 * was attached.
	 */
	*xfrp = xfr;

	result = xfrin_start(xfr);
	if (result != ISC_R_SUCCESS) {
		atomic_store(&xfr->shuttingdown, true);
		xfr->shutdown_result = result;
		xfrin_log(xfr, ISC_LOG_ERROR, "zone transfer setup failed");
		dns_xfrin_detach(xfrp);
	}

	if (db != NULL) {
		dns_db_detach(&db);
	}

	return (result);
}

static void
xfrin_timedout(void *xfr) {
	REQUIRE(VALID_XFRIN(xfr));

	xfrin_fail(xfr, ISC_R_TIMEDOUT, "maximum transfer time exceeded");
}

static void
xfrin_idledout(void *xfr) {
	REQUIRE(VALID_XFRIN(xfr));

	xfrin_fail(xfr, ISC_R_TIMEDOUT, "maximum idle time exceeded");
}

void
dns_xfrin_shutdown(dns_xfrin_t *xfr) {
	REQUIRE(VALID_XFRIN(xfr));
	REQUIRE(dns_zone_gettid(xfr->zone) == isc_tid());

	xfrin_fail(xfr, ISC_R_CANCELED, "shut down");
}

#if DNS_XFRIN_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_xfrin, xfrin_destroy);
#else
ISC_REFCOUNT_IMPL(dns_xfrin, xfrin_destroy);
#endif

static void
xfrin_cancelio(dns_xfrin_t *xfr) {
	dns_dispatch_done(&xfr->dispentry);
	dns_dispatch_detach(&xfr->disp);
}

static void
xfrin_reset(dns_xfrin_t *xfr) {
	REQUIRE(VALID_XFRIN(xfr));

	xfrin_log(xfr, ISC_LOG_INFO, "resetting");

	if (xfr->lasttsig != NULL) {
		isc_buffer_free(&xfr->lasttsig);
	}

	dns_diff_clear(&xfr->diff);
	xfr->difflen = 0;

	if (xfr->ixfr.journal != NULL) {
		dns_journal_destroy(&xfr->ixfr.journal);
	}

	if (xfr->axfr.add_private != NULL) {
		(void)dns_db_endload(xfr->db, &xfr->axfr);
	}

	if (xfr->ver != NULL) {
		dns_db_closeversion(xfr->db, &xfr->ver, false);
	}
}

static void
xfrin_fail(dns_xfrin_t *xfr, isc_result_t result, const char *msg) {
	dns_xfrin_ref(xfr);

	/* Make sure only the first xfrin_fail() trumps */
	if (atomic_compare_exchange_strong(&xfr->shuttingdown, &(bool){ false },
					   true))
	{
		isc_timer_stop(xfr->max_time_timer);
		isc_timer_stop(xfr->max_idle_timer);

		if (result != DNS_R_UPTODATE && result != DNS_R_TOOMANYRECORDS)
		{
			xfrin_log(xfr, ISC_LOG_ERROR, "%s: %s", msg,
				  isc_result_totext(result));
			if (xfr->is_ixfr) {
				/*
				 * Pass special result code to force AXFR retry
				 */
				result = DNS_R_BADIXFR;
			}
		}
		xfrin_cancelio(xfr);

		/*
		 * Close the journal.
		 */
		if (xfr->ixfr.journal != NULL) {
			dns_journal_destroy(&xfr->ixfr.journal);
		}
		if (xfr->done != NULL) {
			(xfr->done)(xfr->zone, result);
			xfr->done = NULL;
		}
		xfr->shutdown_result = result;
	}

	dns_xfrin_detach(&xfr);
}

static void
xfrin_create(isc_mem_t *mctx, dns_zone_t *zone, dns_db_t *db,
	     dns_name_t *zonename, dns_rdataclass_t rdclass,
	     dns_rdatatype_t reqtype, const isc_sockaddr_t *primaryaddr,
	     const isc_sockaddr_t *sourceaddr, dns_tsigkey_t *tsigkey,
	     dns_transport_t *transport, isc_tlsctx_cache_t *tlsctx_cache,
	     dns_xfrin_t **xfrp) {
	dns_xfrin_t *xfr = NULL;

	xfr = isc_mem_get(mctx, sizeof(*xfr));
	*xfr = (dns_xfrin_t){
		.shutdown_result = ISC_R_UNSET,
		.rdclass = rdclass,
		.reqtype = reqtype,
		.maxrecords = dns_zone_getmaxrecords(zone),
		.primaryaddr = *primaryaddr,
		.sourceaddr = *sourceaddr,
		.firstsoa = DNS_RDATA_INIT,
		.magic = XFRIN_MAGIC,
	};

	isc_mem_attach(mctx, &xfr->mctx);
	dns_zone_iattach(zone, &xfr->zone);
	dns_view_weakattach(dns_zone_getview(zone), &xfr->view);
	dns_name_init(&xfr->name, NULL);

	atomic_init(&xfr->shuttingdown, false);

	if (db != NULL) {
		dns_db_attach(db, &xfr->db);
	}

	dns_diff_init(xfr->mctx, &xfr->diff);

	if (reqtype == dns_rdatatype_soa) {
		xfr->state = XFRST_SOAQUERY;
	} else {
		xfr->state = XFRST_INITIALSOA;
	}

	xfr->start = isc_time_now();

	if (tsigkey != NULL) {
		dns_tsigkey_attach(tsigkey, &xfr->tsigkey);
	}

	if (transport != NULL) {
		dns_transport_attach(transport, &xfr->transport);
	}

	dns_name_dup(zonename, mctx, &xfr->name);

	INSIST(isc_sockaddr_pf(primaryaddr) == isc_sockaddr_pf(sourceaddr));
	isc_sockaddr_setport(&xfr->sourceaddr, 0);

	/*
	 * Reserve 2 bytes for TCP length at the beginning of the buffer.
	 */
	isc_buffer_init(&xfr->qbuffer, &xfr->qbuffer_data[2],
			sizeof(xfr->qbuffer_data) - 2);

	isc_tlsctx_cache_attach(tlsctx_cache, &xfr->tlsctx_cache);

	isc_timer_create(dns_zone_getloop(zone), xfrin_timedout, xfr,
			 &xfr->max_time_timer);
	isc_timer_create(dns_zone_getloop(zone), xfrin_idledout, xfr,
			 &xfr->max_idle_timer);

	*xfrp = xfr;
}

static isc_result_t
xfrin_start(dns_xfrin_t *xfr) {
	isc_result_t result = ISC_R_FAILURE;
	isc_interval_t interval;

	dns_xfrin_ref(xfr);

	/*
	 * Reuse an existing TCP connection if possible.  For XoT, we can't
	 * do this because other connections could be using a different
	 * certificate, so we just create a new dispatch every time.
	 */
	if (xfr->transport == NULL ||
	    dns_transport_get_type(xfr->transport) == DNS_TRANSPORT_TCP)
	{
		result = dns_dispatch_gettcp(dns_view_getdispatchmgr(xfr->view),
					     &xfr->primaryaddr,
					     &xfr->sourceaddr, &xfr->disp);
	}
	if (result == ISC_R_SUCCESS) {
		char peer[ISC_SOCKADDR_FORMATSIZE];
		isc_sockaddr_format(&xfr->primaryaddr, peer, sizeof(peer));
		xfrin_log(xfr, ISC_LOG_DEBUG(1),
			  "attached to TCP connection to %s", peer);
	} else {
		CHECK(dns_dispatch_createtcp(dns_view_getdispatchmgr(xfr->view),
					     &xfr->sourceaddr,
					     &xfr->primaryaddr, &xfr->disp));
	}

	/* Set the maximum timer */
	isc_interval_set(&interval, dns_zone_getmaxxfrin(xfr->zone), 0);
	isc_timer_start(xfr->max_time_timer, isc_timertype_once, &interval);

	/* Set the idle timer */
	isc_interval_set(&interval, dns_zone_getidlein(xfr->zone), 0);
	isc_timer_start(xfr->max_idle_timer, isc_timertype_once, &interval);

	/*
	 * XXX: timeouts are hard-coded to 30 seconds; this needs to be
	 * configurable.
	 */
	CHECK(dns_dispatch_add(
		xfr->disp, 0, 30000, &xfr->primaryaddr, xfr->transport,
		xfr->tlsctx_cache, xfrin_connect_done, xfrin_send_done,
		xfrin_recv_done, xfr, &xfr->id, &xfr->dispentry));
	CHECK(dns_dispatch_connect(xfr->dispentry));

	return (ISC_R_SUCCESS);

failure:
	if (xfr->dispentry != NULL) {
		dns_dispatch_done(&xfr->dispentry);
	}
	if (xfr->disp != NULL) {
		dns_dispatch_detach(&xfr->disp);
	}
	dns_xfrin_detach(&xfr);

	return (result);
}

/* XXX the resolver could use this, too */

static isc_result_t
render(dns_message_t *msg, isc_mem_t *mctx, isc_buffer_t *buf) {
	dns_compress_t cctx;
	isc_result_t result;

	dns_compress_init(&cctx, mctx, 0);
	CHECK(dns_message_renderbegin(msg, &cctx, buf));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0));
	CHECK(dns_message_renderend(msg));
	result = ISC_R_SUCCESS;
failure:
	dns_compress_invalidate(&cctx);
	return (result);
}

/*
 * A connection has been established.
 */
static void
xfrin_connect_done(isc_result_t result, isc_region_t *region ISC_ATTR_UNUSED,
		   void *arg) {
	dns_xfrin_t *xfr = (dns_xfrin_t *)arg;
	char addrtext[ISC_SOCKADDR_FORMATSIZE];
	char signerbuf[DNS_NAME_FORMATSIZE];
	const char *signer = "", *sep = "";
	dns_zonemgr_t *zmgr = NULL;

	REQUIRE(VALID_XFRIN(xfr));

	if (atomic_load(&xfr->shuttingdown)) {
		result = ISC_R_SHUTTINGDOWN;
	}

	if (result != ISC_R_SUCCESS) {
		xfrin_fail(xfr, result, "failed to connect");
		goto failure;
	}

	result = dns_dispatch_checkperm(xfr->disp);
	if (result != ISC_R_SUCCESS) {
		xfrin_fail(xfr, result, "connected but unable to transfer");
		goto failure;
	}

	zmgr = dns_zone_getmgr(xfr->zone);
	if (zmgr != NULL) {
		dns_zonemgr_unreachabledel(zmgr, &xfr->primaryaddr,
					   &xfr->sourceaddr);
	}

	if (xfr->tsigkey != NULL && xfr->tsigkey->key != NULL) {
		dns_name_format(dst_key_name(xfr->tsigkey->key), signerbuf,
				sizeof(signerbuf));
		sep = " TSIG ";
		signer = signerbuf;
	}

	isc_sockaddr_format(&xfr->primaryaddr, addrtext, sizeof(addrtext));
	xfrin_log(xfr, ISC_LOG_INFO, "connected using %s%s%s", addrtext, sep,
		  signer);

	result = xfrin_send_request(xfr);
	if (result != ISC_R_SUCCESS) {
		xfrin_fail(xfr, result, "connected but unable to send");
		goto detach;
	}

	return;

failure:
	switch (result) {
	case ISC_R_NETDOWN:
	case ISC_R_HOSTDOWN:
	case ISC_R_NETUNREACH:
	case ISC_R_HOSTUNREACH:
	case ISC_R_CONNREFUSED:
		/*
		 * Add the server to unreachable primaries table only if
		 * the server has a permanent networking error.
		 */
		zmgr = dns_zone_getmgr(xfr->zone);
		if (zmgr != NULL) {
			isc_time_t now = isc_time_now();

			dns_zonemgr_unreachableadd(zmgr, &xfr->primaryaddr,
						   &xfr->sourceaddr, &now);
		}
		break;
	default:
		/* Retry sooner than in 10 minutes */
		break;
	}

detach:
	dns_xfrin_unref(xfr);
}

/*
 * Convert a tuple into a dns_name_t suitable for inserting
 * into the given dns_message_t.
 */
static void
tuple2msgname(dns_difftuple_t *tuple, dns_message_t *msg, dns_name_t **target) {
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdl = NULL;
	dns_rdataset_t *rds = NULL;
	dns_name_t *name = NULL;

	REQUIRE(target != NULL && *target == NULL);

	dns_message_gettemprdata(msg, &rdata);
	dns_rdata_init(rdata);
	dns_rdata_clone(&tuple->rdata, rdata);

	dns_message_gettemprdatalist(msg, &rdl);
	dns_rdatalist_init(rdl);
	rdl->type = tuple->rdata.type;
	rdl->rdclass = tuple->rdata.rdclass;
	rdl->ttl = tuple->ttl;
	ISC_LIST_APPEND(rdl->rdata, rdata, link);

	dns_message_gettemprdataset(msg, &rds);
	dns_rdatalist_tordataset(rdl, rds);

	dns_message_gettempname(msg, &name);
	dns_name_clone(&tuple->name, name);
	ISC_LIST_APPEND(name->list, rds, link);

	*target = name;
}

static const char *
request_type(dns_xfrin_t *xfr) {
	switch (xfr->reqtype) {
	case dns_rdatatype_soa:
		return "SOA";
	case dns_rdatatype_axfr:
		return "AXFR";
	case dns_rdatatype_ixfr:
		return "IXFR";
	default:
		ISC_UNREACHABLE();
	}
}

/*
 * Build an *XFR request and send its length prefix.
 */
static isc_result_t
xfrin_send_request(dns_xfrin_t *xfr) {
	isc_result_t result;
	isc_region_t region;
	dns_rdataset_t *qrdataset = NULL;
	dns_message_t *msg = NULL;
	dns_difftuple_t *soatuple = NULL;
	dns_name_t *qname = NULL;
	dns_dbversion_t *ver = NULL;
	dns_name_t *msgsoaname = NULL;

	/* Create the request message */
	dns_message_create(xfr->mctx, DNS_MESSAGE_INTENTRENDER, &msg);
	CHECK(dns_message_settsigkey(msg, xfr->tsigkey));

	/* Create a name for the question section. */
	dns_message_gettempname(msg, &qname);
	dns_name_clone(&xfr->name, qname);

	/* Formulate the question and attach it to the question name. */
	dns_message_gettemprdataset(msg, &qrdataset);
	dns_rdataset_makequestion(qrdataset, xfr->rdclass, xfr->reqtype);
	ISC_LIST_APPEND(qname->list, qrdataset, link);
	qrdataset = NULL;

	dns_message_addname(msg, qname, DNS_SECTION_QUESTION);
	qname = NULL;

	if (xfr->reqtype == dns_rdatatype_ixfr) {
		/* Get the SOA and add it to the authority section. */
		dns_db_currentversion(xfr->db, &ver);
		CHECK(dns_db_createsoatuple(xfr->db, ver, xfr->mctx,
					    DNS_DIFFOP_EXISTS, &soatuple));
		xfr->ixfr.request_serial = dns_soa_getserial(&soatuple->rdata);
		xfr->ixfr.current_serial = xfr->ixfr.request_serial;
		xfrin_log(xfr, ISC_LOG_DEBUG(3),
			  "requesting IXFR for serial %u",
			  xfr->ixfr.request_serial);

		tuple2msgname(soatuple, msg, &msgsoaname);
		dns_message_addname(msg, msgsoaname, DNS_SECTION_AUTHORITY);
	} else if (xfr->reqtype == dns_rdatatype_soa) {
		CHECK(dns_db_getsoaserial(xfr->db, NULL,
					  &xfr->ixfr.request_serial));
	}

	xfr->nmsg = 0;
	xfr->nrecs = 0;
	xfr->nbytes = 0;
	xfr->start = isc_time_now();
	msg->id = xfr->id;
	if (xfr->tsigctx != NULL) {
		dst_context_destroy(&xfr->tsigctx);
	}

	CHECK(render(msg, xfr->mctx, &xfr->qbuffer));

	/*
	 * Free the last tsig, if there is one.
	 */
	if (xfr->lasttsig != NULL) {
		isc_buffer_free(&xfr->lasttsig);
	}

	/*
	 * Save the query TSIG and don't let message_destroy free it.
	 */
	CHECK(dns_message_getquerytsig(msg, xfr->mctx, &xfr->lasttsig));

	isc_buffer_usedregion(&xfr->qbuffer, &region);
	INSIST(region.length <= 65535);

	dns_xfrin_ref(xfr);
	dns_dispatch_send(xfr->dispentry, &region);
	xfrin_log(xfr, ISC_LOG_DEBUG(3), "sending %s request, QID %d",
		  request_type(xfr), xfr->id);

failure:
	dns_message_detach(&msg);
	if (soatuple != NULL) {
		dns_difftuple_free(&soatuple);
	}
	if (ver != NULL) {
		dns_db_closeversion(xfr->db, &ver, false);
	}

	return (result);
}

static void
xfrin_send_done(isc_result_t result, isc_region_t *region, void *arg) {
	dns_xfrin_t *xfr = (dns_xfrin_t *)arg;

	UNUSED(region);

	REQUIRE(VALID_XFRIN(xfr));

	if (atomic_load(&xfr->shuttingdown)) {
		result = ISC_R_SHUTTINGDOWN;
	}

	CHECK(result);

	xfrin_log(xfr, ISC_LOG_DEBUG(3), "sent request data");

failure:
	if (result != ISC_R_SUCCESS) {
		xfrin_fail(xfr, result, "failed sending request data");
	}

	dns_xfrin_detach(&xfr);
}

static void
xfrin_recv_done(isc_result_t result, isc_region_t *region, void *arg) {
	dns_xfrin_t *xfr = (dns_xfrin_t *)arg;
	dns_message_t *msg = NULL;
	dns_name_t *name = NULL;
	const dns_name_t *tsigowner = NULL;
	isc_buffer_t buffer;

	REQUIRE(VALID_XFRIN(xfr));

	if (atomic_load(&xfr->shuttingdown)) {
		result = ISC_R_SHUTTINGDOWN;
	}

	/* Stop the idle timer */
	isc_timer_stop(xfr->max_idle_timer);

	CHECK(result);

	xfrin_log(xfr, ISC_LOG_DEBUG(7), "received %u bytes", region->length);

	dns_message_create(xfr->mctx, DNS_MESSAGE_INTENTPARSE, &msg);

	CHECK(dns_message_settsigkey(msg, xfr->tsigkey));
	dns_message_setquerytsig(msg, xfr->lasttsig);

	msg->tsigctx = xfr->tsigctx;
	xfr->tsigctx = NULL;

	dns_message_setclass(msg, xfr->rdclass);

	if (xfr->nmsg > 0) {
		msg->tcp_continuation = 1;
	}

	isc_buffer_init(&buffer, region->base, region->length);
	isc_buffer_add(&buffer, region->length);

	result = dns_message_parse(msg, &buffer,
				   DNS_MESSAGEPARSE_PRESERVEORDER);
	if (result == ISC_R_SUCCESS) {
		dns_message_logpacket(
			msg, "received message from", &xfr->primaryaddr,
			DNS_LOGCATEGORY_XFER_IN, DNS_LOGMODULE_XFER_IN,
			ISC_LOG_DEBUG(10), xfr->mctx);
	} else {
		xfrin_log(xfr, ISC_LOG_DEBUG(10), "dns_message_parse: %s",
			  isc_result_totext(result));
	}

	if (result != ISC_R_SUCCESS || msg->rcode != dns_rcode_noerror ||
	    msg->opcode != dns_opcode_query || msg->rdclass != xfr->rdclass)
	{
		if (result == ISC_R_SUCCESS && msg->rcode != dns_rcode_noerror)
		{
			result = dns_result_fromrcode(msg->rcode);
		} else if (result == ISC_R_SUCCESS &&
			   msg->opcode != dns_opcode_query)
		{
			result = DNS_R_UNEXPECTEDOPCODE;
		} else if (result == ISC_R_SUCCESS &&
			   msg->rdclass != xfr->rdclass)
		{
			result = DNS_R_BADCLASS;
		} else if (result == ISC_R_SUCCESS || result == DNS_R_NOERROR) {
			result = DNS_R_UNEXPECTEDID;
		}

		if (xfr->reqtype == dns_rdatatype_axfr ||
		    xfr->reqtype == dns_rdatatype_soa)
		{
			goto failure;
		}

		xfrin_log(xfr, ISC_LOG_DEBUG(3), "got %s, retrying with AXFR",
			  isc_result_totext(result));
	try_axfr:
		dns_message_detach(&msg);
		xfrin_reset(xfr);
		xfr->reqtype = dns_rdatatype_soa;
		xfr->state = XFRST_SOAQUERY;
		result = xfrin_start(xfr);
		if (result != ISC_R_SUCCESS) {
			xfrin_fail(xfr, result, "failed setting up socket");
		}
		dns_xfrin_detach(&xfr);
		return;
	}

	/*
	 * The question section should exist for SOA and in the first
	 * message of a AXFR or IXFR response.  The question section
	 * may exist in the 2nd and subsequent messages in a AXFR or
	 * IXFR response.  If the question section exists it should
	 * match the question that was sent.
	 */
	if (msg->counts[DNS_SECTION_QUESTION] > 1) {
		xfrin_log(xfr, ISC_LOG_DEBUG(3), "too many questions (%u)",
			  msg->counts[DNS_SECTION_QUESTION]);
		result = DNS_R_FORMERR;
		goto failure;
	}

	if ((xfr->state == XFRST_SOAQUERY || xfr->state == XFRST_INITIALSOA) &&
	    msg->counts[DNS_SECTION_QUESTION] != 1)
	{
		xfrin_log(xfr, ISC_LOG_DEBUG(3), "missing question section");
		result = DNS_R_FORMERR;
		goto failure;
	}

	for (result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(msg, DNS_SECTION_QUESTION))
	{
		dns_rdataset_t *rds = NULL;

		name = NULL;
		dns_message_currentname(msg, DNS_SECTION_QUESTION, &name);
		if (!dns_name_equal(name, &xfr->name)) {
			result = DNS_R_FORMERR;
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "question name mismatch");
			goto failure;
		}
		rds = ISC_LIST_HEAD(name->list);
		INSIST(rds != NULL);
		if (rds->type != xfr->reqtype) {
			result = DNS_R_FORMERR;
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "question type mismatch");
			goto failure;
		}
		if (rds->rdclass != xfr->rdclass) {
			result = DNS_R_FORMERR;
			xfrin_log(xfr, ISC_LOG_DEBUG(3),
				  "question class mismatch");
			goto failure;
		}
	}
	if (result != ISC_R_NOMORE) {
		goto failure;
	}

	/*
	 * Does the server know about IXFR?  If it doesn't we will get
	 * a message with a empty answer section or a potentially a CNAME /
	 * DNAME, the later is handled by xfr_rr() which will return FORMERR
	 * if the first RR in the answer section is not a SOA record.
	 */
	if (xfr->reqtype == dns_rdatatype_ixfr &&
	    xfr->state == XFRST_INITIALSOA &&
	    msg->counts[DNS_SECTION_ANSWER] == 0)
	{
		xfrin_log(xfr, ISC_LOG_DEBUG(3),
			  "empty answer section, retrying with AXFR");
		goto try_axfr;
	}

	if (xfr->reqtype == dns_rdatatype_soa &&
	    (msg->flags & DNS_MESSAGEFLAG_AA) == 0)
	{
		FAIL(DNS_R_NOTAUTHORITATIVE);
	}

	result = dns_message_checksig(msg, xfr->view);
	if (result != ISC_R_SUCCESS) {
		xfrin_log(xfr, ISC_LOG_DEBUG(3), "TSIG check failed: %s",
			  isc_result_totext(result));
		goto failure;
	}

	for (result = dns_message_firstname(msg, DNS_SECTION_ANSWER);
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(msg, DNS_SECTION_ANSWER))
	{
		dns_rdataset_t *rds = NULL;

		name = NULL;
		dns_message_currentname(msg, DNS_SECTION_ANSWER, &name);
		for (rds = ISC_LIST_HEAD(name->list); rds != NULL;
		     rds = ISC_LIST_NEXT(rds, link))
		{
			for (result = dns_rdataset_first(rds);
			     result == ISC_R_SUCCESS;
			     result = dns_rdataset_next(rds))
			{
				dns_rdata_t rdata = DNS_RDATA_INIT;
				dns_rdataset_current(rds, &rdata);
				CHECK(xfr_rr(xfr, name, rds->ttl, &rdata));
			}
		}
	}
	if (result != ISC_R_NOMORE) {
		goto failure;
	}

	if (dns_message_gettsig(msg, &tsigowner) != NULL) {
		/*
		 * Reset the counter.
		 */
		xfr->sincetsig = 0;

		/*
		 * Free the last tsig, if there is one.
		 */
		if (xfr->lasttsig != NULL) {
			isc_buffer_free(&xfr->lasttsig);
		}

		/*
		 * Update the last tsig pointer.
		 */
		CHECK(dns_message_getquerytsig(msg, xfr->mctx, &xfr->lasttsig));
	} else if (dns_message_gettsigkey(msg) != NULL) {
		xfr->sincetsig++;
		if (xfr->sincetsig > 100 || xfr->nmsg == 0 ||
		    xfr->state == XFRST_AXFR_END ||
		    xfr->state == XFRST_IXFR_END)
		{
			result = DNS_R_EXPECTEDTSIG;
			goto failure;
		}
	}

	/*
	 * Update the number of messages received.
	 */
	xfr->nmsg++;

	/*
	 * Update the number of bytes received.
	 */
	xfr->nbytes += buffer.used;

	/*
	 * Take the context back.
	 */
	INSIST(xfr->tsigctx == NULL);
	xfr->tsigctx = msg->tsigctx;
	msg->tsigctx = NULL;

	switch (xfr->state) {
	case XFRST_GOTSOA:
		xfr->reqtype = dns_rdatatype_axfr;
		xfr->state = XFRST_INITIALSOA;
		CHECK(xfrin_send_request(xfr));
		break;
	case XFRST_AXFR_END:
		CHECK(axfr_finalize(xfr));
		FALLTHROUGH;
	case XFRST_IXFR_END:
		/*
		 * Close the journal.
		 */
		if (xfr->ixfr.journal != NULL) {
			dns_journal_destroy(&xfr->ixfr.journal);
		}

		/*
		 * Inform the caller we succeeded.
		 */
		if (xfr->done != NULL) {
			(xfr->done)(xfr->zone, ISC_R_SUCCESS);
			xfr->done = NULL;
		}

		atomic_store(&xfr->shuttingdown, true);
		isc_timer_stop(xfr->max_time_timer);
		xfr->shutdown_result = ISC_R_SUCCESS;
		break;
	default:
		/*
		 * Read the next message.
		 */
		dns_message_detach(&msg);
		dns_dispatch_getnext(xfr->dispentry);

		isc_interval_t interval;
		isc_interval_set(&interval, dns_zone_getidlein(xfr->zone), 0);
		isc_timer_start(xfr->max_idle_timer, isc_timertype_once,
				&interval);
		return;
	}

failure:
	if (result != ISC_R_SUCCESS) {
		xfrin_fail(xfr, result, "failed while receiving responses");
	}

	if (msg != NULL) {
		dns_message_detach(&msg);
	}
	dns_xfrin_detach(&xfr);
}

static void
xfrin_destroy(dns_xfrin_t *xfr) {
	uint64_t msecs, persec;

	REQUIRE(VALID_XFRIN(xfr));
	REQUIRE(dns_zone_gettid(xfr->zone) == isc_tid());

	/* Safe-guards */
	REQUIRE(atomic_load(&xfr->shuttingdown));
	isc_refcount_destroy(&xfr->references);

	INSIST(xfr->shutdown_result != ISC_R_UNSET);

	/*
	 * If we're called through dns_xfrin_detach() and are not
	 * shutting down, we can't know what the transfer status is as
	 * we are only called when the last reference is lost.
	 */
	xfrin_log(xfr, ISC_LOG_INFO, "Transfer status: %s",
		  isc_result_totext(xfr->shutdown_result));

	/*
	 * Calculate the length of time the transfer took,
	 * and print a log message with the bytes and rate.
	 */
	xfr->end = isc_time_now();
	msecs = isc_time_microdiff(&xfr->end, &xfr->start) / 1000;
	if (msecs == 0) {
		msecs = 1;
	}
	persec = (xfr->nbytes * 1000) / msecs;
	xfrin_log(xfr, ISC_LOG_INFO,
		  "Transfer completed: %d messages, %d records, "
		  "%" PRIu64 " bytes, "
		  "%u.%03u secs (%u bytes/sec) (serial %u)",
		  xfr->nmsg, xfr->nrecs, xfr->nbytes,
		  (unsigned int)(msecs / 1000), (unsigned int)(msecs % 1000),
		  (unsigned int)persec, xfr->end_serial);

	if (xfr->dispentry != NULL) {
		dns_dispatch_done(&xfr->dispentry);
	}
	if (xfr->disp != NULL) {
		dns_dispatch_detach(&xfr->disp);
	}

	if (xfr->transport != NULL) {
		dns_transport_detach(&xfr->transport);
	}

	if (xfr->tsigkey != NULL) {
		dns_tsigkey_detach(&xfr->tsigkey);
	}

	if (xfr->lasttsig != NULL) {
		isc_buffer_free(&xfr->lasttsig);
	}

	dns_diff_clear(&xfr->diff);

	if (xfr->ixfr.journal != NULL) {
		dns_journal_destroy(&xfr->ixfr.journal);
	}

	if (xfr->axfr.add_private != NULL) {
		(void)dns_db_endload(xfr->db, &xfr->axfr);
	}

	if (xfr->tsigctx != NULL) {
		dst_context_destroy(&xfr->tsigctx);
	}

	if (xfr->name.attributes.dynamic) {
		dns_name_free(&xfr->name, xfr->mctx);
	}

	if (xfr->ver != NULL) {
		dns_db_closeversion(xfr->db, &xfr->ver, false);
	}

	if (xfr->db != NULL) {
		dns_db_detach(&xfr->db);
	}

	if (xfr->zone != NULL) {
		if (!xfr->zone_had_db &&
		    xfr->shutdown_result == ISC_R_SUCCESS &&
		    dns_zone_gettype(xfr->zone) == dns_zone_mirror)
		{
			dns_zone_log(xfr->zone, ISC_LOG_INFO,
				     "mirror zone is now in use");
		}
		xfrin_log(xfr, ISC_LOG_DEBUG(99), "freeing transfer context");
		/*
		 * xfr->zone must not be detached before xfrin_log() is called.
		 */
		dns_zone_idetach(&xfr->zone);
	}

	if (xfr->view != NULL) {
		dns_view_weakdetach(&xfr->view);
	}

	if (xfr->firstsoa_data != NULL) {
		isc_mem_free(xfr->mctx, xfr->firstsoa_data);
	}

	if (xfr->tlsctx_cache != NULL) {
		isc_tlsctx_cache_detach(&xfr->tlsctx_cache);
	}

	isc_timer_destroy(&xfr->max_idle_timer);
	isc_timer_destroy(&xfr->max_time_timer);

	isc_mem_putanddetach(&xfr->mctx, xfr, sizeof(*xfr));
}

/*
 * Log incoming zone transfer messages in a format like
 * transfer of <zone> from <address>: <message>
 */
static void
xfrin_logv(dns_xfrin_t *xfr, int level, const char *zonetext,
	   const isc_sockaddr_t *primaryaddr, const char *fmt, va_list ap) {
	char primarytext[ISC_SOCKADDR_FORMATSIZE];
	char msgtext[2048];

	isc_sockaddr_format(primaryaddr, primarytext, sizeof(primarytext));
	vsnprintf(msgtext, sizeof(msgtext), fmt, ap);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_XFER_IN, DNS_LOGMODULE_XFER_IN,
		      level, "%p: transfer of '%s' from %s: %s", xfr, zonetext,
		      primarytext, msgtext);
}

/*
 * Logging function for use when there is a xfrin_ctx_t.
 */

static void
xfrin_log(dns_xfrin_t *xfr, int level, const char *fmt, ...) {
	va_list ap;
	char zonetext[DNS_NAME_MAXTEXT + 32];

	if (!isc_log_wouldlog(dns_lctx, level)) {
		return;
	}

	dns_zone_name(xfr->zone, zonetext, sizeof(zonetext));

	va_start(ap, fmt);
	xfrin_logv(xfr, level, zonetext, &xfr->primaryaddr, fmt, ap);
	va_end(ap);
}
