/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

 /* $Id: xfrin.c,v 1.13 1999/10/14 01:36:59 halley Exp $ */

#include <config.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/timer.h>
#include <isc/net.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/zone.h>
#include <dns/message.h>
#include <dns/tcpmsg.h>
#include <dns/events.h>
#include <dns/journal.h>
#include <dns/view.h>
#include <dns/tsig.h>
#include <dns/zone.h>
#include <dns/zt.h>

#include <named/globals.h>
#include <named/xfrin.h>

/*
 * Incoming AXFR and IXFR.
 */

#define FAIL(code) do { result = (code); goto failure; } while (0)
#define CHECK(op) do { result = (op); \
		       if (result != DNS_R_SUCCESS) goto failure; \
		     } while (0)


#define DNS_R_NOTLOADED DNS_R_NOTFOUND /* XXX temporary */

typedef struct xfrin_ctx xfrin_ctx_t;

/*
 * The states of the *XFR state machine.  We handle both IXFR and AXFR
 * with a single integrated state machine because they cannot be distinguished
 * immediately - an AXFR response to an IXFR request can only be detected
 * when the first two (2) response RRs have already been received.
 */
typedef enum {
	XFRST_INITIALSOA,
	XFRST_FIRSTDATA,
	XFRST_IXFR_DELSOA,
	XFRST_IXFR_DEL,
	XFRST_IXFR_ADDSOA,
	XFRST_IXFR_ADD,
	XFRST_AXFR,
	XFRST_END
} xfrin_state_t;

/*
 * Incoming zone transfer context.
 */

struct xfrin_ctx {
	isc_mem_t		*mctx;
	dns_zone_t		*zone;

	isc_task_t 		*task;
	isc_timer_t		*timer;
	isc_socketmgr_t 	*socketmgr;

	int			recvs;	/* Number of receives in progress */
	int			tasks;	/* Number of active tasks (0 or 1) */
	
	dns_name_t 		name; 	/* Name of zone to transfer */
	dns_rdataclass_t 	rdclass;

	/*
	 * Requested transfer type (dns_rdatatype_axfr or
	 * dns_rdatatype_ixfr).  The actual transfer type
	 * may differ due to IXFR->AXFR fallback.
	 */
	dns_rdatatype_t 	reqtype;

	isc_sockaddr_t 		sockaddr;
	isc_socket_t 		*socket;

	/* Buffer for IXFR/AXFR request message */
	isc_buffer_t 		qbuffer;
	unsigned char 		qbuffer_data[512];

	/* Incoming reply TCP message */
	dns_tcpmsg_t		tcpmsg;
	isc_boolean_t		tcpmsg_valid;

	dns_db_t 		*db;
	dns_dbversion_t 	*ver;
	dns_diff_t 		diff;		/* Pending database changes */
	int 			difflen;	/* Number of pending tuples */
	
	xfrin_state_t 		state;
	isc_uint32_t 		end_serial;
	isc_boolean_t 		is_ixfr;

	unsigned int		nmsg;		/* Number of messages recvd */

	dns_tsigkey_t		*tsigkey;	/* Key used to create TSIG */
	dns_rdata_any_tsig_t	*lasttsig;	/* The last TSIG */
	void			*tsigctx;	/* TSIG verification context */
	unsigned int		sincetsig;	/* recvd since the last TSIG */

	/*
	 * AXFR- and IXFR-specific data.  Only one is used at a time
	 * according to the is_ixfr flag, so this could be a union, 
	 * but keeping them separate makes it a bit simpler to clean 
	 * things up when destroying the context.
	 */
	struct {
		dns_addrdatasetfunc_t add_func;
		dns_dbload_t	      *add_private;
	} axfr;
	
	struct {
		isc_uint32_t 	request_serial;
		isc_uint32_t 	end_serial;
		dns_journal_t 	*journal;
		
	} ixfr;
};

/**************************************************************************/
/*
 * Forward declarations.
 */

static dns_result_t
xfrin_create(isc_mem_t *mctx,
	     dns_zone_t *zone,
	     dns_db_t *db,
	     isc_task_t *task,
	     isc_socketmgr_t *socketmgr,
	     dns_name_t *zonename,
	     dns_rdataclass_t rdclass,
	     dns_rdatatype_t reqtype,
	     isc_sockaddr_t *master,
	     dns_tsigkey_t *tsigkey,
	     xfrin_ctx_t **xfrp);

static dns_result_t axfr_init(xfrin_ctx_t *xfr);
static dns_result_t axfr_makedb(xfrin_ctx_t *xfr, dns_db_t **dbp);
static dns_result_t axfr_putdata(xfrin_ctx_t *xfr, dns_diffop_t op,
				   dns_name_t *name, dns_ttl_t ttl,
				   dns_rdata_t *rdata);
static dns_result_t axfr_apply(xfrin_ctx_t *xfr);
static dns_result_t axfr_commit(xfrin_ctx_t *xfr);

static dns_result_t ixfr_init(xfrin_ctx_t *xfr);
static dns_result_t ixfr_apply(xfrin_ctx_t *xfr);
static dns_result_t ixfr_putdata(xfrin_ctx_t *xfr, dns_diffop_t op,
				 dns_name_t *name, dns_ttl_t ttl,
				 dns_rdata_t *rdata);
static dns_result_t ixfr_commit(xfrin_ctx_t *xfr);

static dns_result_t xfr_rr(xfrin_ctx_t *xfr, dns_name_t *name,
			   isc_uint32_t ttl, dns_rdata_t *rdata);

void xfrin_start(xfrin_ctx_t *xfr);

static void xfrin_connect_done(isc_task_t *task, isc_event_t *event);
static dns_result_t xfrin_send_request(xfrin_ctx_t *xfr);
static void xfrin_send_done(isc_task_t *task, isc_event_t *event);
static void xfrin_sendlen_done(isc_task_t *task, isc_event_t *event);
static void xfrin_recv_done(isc_task_t *task, isc_event_t *event);
static void xfrin_timeout(isc_task_t *task, isc_event_t *event);
static void xfrin_shutdown(isc_task_t *task, isc_event_t *event);

static isc_boolean_t maybe_free(xfrin_ctx_t *xfr);

static void xfrin_fail(xfrin_ctx_t *xfr, isc_result_t result, char *msg);
static dns_result_t render(dns_message_t *msg, isc_buffer_t *buf);

/**************************************************************************/
/*
 * AXFR handling
 */

static dns_result_t
axfr_init(xfrin_ctx_t *xfr) {
	dns_result_t result;
 	xfr->is_ixfr = ISC_FALSE;

	if (xfr->db != NULL)
		dns_db_detach(&xfr->db);

	CHECK(axfr_makedb(xfr, &xfr->db));
	CHECK(dns_db_beginload(xfr->db, &xfr->axfr.add_func,
			       &xfr->axfr.add_private));
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

static dns_result_t
axfr_makedb(xfrin_ctx_t *xfr, dns_db_t **dbp) {
	return (dns_db_create(xfr->mctx, /* XXX */
			      "rbt", /* XXX guess */
			      &xfr->name,
			      ISC_FALSE,
			      xfr->rdclass,
			      0, NULL, /* XXX guess */
			      dbp));
}

static dns_result_t
axfr_putdata(xfrin_ctx_t *xfr, dns_diffop_t op,
	     dns_name_t *name, dns_ttl_t ttl, dns_rdata_t *rdata)
{
	dns_result_t result;
	dns_difftuple_t *tuple = NULL;
	CHECK(dns_difftuple_create(xfr->diff.mctx, op,
				   name, ttl, rdata, &tuple));
	dns_diff_append(&xfr->diff, &tuple);
	if (++xfr->difflen > 100)
		CHECK(axfr_apply(xfr));
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

/* Store a set of AXFR RRs in the database. */
static dns_result_t
axfr_apply(xfrin_ctx_t *xfr) {
	dns_result_t result;
        CHECK(dns_diff_load(&xfr->diff,
			    xfr->axfr.add_func, xfr->axfr.add_private));
	xfr->difflen = 0;
	dns_diff_clear(&xfr->diff);
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

static dns_result_t
axfr_commit(xfrin_ctx_t *xfr) {
	dns_result_t result;

	CHECK(axfr_apply(xfr));
	CHECK(dns_db_endload(xfr->db, &xfr->axfr.add_private));
	CHECK(dns_zone_replacedb(xfr->zone, xfr->db, ISC_TRUE));

	result = ISC_R_SUCCESS;
 failure:
	printf("axfr_commit returns status %s\n", isc_result_totext(result));
	return (result);
}

/**************************************************************************/
/*
 * IXFR handling
 */

static dns_result_t
ixfr_init(xfrin_ctx_t *xfr) {
	dns_result_t result;
	xfr->is_ixfr = ISC_TRUE;
	INSIST(xfr->db != NULL);
	xfr->difflen = 0;
        CHECK(dns_journal_open(xfr->mctx, dns_zone_getixfrlog(xfr->zone),
			       ISC_TRUE, &xfr->ixfr.journal));
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

static dns_result_t
ixfr_putdata(xfrin_ctx_t *xfr, dns_diffop_t op,
	     dns_name_t *name, dns_ttl_t ttl, dns_rdata_t *rdata)
{
	dns_result_t result;
	dns_difftuple_t *tuple = NULL;
	CHECK(dns_difftuple_create(xfr->diff.mctx, op,
				   name, ttl, rdata, &tuple));
	dns_diff_append(&xfr->diff, &tuple);
	if (++xfr->difflen > 100)
		CHECK(ixfr_apply(xfr));
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

/* Apply a set of IXFR changes to the database. */
static dns_result_t
ixfr_apply(xfrin_ctx_t *xfr) {
	dns_result_t result;
	if (xfr->ver == NULL) {
		CHECK(dns_db_newversion(xfr->db, &xfr->ver));
		CHECK(dns_journal_begin_transaction(xfr->ixfr.journal));
	}
        CHECK(dns_diff_apply(&xfr->diff, xfr->db, xfr->ver));
	dns_journal_writediff(xfr->ixfr.journal, &xfr->diff);
	dns_diff_clear(&xfr->diff);
	xfr->difflen = 0;
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

static dns_result_t
ixfr_commit(xfrin_ctx_t *xfr) {
	dns_result_t result;
	ixfr_apply(xfr);
	if (xfr->ver != NULL) {
		/* XXX enter ready-to-commit state here */
		CHECK(dns_journal_commit(xfr->ixfr.journal));
		dns_db_closeversion(xfr->db, &xfr->ver, ISC_TRUE);
	}
	result = DNS_R_SUCCESS;
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
static dns_result_t
xfr_rr(xfrin_ctx_t *xfr,
       dns_name_t *name, isc_uint32_t ttl, dns_rdata_t *rdata)
{
	dns_result_t result;
 redo:
	switch (xfr->state) {
	case XFRST_INITIALSOA:
		INSIST(rdata->type == dns_rdatatype_soa);
		/*
		 * Remember the serial number in the intial SOA.
		 * We need it to recognize the end of an IXFR.
		 */
		xfr->end_serial = dns_soa_getserial(rdata);
		if (xfr->reqtype == dns_rdatatype_ixfr &&
		    ! DNS_SERIAL_GT(xfr->end_serial, xfr->ixfr.request_serial))
		{
			/*
			 * This must be the single SOA record that is
			 * sent when the current version on the master
			 * is not newer than the version in the request.
			 */
			printf("requested %u, master has %u, not updating\n",
			       xfr->ixfr.request_serial, xfr->end_serial);
			FAIL(DNS_R_UPTODATE);
		}
		xfr->state = XFRST_FIRSTDATA;
		break;
		
	case XFRST_FIRSTDATA:
		/*
		 * If the transfer begins with one SOA record, it is an AXFR,
		 * if it begins with two SOAs, it is an IXFR.
		 */
		if (rdata->type == dns_rdatatype_soa) {
			CHECK(ixfr_init(xfr));
			xfr->state = XFRST_IXFR_DELSOA;
		} else {
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
			isc_uint32_t soa_serial = dns_soa_getserial(rdata);
			xfr->state = XFRST_IXFR_ADDSOA;
			xfr->ixfr.end_serial = soa_serial;
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
			isc_uint32_t soa_serial = dns_soa_getserial(rdata);
			CHECK(ixfr_commit(xfr));
			if (soa_serial == xfr->end_serial) {
				xfr->state = XFRST_END;
				break;
			} else {
				xfr->state = XFRST_IXFR_DELSOA;
				goto redo;
			}
		}
		CHECK(ixfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		break;

	case XFRST_AXFR:
		CHECK(axfr_putdata(xfr, DNS_DIFFOP_ADD, name, ttl, rdata));
		if (rdata->type == dns_rdatatype_soa) {
			CHECK(axfr_commit(xfr));
			xfr->state = XFRST_END;
			break;
		}
		break;
	case XFRST_END:
		FAIL(DNS_R_EXTRADATA);
		break;
	default:
		INSIST(0);
		break;
	}
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

void
ns_xfrin_start(dns_zone_t *zone, isc_sockaddr_t *master) {
	dns_name_t zonename;
	isc_task_t *task;
	xfrin_ctx_t *xfr;
	dns_result_t result;
	dns_db_t *db = NULL;
	dns_rdatatype_t xfrtype;
	dns_tsigkey_t *key = NULL;
	
	printf("attempting zone transfer\n");

	dns_name_init(&zonename, NULL);
	CHECK(dns_zone_getorigin(zone, xfr->mctx, &zonename));
	result = dns_zone_getdb(zone, &db);
	if (result == DNS_R_NOTLOADED)
		INSIST(db == NULL);
	else
		CHECK(result);

	task = NULL;
	RUNTIME_CHECK(isc_task_create(ns_g_taskmgr, ns_g_mctx, 0, &task)
		      == DNS_R_SUCCESS);
	
	if (db == NULL) {
		printf("no database exists, trying to create with axfr\n");
		xfrtype = dns_rdatatype_axfr;
	} else {
		printf("database exists, trying ixfr\n");
		xfrtype = dns_rdatatype_ixfr;
	}

	CHECK(xfrin_create(ns_g_mctx,
			   zone,
			   db,
			   task,
			   ns_g_socketmgr,
			   &zonename,
			   dns_rdataclass_in, xfrtype,
			   master, key, &xfr));

	dns_name_free(&zonename, ns_g_mctx);
		
	xfrin_start(xfr);
	return;
	
 failure:
	if (zonename.ndata != NULL)
		dns_name_free(&zonename, ns_g_mctx);
	printf("zone transfer setup failed\n");
	return;
}

static void xfrin_cleanup(xfrin_ctx_t *xfr) {
	printf("end of zone transfer - destroying task %p\n", xfr->task);
	isc_socket_cancel(xfr->socket, xfr->task, ISC_SOCKSHUT_ALL); /* XXX? */
	isc_socket_detach(&xfr->socket);
	isc_timer_detach(&xfr->timer);
	isc_task_destroy(&xfr->task);
	if (xfr->lasttsig != NULL) {
		dns_rdata_freestruct(xfr->lasttsig);
		isc_mem_put(xfr->mctx, xfr->lasttsig, sizeof(*xfr->lasttsig));
	}
	/* The rest will be done when the task runs its shutdown event. */
}

static void
xfrin_fail(xfrin_ctx_t *xfr, isc_result_t result, char *msg) {
	if (result != DNS_R_UPTODATE) {
		printf("error in incoming zone transfer: %s: %s\n",
		       msg, isc_result_totext(result));
	}
	xfrin_cleanup(xfr);
}

static dns_result_t
xfrin_create(isc_mem_t *mctx,
	     dns_zone_t *zone,
	     dns_db_t *db,
	     isc_task_t *task,
	     isc_socketmgr_t *socketmgr,
	     dns_name_t *zonename,
	     dns_rdataclass_t rdclass,
	     dns_rdatatype_t reqtype,
	     isc_sockaddr_t *master,
	     dns_tsigkey_t *tsigkey,
	     xfrin_ctx_t **xfrp)
{
	xfrin_ctx_t *xfr = NULL;
	isc_result_t result;
	isc_interval_t interval;
	
	xfr = isc_mem_get(mctx, sizeof(*xfr));
	if (xfr == NULL)
		return (DNS_R_NOMEMORY);
	xfr->mctx = mctx;
	xfr->zone = NULL;
	dns_zone_attach(zone, &xfr->zone);
	xfr->task = task;
	xfr->timer = NULL;
	xfr->socketmgr = socketmgr;

	xfr->recvs = 0;
	xfr->tasks = 1;
	
	dns_name_init(&xfr->name, NULL);
	xfr->rdclass = rdclass;
	xfr->reqtype = reqtype;

	/* sockaddr */
	xfr->socket = NULL;
	/* qbuffer */
	/* qbuffer_data */
	/* tcpmsg */
	xfr->tcpmsg_valid = ISC_FALSE;

	xfr->db = db;
	xfr->ver = NULL;
	dns_diff_init(xfr->mctx, &xfr->diff);
	xfr->difflen = 0;

	xfr->state = XFRST_INITIALSOA;
	/* end_serial */

	xfr->nmsg = 0;

	xfr->tsigkey = tsigkey;
	xfr->lasttsig = NULL;
	xfr->tsigctx = NULL;
	xfr->sincetsig = 0;

	/* is_ixfr */

	/* ixfr.request_serial */
	/* ixfr.end_serial */
	xfr->ixfr.journal = NULL;

	xfr->axfr.add_func = NULL;
	xfr->axfr.add_private = NULL;

	isc_task_onshutdown(xfr->task, xfrin_shutdown, xfr);
	
	CHECK(dns_name_dup(zonename, mctx, &xfr->name));

	isc_interval_set(&interval, 3600, 0); /* XXX */
	CHECK(isc_timer_create(ns_g_timermgr, isc_timertype_once,
			       NULL, &interval, task,
			       xfrin_timeout, xfr, &xfr->timer));

	xfr->sockaddr = *master;

	isc_buffer_init(&xfr->qbuffer, xfr->qbuffer_data,
			sizeof(xfr->qbuffer_data),
			ISC_BUFFERTYPE_BINARY);

	*xfrp = xfr;
	return (DNS_R_SUCCESS);
	
 failure:
	xfrin_cleanup(xfr);
	return (result);
}

void
xfrin_start(xfrin_ctx_t *xfr) {
	dns_result_t result;
	CHECK(isc_socket_create(xfr->socketmgr,
				isc_sockaddr_pf(&xfr->sockaddr),
				isc_sockettype_tcp,
				&xfr->socket));
	CHECK(isc_socket_connect(xfr->socket, &xfr->sockaddr, xfr->task,
				 xfrin_connect_done, xfr));
	return;
 failure:
	xfrin_fail(xfr, result, "setting up socket");
}

/* XXX the resolver could use this, too */

static dns_result_t
render(dns_message_t *msg, isc_buffer_t *buf) {
	dns_result_t result;
	CHECK(dns_message_renderbegin(msg, buf));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_QUESTION, 0, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_ANSWER, 0, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_AUTHORITY, 0, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_ADDITIONAL, 0, 0));
	CHECK(dns_message_rendersection(msg, DNS_SECTION_TSIG, 0, 0));
	CHECK(dns_message_renderend(msg));
	result = DNS_R_SUCCESS;
 failure:
	return (result);
}

/*
 * A connection has been established.
 */
static void
xfrin_connect_done(isc_task_t *task, isc_event_t *event) {
	isc_socket_connev_t *cev = (isc_socket_connev_t *) event;
	xfrin_ctx_t *xfr = (xfrin_ctx_t *) event->arg;
	dns_result_t result;
	task = task; /* Unused */
	INSIST(event->type == ISC_SOCKEVENT_CONNECT);
	
	printf("connected\n");
	CHECK(cev->result);

	dns_tcpmsg_init(xfr->mctx, xfr->socket, &xfr->tcpmsg);
	xfr->tcpmsg_valid = ISC_TRUE;

	CHECK(xfrin_send_request(xfr));
	
	isc_event_free(&event);
	return;

 failure:
	isc_event_free(&event);
	xfrin_fail(xfr, result, "connecting"); 
}

/*
 * Build an *XFR request and send its length prefix.
 */
static dns_result_t
xfrin_send_request(xfrin_ctx_t *xfr) {
	dns_result_t result;
	isc_region_t region;
	isc_region_t lregion;
	dns_rdataset_t qrdataset;
	dns_message_t *msg = NULL;
	unsigned char length[2];
	dns_rdatalist_t soardl;
	dns_rdataset_t soards;
	dns_difftuple_t *soatuple = NULL;
	
	dns_rdataset_init(&qrdataset);
	dns_rdataset_makequestion(&qrdataset, xfr->rdclass, xfr->reqtype);
	ISC_LIST_INIT(xfr->name.list);
	ISC_LIST_APPEND(xfr->name.list, &qrdataset, link);
	
	CHECK(dns_message_create(xfr->mctx, DNS_MESSAGE_INTENTRENDER, &msg));
	msg->tsigkey = xfr->tsigkey;
	dns_message_addname(msg, &xfr->name, DNS_SECTION_QUESTION);

	if (xfr->reqtype == dns_rdatatype_ixfr) {
		/* Get the SOA. */
		/* XXX is using the current version the right thing? */
		dns_dbversion_t *ver = NULL;
		dns_db_currentversion(xfr->db, &ver);
		dns_db_createsoatuple(xfr->db, ver, xfr->mctx,
				      DNS_DIFFOP_EXISTS, &soatuple);
		xfr->ixfr.request_serial = dns_soa_getserial(&soatuple->rdata);
		dns_db_closeversion(xfr->db, &ver, ISC_FALSE);

		printf("requesting IXFR for serial %u\n",
			       xfr->ixfr.request_serial);

		/* Create a dns_rdatalist_t */
		soardl.type = soatuple->rdata.type;
		soardl.rdclass = soatuple->rdata.rdclass;
		soardl.ttl = soatuple->ttl;
		ISC_LIST_INIT(soardl.rdata);
		ISC_LINK_INIT(&soardl, link);
		ISC_LIST_APPEND(soardl.rdata, &soatuple->rdata, link);

		dns_rdataset_init(&soards);
		result = dns_rdatalist_tordataset(&soardl, &soards);
		INSIST(result == DNS_R_SUCCESS);
		ISC_LIST_APPEND(soatuple->name.list, &soards, link);

		dns_message_addname(msg, &soatuple->name,
				    DNS_SECTION_AUTHORITY);
	}

	msg->id = ('b' << 8) | '9'; /* Arbitrary */

	CHECK(render(msg, &xfr->qbuffer));

	/* Save the query TSIG and don't let message_destroy free it */
	xfr->lasttsig = msg->tsig;
	msg->tsig = NULL;

	ISC_LIST_UNLINK(xfr->name.list, &qrdataset, link);
	dns_message_destroy(&msg); /* XXX failure */
	if (soatuple != NULL)
		dns_difftuple_free(&soatuple);

	isc_buffer_used(&xfr->qbuffer, &region);
	INSIST(region.length <= 65535);

	length[0] = region.length >> 8;
	length[1] = region.length & 0xFF;
	lregion.base = length;
	lregion.length = 2;
	CHECK(isc_socket_send(xfr->socket, &lregion, xfr->task,
			      xfrin_sendlen_done, xfr));
	return (DNS_R_SUCCESS);
	
 failure:
	if (soatuple != NULL)
		dns_difftuple_free(&soatuple);
	return (result);
}

/* XXX there should be library support for sending DNS TCP messages */

static void
xfrin_sendlen_done(isc_task_t *task, isc_event_t *event)
{
	isc_socketevent_t *sev = (isc_socketevent_t *) event;
	xfrin_ctx_t *xfr = (xfrin_ctx_t *) event->arg;
	dns_result_t result;
	isc_region_t region;

	task = task; /* Unused */
	INSIST(event->type == ISC_SOCKEVENT_SENDDONE);
	
	printf("sendlen done\n");
	CHECK(sev->result);

	isc_buffer_used(&xfr->qbuffer, &region);
	CHECK(isc_socket_send(xfr->socket, &region, xfr->task,
			      xfrin_send_done, xfr));
	isc_event_free(&event);
	return;
	
 failure:
	isc_event_free(&event);
	xfrin_fail(xfr, result, "sending request length prefix");
}


static void
xfrin_send_done(isc_task_t *task, isc_event_t *event)
{
	isc_socketevent_t *sev = (isc_socketevent_t *) event;
	xfrin_ctx_t *xfr = (xfrin_ctx_t *) event->arg;
	dns_result_t result;

	task = task; /* Unused */
	INSIST(event->type == ISC_SOCKEVENT_SENDDONE);
	
	printf("send done\n");
	CHECK(sev->result);

	CHECK(dns_tcpmsg_readmessage(&xfr->tcpmsg, xfr->task,
				     xfrin_recv_done, xfr));
	xfr->recvs++;
	isc_event_free(&event);
	return;
	
 failure:
	isc_event_free(&event);
	xfrin_fail(xfr, result, "sending request");
}


static void
xfrin_recv_done(isc_task_t *task, isc_event_t *ev) {
	xfrin_ctx_t *xfr = (xfrin_ctx_t *) ev->arg;
	dns_result_t result;
	dns_message_t *msg = NULL;
	dns_name_t *name;
	dns_tcpmsg_t *tcpmsg;
	
	task = task; /* Unused */
	
	INSIST(ev->type == DNS_EVENT_TCPMSG);
	tcpmsg = ev->sender;
	isc_event_free(&ev);
	
	printf("got tcp message\n");
	xfr->recvs--;
	if (maybe_free(xfr))
		return;

	CHECK(tcpmsg->result);

	CHECK(isc_timer_touch(xfr->timer));
	
	CHECK(dns_message_create(xfr->mctx, DNS_MESSAGE_INTENTPARSE, &msg));

	msg->tsigkey = xfr->tsigkey;
	msg->querytsig = xfr->lasttsig;
	msg->tsigctx = xfr->tsigctx;
	if (xfr->nmsg > 0)
		msg->tcp_continuation = 1;

	CHECK(dns_message_parse(msg, &tcpmsg->buffer, ISC_TRUE));

	if (msg->rcode != dns_rcode_noerror) {
		result = ISC_RESULTCLASS_DNSRCODE + msg->rcode; /* XXX */
		if (xfr->reqtype == dns_rdatatype_axfr)
			FAIL(result);
		printf("got %s, retrying with AXFR\n",
		       isc_result_totext(result));
		dns_message_destroy(&msg);
		xfr->reqtype = dns_rdatatype_axfr;
		CHECK(xfrin_send_request(xfr));
		return;
	}
	
	for (result = dns_message_firstname(msg, DNS_SECTION_ANSWER);
	     result == DNS_R_SUCCESS;
	     result = dns_message_nextname(msg, DNS_SECTION_ANSWER))
	{
		dns_rdataset_t *rds;
		
		name = NULL;
		dns_message_currentname(msg, DNS_SECTION_ANSWER, &name);
		for (rds = ISC_LIST_HEAD(name->list);
		     rds != NULL;
		     rds = ISC_LIST_NEXT(rds, link))
		{
			for (result = dns_rdataset_first(rds);
			     result == DNS_R_SUCCESS;
			     result = dns_rdataset_next(rds))
			{
				dns_rdata_t rdata;
				dns_rdataset_current(rds, &rdata);
				CHECK(xfr_rr(xfr, name, rds->ttl, &rdata));
			}
		}
	}
	if (result != DNS_R_NOMORE)
		goto failure;

	if (msg->tsig != NULL) {
		/* Reset the counter */
		xfr->sincetsig = 0;

		/* Free the last tsig, if there is one */
		if (xfr->lasttsig != NULL) {
			dns_rdata_freestruct(xfr->lasttsig);
			isc_mem_put(xfr->mctx, xfr->lasttsig,
				    sizeof(*xfr->lasttsig));
		}

		/* Update the last tsig pointer */
		xfr->lasttsig = msg->tsig;

		/* Reset msg->tsig so it doesn't get freed */
		msg->tsig = NULL;
	}
	else {
		xfr->sincetsig++;
		if (xfr->sincetsig > 100 || xfr->state == XFRST_END) {
			result = DNS_R_EXPECTEDTSIG;
			goto failure;
		}
	}

	/* Update the number of messages received */
	xfr->nmsg++;
	
	/* Reset msg->querytsig so it doesn't get freed */
	msg->querytsig = NULL;

	/* Copy the context back */
	xfr->tsigctx = msg->tsigctx;

	dns_message_destroy(&msg);

	if (xfr->state == XFRST_END) {
		xfrin_cleanup(xfr);
	} else {
		/* Read the next message. */
		CHECK(dns_tcpmsg_readmessage(&xfr->tcpmsg, xfr->task,
					     xfrin_recv_done, xfr));
		xfr->recvs++;
	}
	return;
	
 failure:
	if (msg != NULL) {
		msg->querytsig = NULL;
		dns_message_destroy(&msg);
	}
	xfrin_fail(xfr, result, "receving responses");
}

static void
xfrin_timeout(isc_task_t *task, isc_event_t *event) {
	xfrin_ctx_t *xfr = (xfrin_ctx_t *) event->arg;
	task = task; /* Unused */
	INSIST(event->type == ISC_TIMEREVENT_IDLE);
	isc_event_free(&event);
	xfrin_fail(xfr, ISC_R_TIMEDOUT, "giving up");
}

static void
xfrin_shutdown(isc_task_t *task, isc_event_t *event) {
	xfrin_ctx_t *xfr = (xfrin_ctx_t *) event->arg;
	task = task; /* Unused */
	INSIST(event->type == ISC_TASKEVENT_SHUTDOWN);
	isc_event_free(&event);
	printf("xfrin_shutdown task=%p\n", task);
	xfr->tasks--;
	maybe_free(xfr);
}

static isc_boolean_t
maybe_free(xfrin_ctx_t *xfr) {
	INSIST(xfr->tasks >= 0);
	INSIST(xfr->recvs >= 0);
	if (xfr->tasks != 0 || xfr->recvs != 0)
		return (ISC_FALSE);

	printf("freeing xfrin context\n");
	
	dns_diff_clear(&xfr->diff);

	if (xfr->ixfr.journal != NULL)
		dns_journal_destroy(&xfr->ixfr.journal);

	if (xfr->axfr.add_private != NULL)
		(void) dns_db_endload(xfr->db, &xfr->axfr.add_private);

	if (xfr->tcpmsg_valid)
		dns_tcpmsg_invalidate(&xfr->tcpmsg);
	
	if ((xfr->name.attributes & DNS_NAMEATTR_DYNAMIC) != 0)
		dns_name_free(&xfr->name, xfr->mctx);

	if (xfr->ver != NULL)
		dns_db_closeversion(xfr->db, &xfr->ver, ISC_FALSE);

	if (xfr->db != NULL) 
		dns_db_detach(&xfr->db);

	if (xfr->zone != NULL)
		dns_zone_detach(&xfr->zone);
		
	isc_mem_put(xfr->mctx, xfr, sizeof(*xfr));

	printf("xfrin_shutdown done\n");
	return (ISC_TRUE);
}
