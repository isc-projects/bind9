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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/result.h>
#include <isc/socket.h>
#include <isc/timer.h>
#include <isc/app.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/compress.h>
#include <dns/db.h>
#include <dns/dbtable.h>
#include <dns/message.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "confparser.h"
#include "udpclient.h"
#include "tcpclient.h"
#include "interfacemgr.h"

typedef struct dbinfo {
	dns_db_t *		db;
	ISC_LINK(struct dbinfo)	link;
} dbinfo;

isc_mem_t *			mctx;
isc_boolean_t			want_stats = ISC_FALSE;
static char			dbtype[128];
static dns_dbtable_t *		dbtable;
static ISC_LIST(dbinfo)		dbs;
static dbinfo *			cache_dbi;

static inline isc_boolean_t
CHECKRESULT(dns_result_t result, char *msg)
{
	if ((result) != DNS_R_SUCCESS) {
		printf("%s: %s\n", (msg), dns_result_totext(result));
		return (ISC_TRUE);
	}

	return (ISC_FALSE);
}

/*
 * This is in bin/tests/wire_test.c, but should be in a debugging library.
 */
extern dns_result_t
printmessage(dns_message_t *);

#define MAX_RDATASETS 25

static dns_result_t
resolve_packet(isc_mem_t *mctx, dns_message_t *query, isc_buffer_t *target) {
	dns_message_t *message;
	dns_result_t result, dbresult;
	dns_name_t *qname, *fname;
	dns_fixedname_t foundname;
	dns_rdataset_t *rds, *rdataset, rdatasets[MAX_RDATASETS];
	unsigned int nrdatasets = 0;
	dns_dbnode_t *node;
	dns_db_t *db;
	dns_rdatasetiter_t *rdsiter;
	dns_rdatatype_t type;
	isc_boolean_t possibly_auth = ISC_FALSE;

	message = NULL;
	result = dns_message_create(mctx, &message, DNS_MESSAGE_INTENTRENDER);
	CHECKRESULT(result, "dns_message_create failed");

	message->id = query->id;
	message->rcode = dns_rcode_noerror;
	message->flags = query->flags;
	message->flags |= DNS_MESSAGEFLAG_QR;

	/*
	 * XXX This is a total and disgusting hack.  We need a way to add
	 * a copy of a rdataset and a name to the new message, but for now
	 * I'll just steal the one from the existing query message, and
	 * make certain the query is not destroyed before our message is.
	 */
	result = dns_message_firstname(query, DNS_SECTION_QUESTION);
	if (result != DNS_R_SUCCESS)
		return (result);
	qname = NULL;
	dns_message_currentname(query, DNS_SECTION_QUESTION, &qname);
	rds = ISC_LIST_HEAD(qname->list);
	if (rds == NULL)
		return (DNS_R_UNEXPECTED);
	type = rds->type;

	ISC_LIST_UNLINK(query->sections[DNS_SECTION_QUESTION], qname, link);
	dns_message_addname(message, qname, DNS_SECTION_QUESTION);

	result = printmessage(message);
	INSIST(result == DNS_R_SUCCESS);  /* XXX not in a real server */

	/*
	 * Find a database to answer the query from.
	 */
	db = NULL;
	result = dns_dbtable_find(dbtable, qname, &db);
	if (result != DNS_R_SUCCESS && result != DNS_R_PARTIALMATCH) {
		printf("could not find a dbtable: %s\n",
		       dns_result_totext(result));
		message->rcode = dns_rcode_servfail;
		goto render;
	}
	
	/*
	 * Now look for an answer in the database.
	 */
	dns_fixedname_init(&foundname);
	fname = dns_fixedname_name(&foundname);
	rdataset = &rdatasets[nrdatasets++];
	dns_rdataset_init(rdataset);
	node = NULL;
	dbresult = dns_db_find(db, qname, NULL, type, 0, 0, &node, fname,
			       rdataset);
	switch (dbresult) {
	case DNS_R_SUCCESS:
	case DNS_R_DNAME:
	case DNS_R_CNAME:
		possibly_auth = ISC_TRUE;
		break;
	case DNS_R_GLUE:
	case DNS_R_ZONECUT:
	case DNS_R_DELEGATION:
		break;
	case DNS_R_NXRDATASET:
		if (dns_db_iszone(db))
			message->flags |= DNS_MESSAGEFLAG_AA;
		dns_db_detachnode(db, &node);
		dns_db_detach(&db);
                goto render;
	case DNS_R_NXDOMAIN:
		if (dns_db_iszone(db))
			message->flags |= DNS_MESSAGEFLAG_AA;
		dns_db_detach(&db);
                message->rcode = dns_rcode_nxdomain;
                goto render;
	default:
		printf("%s\n", dns_result_totext(result));
		dns_db_detach(&db);
                message->rcode = dns_rcode_servfail;
                goto render;
	}

	if (dbresult == DNS_R_DELEGATION) {
		ISC_LIST_APPEND(fname->list, rdataset, link);
		dns_message_addname(message, fname, DNS_SECTION_AUTHORITY);
	} else if (type == dns_rdatatype_any) {
		rdsiter = NULL;
		result = dns_db_allrdatasets(db, node, NULL, 0, &rdsiter);
		if (result == DNS_R_SUCCESS)
			result = dns_rdatasetiter_first(rdsiter);
		while (result == DNS_R_SUCCESS) {
			dns_rdatasetiter_current(rdsiter, rdataset);
			ISC_LIST_APPEND(fname->list, rdataset, link);
			if (nrdatasets == MAX_RDATASETS) {
				result = DNS_R_NOSPACE;
			} else {
				rdataset = &rdatasets[nrdatasets++];
				dns_rdataset_init(rdataset);
				result = dns_rdatasetiter_next(rdsiter);
			}
		}
		if (result != DNS_R_NOMORE) {
			dns_db_detachnode(db, &node);
			dns_db_detach(&db);
			message->rcode = dns_rcode_servfail;
			goto render;
		}
		dns_message_addname(message, fname, DNS_SECTION_ANSWER);
	} else {
		ISC_LIST_APPEND(fname->list, rdataset, link);
		dns_message_addname(message, fname, DNS_SECTION_ANSWER);
	}

	if (dns_db_iszone(db) && possibly_auth)
		message->flags |= DNS_MESSAGEFLAG_AA;

	dns_db_detachnode(db, &node);
	dns_db_detach(&db);

 render:

	result = dns_message_renderbegin(message, target);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_QUESTION,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_ANSWER,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_AUTHORITY,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_ADDITIONAL,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_rendersection(message, DNS_SECTION_TSIG,
					   0, 0);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_message_renderend(message);

	dns_message_destroy(&message);

	return (DNS_R_SUCCESS);
}

/*
 * Process the wire format message given in r, and return a new packet to
 * transmit.
 *
 * Return of DNS_R_SUCCESS means r->base is a newly allocated region of
 * memory, and r->length is its length.  The actual for-transmit packet
 * begins at (r->length + reslen) to reserve (reslen) bytes at the front
 * of the packet for transmission specific details.
 */
static dns_result_t
dispatch(isc_mem_t *mctx, isc_region_t *rxr, unsigned int reslen)
{
	char t[512];
	isc_buffer_t source;
	isc_buffer_t target;
	dns_result_t result;
	isc_region_t txr;
	dns_message_t *message;

	/*
	 * Set up the input buffer from the contents of the region passed
	 * to us.
	 */
	isc_buffer_init(&source, rxr->base, rxr->length,
			ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, rxr->length);

	message = NULL;
	result = dns_message_create(mctx, &message, DNS_MESSAGE_INTENTPARSE);
	if (CHECKRESULT(result, "dns_message_create failed")) {
		return (result);
	}

	result = dns_message_parse(message, &source);
	if (CHECKRESULT(result, "dns_message_parsed failed")) {
		dns_message_destroy(&message);
		return (result);
	}
	CHECKRESULT(result, "dns_message_parse failed");

	result = printmessage(message);
	if (CHECKRESULT(result, "printmessage failed")) {
		dns_message_destroy(&message);
		return (result);
	}

	isc_buffer_init(&target, t, sizeof(t), ISC_BUFFERTYPE_BINARY);
	result = resolve_packet(mctx, message, &target);
	if (result != DNS_R_SUCCESS) {
		dns_message_destroy(&message);
		return (result);
	}

	/*
	 * Copy the reply out, adjusting for reslen
	 */
	isc_buffer_used(&target, &txr);
	txr.base = isc_mem_get(mctx, txr.length + reslen);
	if (txr.base == NULL) {
		dns_message_destroy(&message);

		return (DNS_R_NOMEMORY);
	}

	memcpy(txr.base + reslen, t, txr.length);
	rxr->base = txr.base;
	rxr->length = txr.length + reslen;

	printf("Base == %p, length == %u\n", txr.base, txr.length);
	fflush(stdout);

	if (want_stats)
		isc_mem_stats(mctx, stdout);

	dns_message_destroy(&message);

	return (DNS_R_SUCCESS);
}

static dns_result_t
load(char *filename, char *origintext, isc_boolean_t cache) {
	dns_fixedname_t forigin;
	dns_name_t *origin;
	dns_result_t result;
	isc_buffer_t source;
	size_t len;
	dbinfo *dbi;

	dbi = isc_mem_get(mctx, sizeof *dbi);
	if (dbi == NULL)
		return (DNS_R_NOMEMORY);
	dbi->db = NULL;
	
	len = strlen(origintext);
	isc_buffer_init(&source, origintext, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	result = dns_name_fromtext(origin, &source, dns_rootname, ISC_FALSE,
				   NULL);
	if (result != DNS_R_SUCCESS)
		return (result);

	result = dns_db_create(mctx, dbtype, origin, cache, dns_rdataclass_in,
			       0, NULL, &dbi->db);
	if (result != DNS_R_SUCCESS) {
		isc_mem_put(mctx, dbi, sizeof *dbi);
		return (result);
	}

	printf("loading %s (%s)\n", filename, origintext);
	result = dns_db_load(dbi->db, filename);
	if (result != DNS_R_SUCCESS) {
		dns_db_detach(&dbi->db);
		isc_mem_put(mctx, dbi, sizeof *dbi);
		return (result);
	}
	printf("loaded\n");

	if (cache) {
		INSIST(cache_dbi == NULL);
		dns_dbtable_adddefault(dbtable, dbi->db);
		cache_dbi = dbi;
	} else {
		if (dns_dbtable_add(dbtable, dbi->db) != DNS_R_SUCCESS) {
			dns_db_detach(&dbi->db);
			isc_mem_put(mctx, dbi, sizeof *dbi);
			return (result);
		}
	}
	ISC_LIST_APPEND(dbs, dbi, link);

	return (DNS_R_SUCCESS);
}

static void
unload_all(void) {
	dbinfo *dbi, *dbi_next;
	
	for (dbi = ISC_LIST_HEAD(dbs); dbi != NULL; dbi = dbi_next) {
		dbi_next = ISC_LIST_NEXT(dbi, link);
		if (dns_db_iszone(dbi->db))
			dns_dbtable_remove(dbtable, dbi->db);
		else {
			INSIST(dbi == cache_dbi);
			dns_dbtable_removedefault(dbtable);
			cache_dbi = NULL;
		}
		dns_db_detach(&dbi->db);
		ISC_LIST_UNLINK(dbs, dbi, link);
		isc_mem_put(mctx, dbi, sizeof *dbi);
	}
}

int
main(int argc, char *argv[])
{
	isc_taskmgr_t *manager = NULL;
	unsigned int workers;
	isc_socketmgr_t *socketmgr;
	isc_sockaddr_t sockaddr;
	unsigned int addrlen;
	int ch;
	char *origintext;
	dns_result_t result;
	isc_result_t iresult;
	ns_interfacemgr_t *ifmgr = NULL;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

#if 0 /* brister */
	isc_cfgctx_t *configctx = NULL;
	const char *conffile = "/etc/named.conf"; /* XXX hardwired */
#endif

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_dbtable_create(mctx, dns_rdataclass_in, &dbtable) ==
		      DNS_R_SUCCESS);
	strcpy(dbtype, "rbt");

	/*+ XXX */
	while ((ch = getopt(argc, argv, "c:d:z:s")) != -1) {
		switch (ch) {
		case 'c':
			result = load(optarg, ".", ISC_TRUE);
			if (result != DNS_R_SUCCESS)
				printf("%s\n", dns_result_totext(result));
			break;
		case 'd':
			strcpy(dbtype, optarg);
			break;
		case 'z':
			origintext = strrchr(optarg, '/');
			if (origintext == NULL)
				origintext = optarg;
			else
				origintext++;	/* Skip '/'. */
			result = load(optarg, origintext, ISC_FALSE);
			if (result != DNS_R_SUCCESS)
				printf("%s\n", dns_result_totext(result));
			break;
		case 's':
			want_stats = ISC_TRUE;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		fprintf(stderr, "ignoring extra command line arguments\n");

	/*- XXX */

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.type.sin.sin_port = htons(5544);
	addrlen = sizeof(struct sockaddr_in);

	workers = 2;
	printf("%d workers\n", workers);

#if 0 /* brister */
	parser_init();
	RUNTIME_CHECK(parse_configuration(conffile, mctx, &configctx) ==
		      ISC_R_SUCCESS);
#endif

	RUNTIME_CHECK(isc_taskmgr_create(mctx, workers, 0, &manager) ==
		      ISC_R_SUCCESS);

	socketmgr = NULL;
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	result = ns_interfacemgr_create(mctx, manager, socketmgr, dispatch, &ifmgr);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = ns_interfacemgr_scan(ifmgr);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	if (want_stats)
		isc_mem_stats(mctx, stdout);

	/*
	 * Block until shutdown is requested.
	 */
	iresult = isc_app_run();
	if (iresult != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_app_run(): %s",
				 isc_result_totext(iresult));

	printf("Destroying network interface manager\n");
	ns_interfacemgr_destroy(&ifmgr);

	printf("Destroying task manager\n");
	isc_taskmgr_destroy(&manager);

	printf("Destroying socket manager\n");
	isc_socketmgr_destroy(&socketmgr);

	printf("Unloading\n");
	unload_all();
	dns_dbtable_detach(&dbtable);

	if (want_stats)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}
