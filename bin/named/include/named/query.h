/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: query.h,v 1.17 2000/06/22 21:49:50 tale Exp $ */

#ifndef NAMED_QUERY_H
#define NAMED_QUERY_H 1

#include <isc/types.h>
#include <isc/buffer.h>

#include <dns/types.h>
#include <dns/a6.h>

#include <named/types.h>

typedef struct ns_dbversion {
	dns_db_t			*db;
	dns_dbversion_t			*version;
	isc_boolean_t			queryok;
	ISC_LINK(struct ns_dbversion)	link;
} ns_dbversion_t;

struct ns_query {
	unsigned int			attributes;
	unsigned int			restarts;
	dns_name_t *			qname;
	dns_name_t *			origqname;
	dns_rdataset_t *		qrdataset;
	unsigned int			dboptions;
	dns_db_t *			gluedb;
	dns_fetch_t *			fetch;
	dns_a6context_t			a6ctx;
	isc_bufferlist_t		namebufs;
	ISC_LIST(ns_dbversion_t)	activeversions;
	ISC_LIST(ns_dbversion_t)	freeversions;
};

#define NS_QUERYATTR_RECURSIONOK	0x01
#define NS_QUERYATTR_CACHEOK		0x02
#define NS_QUERYATTR_PARTIALANSWER	0x04
#define NS_QUERYATTR_NAMEBUFUSED	0x08
#define NS_QUERYATTR_RECURSING		0x10
#define NS_QUERYATTR_CACHEGLUEOK	0x20
#define NS_QUERYATTR_QUERYOKVALID	0x40
#define NS_QUERYATTR_QUERYOK		0x80

isc_result_t
ns_query_init(ns_client_t *client);

void
ns_query_free(ns_client_t *client);

void
ns_query_start(ns_client_t *client);

#endif /* NAMED_QUERY_H */
