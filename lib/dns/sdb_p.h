/*
 * Copyright (C) 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: sdb_p.h,v 1.1 2000/08/21 22:15:27 bwelling Exp $ */

/* $Id: sdb_p.h,v 1.1 2000/08/21 22:15:27 bwelling Exp $ */

#ifndef DNS_SIMPLEDB_H
#define DNS_SIMPLEDB_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS simple database wrapper implementation
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>

#include <dns/types.h>

/***
 *** Types
 ***/

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_sdb_create(isc_mem_t *mctx, dns_name_t *origin, dns_dbtype_t type,
	       dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	       dns_db_t **dbp);

ISC_LANG_ENDDECLS

#endif /* DNS_SIMPLEDB_H */
