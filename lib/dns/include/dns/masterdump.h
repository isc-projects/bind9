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

#ifndef DNS_MASTERDUMP_H
#define DNS_MASTERDUMP_H 1

/***
 ***	Imports
 ***/

#include <stdio.h>

#include <isc/lang.h>
#include <isc/mem.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdataset.h>

/***
 *** Types
 ***/

/*
 * Style options for masterfile dumps.  This struct is currently
 * opaque, so applications cannot define their own style but have
 * to choose a predefined style.  A more flexible interface may 
 * be exported in the future.
 */

typedef struct dns_master_style dns_master_style_t;

ISC_LANG_BEGINDECLS

/***
 ***	Constants
 ***/

/*
 * The default masterfile style.  
 */
extern const dns_master_style_t dns_master_style_default;


/***
 ***	Functions
 ***/

isc_result_t
dns_master_dumptostream(isc_mem_t *mctx, dns_db_t *db,
		dns_dbversion_t *version,
		const dns_master_style_t *style, FILE *f);
/*
 * Dump the database 'db' to the steam 'f' in RFC1035 master 
 * file format, in the style defined by 'style'
 * (e.g., &dns_default_master_style_default)
 *
 * Temporary dynamic memory may be allocated from 'mctx'.
 *
 * Returns:
 *	DNS_R_SUCCESS 
 *	DNS_R_NOMEMORY
 * 	Any database or rrset iterator error.
 *	Any dns_rdata_totext() error code.
 */

isc_result_t
dns_master_dump(isc_mem_t *mctx, dns_db_t *db,
		dns_dbversion_t *version,
		const dns_master_style_t *style, const char *filename);
/*
 * Dump the database 'db' to the file 'filename' in RFC1035 master 
 * file format, in the style defined by 'style'
 * (e.g., &dns_default_master_style_default)
 *
 * Temporary dynamic memory may be allocated from 'mctx'.
 *
 * Returns:
 *	DNS_R_SUCCESS 
 *	DNS_R_NOMEMORY
 * 	Any database or rrset iterator error.
 *	Any dns_rdata_totext() error code.
 */

ISC_LANG_ENDDECLS

#endif	/* DNS_MASTERDUMP_H */
