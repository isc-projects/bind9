/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#if ! defined(ZONE_H)
#define ZONE_H

#include <config.h>

#include <sys/types.h>

#include <isc/list.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/types.h>

#include <dns/types.h>

/* Zone context structures contain a set of zones and related information
   (like isc_mem_t contexts to allocate memory from). */
typedef struct isc_zonectx isc_zonectx_t;

/* The zone. All access is through function API */
typedef struct isc_zoneinfo isc_zoneinfo_t;


typedef enum {
  zone_master, zone_slave, zone_hint, zone_stub, zone_forward
} isc_zonet_t ;
  

typedef enum {
	class_any, class_none, class_in, class_chaos, class_hesiod,
	class_hs
} isc_rrclass_t;


/* This structure contains all the run-time information about a zone. */
struct isc_zoneinfo 
{
	isc_int32_t	magic;		/* private magic stamp for valid'ng */

	isc_textregion_t	origin;
	isc_textregion_t	source;

	isc_zonet_t	type;		/* master, slave etc. */
	isc_rrclass_t	zone_class;	/* IN, CHAOS etc. */
	
	dns_db_t	*thedb;


	/* The rest below aren't implmented yet */

	time_t		filemodtime;	/* mod time of zone file */
	time_t		lastupdate;	/* time last soa serial increment */
	isc_uint32_t	refresh;	/* refresh interval */
	isc_uint32_t	retry;		/* refresh retry interval */
	isc_uint32_t	expire;		/* expiration time for cached info */
	isc_uint32_t	minimum;	/* minimum TTL value */
	isc_uint32_t	serial;		/* SOA serial number */

	unsigned int	options;	/* zone specific options */
	int		zoneclass;	/* zone class type */

	struct isc_zonectx	*zctx;		/* contect zone came from. */
	
	ISC_LINK(struct isc_zoneinfo) chainlink;
};


/* This structure contains context information about a set of
   zones. Presumamable there'd only be one of these passed around the
   various threads, but separating out zones might be useful in some way */
struct isc_zonectx 
{
	ISC_LIST(isc_zoneinfo_t) 	freezones;
	ISC_LIST(isc_zoneinfo_t) 	usedzones;

	isc_mem_t		*memctx; /* where we get all our memory from */
};



/* Allocate a zone context from the memctx pool. All zone-private data
 * structures will be will be made from that same pool.
 */
isc_result_t	isc_zone_newcontext(isc_mem_t *memctx, isc_zonectx_t **ctx);

/* Allocate a zone from the give zone context. */
isc_result_t 	isc_zone_newinfo(isc_zonectx_t *zctx, isc_zoneinfo_t **zone);

isc_result_t	isc_zone_release_zone(isc_zoneinfo_t *zone);

/* write named.conf-type format */
void		isc_zone_dump(FILE *fp, isc_zoneinfo_t *zone);

/* Free up a zone and all associated data structures. The zone knows which
 *zone context to go back to
 */	
isc_result_t 	isc_zone_freezone(isc_zoneinfo_t *zone);
isc_result_t	isc_zone_freecontext(isc_zonectx_t *ctx);

/* These functions copy the data they're given. */
isc_result_t    isc_zone_setsource(isc_zoneinfo_t *zone,
				   const char *source);
isc_result_t	isc_zone_setorigin(isc_zoneinfo_t *zone,
				   const char *origin);

isc_result_t	isc_zone_setclass(isc_zoneinfo_t *zone, isc_rrclass_t class);

				  

const char *	isc_zonetype_to_string(isc_zonet_t zont_type);
void		isc_zonectx_dump(FILE *fp, isc_zonectx_t *ctx);
void		isc_zone_dump(FILE *fp, isc_zoneinfo_t *zone);

const char *	rrclass_to_string(isc_rrclass_t rrclass);



#endif
