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

#include <config.h>

#include <stdlib.h>

#include <dns/types.h>

#include <isc/mem.h>
#include <isc/assertions.h>

#include "zone.h"

/*

  NOTES

  - This needs to be fixed for threads.
  	-
  
  - we do not 'realloc' to keep all the zones in contiguous memory.
  
 */

#define ZONECHUNK 50		  /* how many zone structs we make at once.*/
#define ZONE_USED_MAGIC 0x7fffffff
#define ZONE_FREE_MAGIC 0x0



/* This structure contains all the run-time information about a zone. */
struct zoneinfo 
{
	char		*origin;	/* name of zone */
	time_t		filemodtime;	/* mod time of zone file */
	char		*source;	/* where zone data came from */

#if 0
	dns_db_t	what_am_i;	/* XXX unknown thing... */
#endif
	
	time_t		lastupdate;	/* time last soa serial increment */
	u_int32_t	refresh;	/* refresh interval */
	u_int32_t	retry;		/* refresh retry interval */
	u_int32_t	expire;		/* expiration time for cached info */
	u_int32_t	minimum;	/* minimum TTL value */
	u_int32_t	serial;		/* SOA serial number */

	u_int		options;	/* zone specific options */
	int		zoneclass;	/* zone class type */

	int32_t		magic;		/* private magic stamp for valid'ng */

	struct zonectx	*zctx;		/* contect zone came from. */
	
	ISC_LINK(struct zoneinfo) chainlink;
};


/* This structure contains context information about a set of
   zones. Presumamable there'd only be one of these passed around the
   various threads, but separating out zones might be useful in some way */
struct zonectx 
{
	ISC_LIST(zoneinfo_t) 	freezones;
	ISC_LIST(zoneinfo_t) 	usedzones;

	isc_mem_t		*memctx; /* where we get all our memory from */
};




isc_result_t
new_zonecontext(isc_mem_t *memctx, zonectx_t **zctx) {
	zonectx_t *zc ;
	
	INSIST(zctx != NULL);
	INSIST(memctx != NULL);
	
	zc = isc_mem_get(memctx, sizeof *zc);
	INSIST(zc != NULL);

	memset(zc, 0x0, sizeof *zc);
	zc->memctx = memctx;

	*zctx = zc;
	
	return ISC_R_SUCCESS;
}
	

isc_result_t 
new_zone(zonectx_t *zctx, zoneinfo_t **zone) {
	struct zoneinfo *zp;

	INSIST(zctx != NULL);
	INSIST(zone != NULL);
	
	if (ISC_LIST_EMPTY(zctx->freezones)) {
		int bytes = sizeof (*zp) * ZONECHUNK;
		int idx;
		
		zp = isc_mem_get(zctx->memctx, bytes);
		INSIST(zp != NULL);
			
		memset(zp, 0x0, bytes);
		zp->magic = ZONE_FREE_MAGIC;
		
		for (idx = 0 ; idx < ZONECHUNK ; idx++) {
			zp[idx].magic = ZONE_FREE_MAGIC;
			ISC_LIST_APPEND(zctx->freezones, &zp[idx], chainlink);
		}
	}

	INSIST(!ISC_LIST_EMPTY(zctx->freezones));
	
	zp = ISC_LIST_HEAD(zctx->freezones);
	ISC_LIST_UNLINK(zctx->freezones, zp, chainlink);
	ISC_LIST_APPEND(zctx->usedzones, zp, chainlink);

	zp->magic = ZONE_USED_MAGIC;
	zp->zctx = zctx;

	*zone = zp;
	
	return ISC_R_SUCCESS;
}


isc_result_t
free_zone(zoneinfo_t *zone) {
	INSIST(zone != NULL);
	INSIST(zone->magic == ZONE_USED_MAGIC);
	INSIST(zone->zctx != NULL);

	ISC_LIST_UNLINK(zone->zctx->usedzones, zone, chainlink);
	zone->magic = ZONE_FREE_MAGIC;
	ISC_LIST_APPEND(zone->zctx->freezones, zone, chainlink);

	return ISC_R_SUCCESS;
}


	
isc_result_t	zone_setorigin(zoneinfo_t *zone, char *origin)
{
	(void) zone;
	(void) origin;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getorigin(zoneinfo_t *zone, char **origin)
{
	(void) zone;
	(void) origin;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setfilemodtime(zoneinfo_t *zone, time_t ftime)
{
	(void) zone;
	(void) ftime;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getfilemodtime(zoneinfo_t *zone, time_t *ftime)
{
	(void) zone;
	(void) ftime;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setsource(zoneinfo_t *zone, char *source)
{
	(void) zone;
	(void) source;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getsource(zoneinfo_t *zone, char **source)
{
	(void) zone;
	(void) source;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setlastupdate(zoneinfo_t *zone, time_t lastupdate)
{
	(void) zone;
	(void) lastupdate;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getlastupdate(zoneinfo_t *zone, time_t *lastupdate)
{
	(void) zone;
	(void) lastupdate;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setrefresh(zoneinfo_t *zone, u_int32_t refresh)
{
	(void) zone;
	(void) refresh;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getrefresh(zoneinfo_t *zone, u_int32_t *refresh)
{
	(void) zone;
	(void) refresh;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setretry(zoneinfo_t *zone, u_int32_t retry)
{
	(void) zone;
	(void) retry;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getretry(zoneinfo_t *zone, u_int32_t *retry)
{
	(void) zone;
	(void) retry;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setexpire(zoneinfo_t *zone, u_int32_t expire)
{
	(void) zone;
	(void) expire;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getexpire(zoneinfo_t *zone, u_int32_t *expire)
{
	(void) zone;
	(void) expire;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setminimum(zoneinfo_t *zone, u_int32_t minimum)
{
	(void) zone;
	(void) minimum;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getminimum(zoneinfo_t *zone, u_int32_t *minimum)
{
	(void) zone;
	(void) minimum;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setserial(zoneinfo_t *zone, u_int32_t serial)
{
	(void) zone;
	(void) serial;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getserial(zoneinfo_t *zone, u_int32_t *serial)
{
	(void) zone;
	(void) serial;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setoptions(zoneinfo_t *zone, u_int options)
{
	(void) zone;
	(void) options;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getoptions(zoneinfo_t *zone, u_int *options)
{
	(void) zone;
	(void) options;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


isc_result_t	zone_setzoneclass(zoneinfo_t *zone, int zclass)
{
	(void) zone;
	(void) zclass;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}

isc_result_t	zone_getzoneclass(zoneinfo_t *zone, int *zclass)
{
	(void) zone;
	(void) zclass;

  /* XXX fill this in */

	return ISC_R_SUCCESS;
}


