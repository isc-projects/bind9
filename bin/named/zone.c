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


static isc_result_t set_string(char **string, size_t *len,
			       const char *source, isc_mem_t *mem);



isc_result_t
isc_zone_newcontext(isc_mem_t *memctx, isc_zonectx_t **zctx)
{
	isc_zonectx_t *zc ;
	
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
isc_zone_freecontext(isc_zonectx_t *zonectx)
{
	isc_zoneinfo_t *zi ;

	zi = ISC_LIST_HEAD(zonectx->freezones) ;
	while (zi != NULL ) {
		isc_zone_release_zone(zi);
	}
	
	return (ISC_R_SUCCESS);	
}

isc_result_t 
isc_zone_newinfo(isc_zonectx_t *zctx, isc_zoneinfo_t **zone)
{
	struct isc_zoneinfo *zp;

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
isc_zone_freezone(isc_zoneinfo_t *zone)
{
	INSIST(zone != NULL);
	INSIST(zone->magic == ZONE_USED_MAGIC);
	INSIST(zone->zctx != NULL);

	ISC_LIST_UNLINK(zone->zctx->usedzones, zone, chainlink);
	zone->magic = ZONE_FREE_MAGIC;
	ISC_LIST_APPEND(zone->zctx->freezones, zone, chainlink);

	return ISC_R_SUCCESS;
}


isc_result_t
isc_zone_release_zone(isc_zoneinfo_t *zone)
{
	isc_mem_put(zone->zctx->memctx, zone, sizeof *zone);

	return (ISC_R_SUCCESS);
}


isc_result_t
isc_zone_setsource(isc_zoneinfo_t *zone, const char *source)
{
	INSIST(zone != NULL);
	INSIST(source != NULL);
	INSIST(strlen(source) > 0);

	return (set_string(&zone->source, &zone->sourcelen,
			   source, zone->zctx->memctx));
	
}


isc_result_t
isc_zone_setorigin(isc_zoneinfo_t *zone, const char *source)
{
	INSIST(zone != NULL);
	INSIST(source != NULL);
	INSIST(strlen(source) > 0);

	return (set_string(&zone->origin, &zone->originlen,
			   source, zone->zctx->memctx));
}	



static isc_result_t
set_string(char **string, size_t *len, const char *source, isc_mem_t *mem)
{
	INSIST(string != NULL);
	INSIST(len != 0);
	INSIST(mem != NULL);
	
	if (*len > 0 && *len <= strlen(source)) {
		isc_mem_put(mem, *string, *len);
		*len = 0;
		*string = NULL;
	}

	if (*len == 0) {
		size_t need = strlen(source) + 1;

		*string = isc_mem_get(mem, need);
		if (*string == NULL) {
			return (ISC_R_NOMEMORY);
		}
	}

	strcpy (*string, source);

	return (ISC_R_SUCCESS);
}

