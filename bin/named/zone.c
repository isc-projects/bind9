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
#include <string.h>

#include <dns/types.h>

#include <isc/mem.h>
#include <isc/assertions.h>

#include "zone.h"

/*
 * NOTE:  we do not 'realloc' to keep all the zones in contiguous memory.
 *	
 */

#define ZONECHUNK 50		  /* how many zone structs we make at once.*/
#define ZONE_USED_MAGIC 0x7fffffff
#define ZONE_FREE_MAGIC 0x0


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
	isc_zoneinfo_t *zi;
	isc_zoneinfo_t *zp;

	zi = ISC_LIST_HEAD(zonectx->freezones);
	while (zi != NULL ) {
		zp = zi;
		zi = ISC_LIST_NEXT(zi, chainlink);

		isc_zone_release_zone(zp);
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
	size_t len;
	
	INSIST(zone != NULL);
	INSIST(source != NULL);

	len = strlen(source) + 1;
	
	INSIST(len > 1);

	zone->source.base = isc_mem_get(zone->zctx->memctx, len);
	if (zone->source.base == NULL) {
		return (ISC_R_NOMEMORY);
	}
	zone->source.length = len;
	strcpy(zone->source.base, source);

	return (ISC_R_SUCCESS);
}


isc_result_t
isc_zone_setorigin(isc_zoneinfo_t *zone, const char *origin)
{
	size_t len;
	
	INSIST(zone != NULL);
	INSIST(origin != NULL);

	len = strlen(origin) + 1;

	INSIST(len > 1);

	zone->origin.base = isc_mem_get(zone->zctx->memctx, len);
	if (zone->origin.base == NULL) {
		return (ISC_R_NOMEMORY);
	}
	zone->origin.length = len;
	
	strcpy(zone->origin.base, origin);

	return (ISC_R_SUCCESS);
}	


const char *
isc_zonetype_to_string(isc_zonet_t zone_type)
{
	const char *res = NULL;
	switch (zone_type) {
	case zone_master:
		res = "master";
		break;
	case zone_slave:
		res = "slave";
		break;
	case zone_hint:
		res = "hint";
		break;
	case zone_stub:
		res = "stub";
		break;
	case zone_forward:
		res = "forward";
		break;
	}

	INSIST (res != NULL);

	return (res);
}


void
isc_zonectx_dump(FILE *fp, isc_zonectx_t *ctx)
{
	isc_zoneinfo_t *zi;
	
	INSIST(ctx != NULL);

	zi = ISC_LIST_HEAD(ctx->usedzones);
	while (zi != NULL ) {
		isc_zone_dump(fp, zi);
		zi = ISC_LIST_NEXT(zi, chainlink);
	}
}

	
void
isc_zone_dump(FILE *fp, isc_zoneinfo_t *zone)
{
	INSIST(fp != NULL);
	INSIST(zone != NULL);
	
	fprintf(fp, "zone \"%s\" %s {\n", zone->origin.base,
		rrclass_to_string(zone->zone_class));
	fprintf(fp, "\ttype %s;\n",isc_zonetype_to_string(zone->type));

	/* XXX this will get more complicated */
	fprintf(fp, "\tfile \"%s\";\n",zone->source.base);
	fprintf(fp, "}\n");
}

	
	
isc_result_t
isc_zone_setclass(isc_zoneinfo_t *zone, isc_rrclass_t rrclass)
{
	INSIST(zone != NULL);

	zone->zone_class = rrclass;

	return (ISC_R_SUCCESS);
}


const char *
rrclass_to_string(isc_rrclass_t rrclass)
{
	const char *res;

	switch (rrclass) {
	case class_none:
		res = "NONE";
		break;
	case class_any:
		res = "ANY";
		break;
	case class_in:
		res = "IN";
		break;
	case class_chaos:
		res = "CHAOS";
		break;
	case class_hesiod:
		res = "HESIOD";
		break;
	case class_hs:
		res = "HS";
		break;
	default:
		res = NULL;
		break;
	}

	INSIST(res != NULL);

	return (res);
}

			
