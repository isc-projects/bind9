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

#include <sys/types.h>

#include <isc/list.h>
#include <isc/result.h>
#include <isc/mem.h>

/* Zone context structures contain a set of zones and related information
   (like isc_mem_t contexts to allocate memory from). */
typedef struct zonectx zonectx_t;

/* The zone. All access is through function API */
typedef struct zoneinfo zoneinfo_t;


/* Allocate a zone context from the memctx pool. All zone-private data
 * structures will be will be made from that same pool.
 */
isc_result_t	new_zonecontext(isc_mem_t *memctx, zonectx_t **ctx);

/* Allocate a zone from the give zone context. */
isc_result_t 	new_zone(zonectx_t *zctx, zoneinfo_t **zone);

/* Free up a zone and all associated data structures. The zone knows which
 *zone context to go back to
*/	
isc_result_t 	free_zone(zoneinfo_t *zone);


/* Misc accessor routines. All returned data is through the parameter
 * lists. Function return values indicates success (or not).  All the set
 * functions copy their arguments so the caller retains ownership of any
 * pointers passed through the API.  All pointers that come back through
 * the API in the get functions (e.g. getorigin and getsource) are still
 * owned by the zoneinfo_t structure and the data they point to must be
 * copied by the caller
 */
isc_result_t	zone_setorigin(zoneinfo_t *zone, char *origin);
isc_result_t	zone_getorigin(zoneinfo_t *zone, char **origin);

isc_result_t	zone_setfilemodtime(zoneinfo_t *zone, time_t ftime);
isc_result_t	zone_getfilemodtime(zoneinfo_t *zone, time_t *ftime);

isc_result_t	zone_setsource(zoneinfo_t *zone, char *source);
isc_result_t	zone_getsource(zoneinfo_t *zone, char **source);

isc_result_t	zone_setlastupdate(zoneinfo_t *zone, time_t lastupdate);
isc_result_t	zone_getlastupdate(zoneinfo_t *zone, time_t *lastupdate);

isc_result_t	zone_setrefresh(zoneinfo_t *zone, u_int32_t refresh);
isc_result_t	zone_getrefresh(zoneinfo_t *zone, u_int32_t *refresh);

isc_result_t	zone_setretry(zoneinfo_t *zone, u_int32_t retry);
isc_result_t	zone_getretry(zoneinfo_t *zone, u_int32_t *retry);

isc_result_t	zone_setexpire(zoneinfo_t *zone, u_int32_t expire);
isc_result_t	zone_getexpire(zoneinfo_t *zone, u_int32_t *expire);

isc_result_t	zone_setminimum(zoneinfo_t *zone, u_int32_t minimum);
isc_result_t	zone_getminimum(zoneinfo_t *zone, u_int32_t *minimum);

isc_result_t	zone_setserial(zoneinfo_t *zone, u_int32_t serial);
isc_result_t	zone_getserial(zoneinfo_t *zone, u_int32_t *serial);

isc_result_t	zone_setoptions(zoneinfo_t *zone, u_int options);
isc_result_t	zone_getoptions(zoneinfo_t *zone, u_int *options);

isc_result_t	zone_setzoneclass(zoneinfo_t *zone, int zclass);
isc_result_t	zone_getzoneclass(zoneinfo_t *zone, int *zclass);

