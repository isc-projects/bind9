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
#include <isc/assertions.h>
#include <dns/zt.h>

struct dns_zt {
        unsigned int    	magic;
	dns_rdataclass_t	rdclass;
	dns_rbt_t       	*table; 
	isc_mem_t      		*mctx;
};

#define ZTMAGIC 0x5a54626cU	/* ZTbl */
#define VALID_ZT(zt) ((zt) != NULL && (zt)->magic == ZTMAGIC)

static void auto_detach(void *, void *);

dns_result_t
dns_zt_create(isc_mem_t *mctx, dns_rdataclass_t rdclass, dns_zt_t **zt) {
	dns_zt_t *new;
	dns_result_t result;

	REQUIRE(zt != NULL && *zt == NULL);
	new = isc_mem_get(mctx, sizeof *new);
	if (new == NULL)
		return (DNS_R_NOMEMORY);

	result = dns_rbt_create(mctx, auto_detach, NULL, &new->table);
	if (result != DNS_R_SUCCESS) {
		isc_mem_put(mctx, new, sizeof *new);
		return (result);
	}
	new->mctx = mctx;
	new->rdclass = rdclass;
	new->magic = ZTMAGIC;
	*zt = new;
	return (DNS_R_SUCCESS);
}

dns_result_t
dns_zt_mount_zone(dns_zt_t *zt, dns_zone_t *zone) {
	dns_result_t result;
	dns_zone_t *dummy = NULL;

	REQUIRE(VALID_ZT(zt));

	dns_zone_attach(zone, &dummy);
	result = dns_rbt_addname(zt->table, dns_zone_getorigin(zone), zone);
	return (result);
}

dns_result_t
dns_zt_unmount_zone(dns_zt_t *zt, dns_zone_t *zone) {
	dns_result_t result;

	REQUIRE(VALID_ZT(zt));

	result = dns_rbt_deletename(zt->table, dns_zone_getorigin(zone),
				    ISC_FALSE);
	return (result);
}

dns_result_t
dns_zt_lookup_zone(dns_zt_t *zt, dns_name_t *name, dns_name_t *foundname,
		   dns_zone_t **zone)
{
	dns_result_t result;

	REQUIRE(VALID_ZT(zt));

	result = dns_rbt_findname(zt->table, name, foundname, (void **)zone);
	return (result);
}

void
dns_zt_destroy(dns_zt_t *zt) {
	REQUIRE(VALID_ZT(zt));

	zt->magic = 0;
	dns_rbt_destroy(&zt->table);
	isc_mem_put(zt->mctx, zt, sizeof *zt);
}

static void
auto_detach(void *zone, void *xxx) {
	dns_zone_t *dummy = zone;

	xxx = xxx;	/*unused*/

	dns_zone_detach(&dummy);
}
