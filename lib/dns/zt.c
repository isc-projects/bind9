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
#include <isc/magic.h>
#include "../isc/util.h"
#include <dns/zt.h>

struct dns_zt {
        unsigned int    	magic;
	isc_mem_t      		*mctx;
	dns_rdataclass_t	rdclass;
	isc_mutex_t             lock;
	isc_uint32_t		references;
	dns_rbt_t       	*table; 
};

#define ZTMAGIC 0x5a54626cU	/* ZTbl */
#define VALID_ZT(zt) ISC_MAGIC_VALID(zt, ZTMAGIC)

static void auto_detach(void *, void *);

dns_result_t
dns_zt_create(isc_mem_t *mctx, dns_rdataclass_t rdclass, dns_zt_t **zt) {
	dns_zt_t *new;
	dns_result_t result;
	isc_result_t iresult;

	REQUIRE(zt != NULL && *zt == NULL);
	new = isc_mem_get(mctx, sizeof *new);
	if (new == NULL)
		return (DNS_R_NOMEMORY);

	new->table = NULL;
	result = dns_rbt_create(mctx, auto_detach, NULL, &new->table);
	if (result != DNS_R_SUCCESS)
		goto cleanup0;

	iresult = isc_mutex_init(&new->lock);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_lock_init() failed: %s",
				 isc_result_totext(result));
		result = DNS_R_UNEXPECTED;
		goto cleanup1;
	}

	new->mctx = mctx;
	new->references = 1;
	new->rdclass = rdclass;
	new->magic = ZTMAGIC;
	*zt = new;
	return (DNS_R_SUCCESS);

   cleanup1:
	dns_rbt_destroy(&new->table);

   cleanup0:
	isc_mem_put(mctx, new, sizeof *new);
	return (result);
}

dns_result_t
dns_zt_mount(dns_zt_t *zt, dns_zone_t *zone) {
	dns_result_t result;
	dns_zone_t *dummy = NULL;
	dns_name_t name;

	REQUIRE(VALID_ZT(zt));

	dns_name_init(&name, NULL);
	result = dns_zone_getorigin(zone, zt->mctx, &name);
	if (result != DNS_R_SUCCESS)
		return (result);
	LOCK(&zt->lock);
	result = dns_rbt_addname(zt->table, &name, zone);
	UNLOCK(&zt->lock);
	dns_name_free(&name, zt->mctx);
	if (result == DNS_R_SUCCESS)
		dns_zone_attach(zone, &dummy);

	return (result);
}

dns_result_t
dns_zt_unmount(dns_zt_t *zt, dns_zone_t *zone) {
	dns_result_t result;
	dns_name_t name;

	REQUIRE(VALID_ZT(zt));

	dns_name_init(&name, NULL);
	result = dns_zone_getorigin(zone, zt->mctx, &name);
	if (result != DNS_R_SUCCESS)
		return (result);
	LOCK(&zt->lock);
	result = dns_rbt_deletename(zt->table, &name, ISC_FALSE);
	UNLOCK(&zt->lock);
	dns_name_free(&name, zt->mctx);
	return (result);
}

dns_result_t
dns_zt_find(dns_zt_t *zt, dns_name_t *name, dns_name_t *foundname,
		   dns_zone_t **zone)
{
	dns_result_t result;
	dns_zone_t *dummy = NULL;

	REQUIRE(VALID_ZT(zt));

	LOCK(&zt->lock);
	result = dns_rbt_findname(zt->table, name, foundname, (void **)&dummy);
	UNLOCK(&zt->lock);

	if (result == DNS_R_SUCCESS || result == DNS_R_PARTIALMATCH)
		dns_zone_attach(dummy, zone);

	return (result);
}

void
dns_zt_detach(dns_zt_t **ztp) {
	isc_boolean_t destroy = ISC_FALSE;
	dns_zt_t *zt;

	REQUIRE(ztp != NULL && VALID_ZT(*ztp));

	zt = *ztp;

	LOCK(&zt->lock);
	
	INSIST(zt->references > 0);
	zt->references--;
	if (zt->references == 0)
		destroy = ISC_TRUE;
	UNLOCK(&zt->lock);

	if (destroy) {
		dns_rbt_destroy(&zt->table);
		isc_mutex_destroy(&zt->lock);
		isc_mem_put(zt->mctx, zt, sizeof *zt);
		zt->magic = 0;
	}

	*ztp = NULL;
}

void
dns_zt_attach(dns_zt_t *zt, dns_zt_t **ztp) {

	REQUIRE(VALID_ZT(zt));
	REQUIRE(ztp != NULL && *ztp == NULL);

	LOCK(&zt->lock);

	INSIST(zt->references > 0);
	zt->references++;
	INSIST(zt->references != 0xffffffffU);

	UNLOCK(&zt->lock);

	*ztp = zt;
}

void
dns_zt_print(dns_zt_t *zt) {
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	dns_result_t result;
	dns_zone_t *zone;

	REQUIRE(VALID_ZT(zt));

	dns_rbtnodechain_init(&chain, zt->mctx);
	result = dns_rbtnodechain_first(&chain, zt->table, NULL, NULL);
	while (result == DNS_R_NEWORIGIN || result == DNS_R_SUCCESS) {
		result = dns_rbtnodechain_current(&chain, NULL, NULL,
						  &node);
		if (result == DNS_R_SUCCESS) {
			zone = node->data;
			if (zone != NULL)
				(void)dns_zone_print(zone);
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}
	dns_rbtnodechain_invalidate(&chain);
}

void
dns_zt_load(dns_zt_t *zt) {
	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	dns_result_t result;
	dns_zone_t *zone;

	REQUIRE(VALID_ZT(zt));

	dns_rbtnodechain_init(&chain, zt->mctx);
	result = dns_rbtnodechain_first(&chain, zt->table, NULL, NULL);
	while (result == DNS_R_NEWORIGIN || result == DNS_R_SUCCESS) {
		result = dns_rbtnodechain_current(&chain, NULL, NULL,
						  &node);
		if (result == DNS_R_SUCCESS) {
			zone = node->data;
			if (zone != NULL)
				(void)dns_zone_load(zone);
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}
	dns_rbtnodechain_invalidate(&chain);
}

/***
 *** Private
 ***/

static void
auto_detach(void *zone, void *xxx) {
	dns_zone_t *dummy = zone;

	xxx = xxx;	/*unused*/

	printf("auto_detach\n");
	dns_zone_detach(&dummy);
}
