/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/order.h>
#include <dns/rdataset.h>
#include <dns/types.h>

typedef struct dns_order_ent dns_order_ent_t;
struct dns_order_ent {
	dns_fixedname_t name;
	dns_rdataclass_t rdclass;
	dns_rdatatype_t rdtype;
	dns_orderopt_t mode;
	ISC_LINK(dns_order_ent_t) link;
};

struct dns_order {
	unsigned int magic;
	isc_refcount_t references;
	ISC_LIST(dns_order_ent_t) ents;
	isc_mem_t *mctx;
};

#define DNS_ORDER_MAGIC	       ISC_MAGIC('O', 'r', 'd', 'r')
#define DNS_ORDER_VALID(order) ISC_MAGIC_VALID(order, DNS_ORDER_MAGIC)

void
dns_order_create(isc_mem_t *mctx, dns_order_t **orderp) {
	dns_order_t *order = NULL;

	REQUIRE(orderp != NULL && *orderp == NULL);

	order = isc_mem_get(mctx, sizeof(*order));
	*order = (dns_order_t){
		.ents = ISC_LIST_INITIALIZER,
		.references = ISC_REFCOUNT_INITIALIZER(1),
		.magic = DNS_ORDER_MAGIC,
	};

	isc_mem_attach(mctx, &order->mctx);
	*orderp = order;
}

void
dns_order_add(dns_order_t *order, const dns_name_t *name,
	      dns_rdatatype_t rdtype, dns_rdataclass_t rdclass,
	      dns_orderopt_t mode) {
	dns_order_ent_t *ent = NULL;

	REQUIRE(DNS_ORDER_VALID(order));

	ent = isc_mem_get(order->mctx, sizeof(*ent));
	*ent = (dns_order_ent_t){
		.rdtype = rdtype,
		.rdclass = rdclass,
		.mode = mode,
		.link = ISC_LINK_INITIALIZER,
	};

	dns_fixedname_init(&ent->name);
	dns_name_copy(name, dns_fixedname_name(&ent->name));

	ISC_LIST_INITANDAPPEND(order->ents, ent, link);
}

static bool
match(const dns_name_t *name1, const dns_name_t *name2) {
	if (dns_name_iswildcard(name2)) {
		return dns_name_matcheswildcard(name1, name2);
	}
	return dns_name_equal(name1, name2);
}

dns_orderopt_t
dns_order_find(dns_order_t *order, const dns_name_t *name,
	       dns_rdatatype_t rdtype, dns_rdataclass_t rdclass) {
	REQUIRE(DNS_ORDER_VALID(order));

	ISC_LIST_FOREACH (order->ents, ent, link) {
		if (ent->rdtype != rdtype && ent->rdtype != dns_rdatatype_any) {
			continue;
		}
		if (ent->rdclass != rdclass &&
		    ent->rdclass != dns_rdataclass_any)
		{
			continue;
		}
		if (match(name, dns_fixedname_name(&ent->name))) {
			return ent->mode;
		}
	}
	return dns_order_none;
}

void
dns_order_attach(dns_order_t *source, dns_order_t **target) {
	REQUIRE(DNS_ORDER_VALID(source));
	REQUIRE(target != NULL && *target == NULL);
	isc_refcount_increment(&source->references);
	*target = source;
}

void
dns_order_detach(dns_order_t **orderp) {
	REQUIRE(orderp != NULL && DNS_ORDER_VALID(*orderp));
	dns_order_t *order = *orderp;
	*orderp = NULL;

	if (isc_refcount_decrement(&order->references) == 1) {
		isc_refcount_destroy(&order->references);
		order->magic = 0;
		ISC_LIST_FOREACH (order->ents, ent, link) {
			ISC_LIST_UNLINK(order->ents, ent, link);
			isc_mem_put(order->mctx, ent, sizeof(*ent));
		}
		isc_mem_putanddetach(&order->mctx, order, sizeof(*order));
	}
}
