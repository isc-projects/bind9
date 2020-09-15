/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#define DNS_NAME_USEINLINE 1

#include <config.h>

#include <inttypes.h>
#include <stdbool.h>

#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/rbt.h>
#include <dns/result.h>

#define CCTX_MAGIC	ISC_MAGIC('C', 'C', 'T', 'X')
#define VALID_CCTX(x)	ISC_MAGIC_VALID(x, CCTX_MAGIC)

#define DCTX_MAGIC	ISC_MAGIC('D', 'C', 'T', 'X')
#define VALID_DCTX(x)	ISC_MAGIC_VALID(x, DCTX_MAGIC)

#define TABLE_READY							\
	do {								\
		unsigned int i;						\
									\
		if ((cctx->allowed & DNS_COMPRESS_READY) == 0) {	\
			cctx->allowed |= DNS_COMPRESS_READY;		\
			for (i = 0; i < DNS_COMPRESS_TABLESIZE; i++)	\
				cctx->table[i] = NULL;			\
		}							\
	} while (0)

/***
 ***	Compression
 ***/

isc_result_t
dns_compress_init(dns_compress_t *cctx, int edns, isc_mem_t *mctx) {
	REQUIRE(cctx != NULL);
	REQUIRE(mctx != NULL);	/* See: rdataset.c:towiresorted(). */

	cctx->edns = edns;
	cctx->mctx = mctx;
	cctx->count = 0;
	cctx->allowed = DNS_COMPRESS_ENABLED;
	cctx->magic = CCTX_MAGIC;
	return (ISC_R_SUCCESS);
}

void
dns_compress_invalidate(dns_compress_t *cctx) {
	dns_compressnode_t *node;
	unsigned int i;

	REQUIRE(VALID_CCTX(cctx));

	if ((cctx->allowed & DNS_COMPRESS_READY) != 0) {
		for (i = 0; i < DNS_COMPRESS_TABLESIZE; i++) {
			while (cctx->table[i] != NULL) {
				node = cctx->table[i];
				cctx->table[i] = cctx->table[i]->next;
				if ((node->offset & 0x8000) != 0)
					isc_mem_put(cctx->mctx, node->r.base,
						    node->r.length);
				if (node->count < DNS_COMPRESS_INITIALNODES)
					continue;
				isc_mem_put(cctx->mctx, node, sizeof(*node));
			}
		}
	}
	cctx->magic = 0;
	cctx->allowed = 0;
	cctx->edns = -1;
}

void
dns_compress_setmethods(dns_compress_t *cctx, unsigned int allowed) {
	REQUIRE(VALID_CCTX(cctx));

	cctx->allowed &= ~DNS_COMPRESS_ALL;
	cctx->allowed |= (allowed & DNS_COMPRESS_ALL);
}

unsigned int
dns_compress_getmethods(dns_compress_t *cctx) {
	REQUIRE(VALID_CCTX(cctx));
	return (cctx->allowed & DNS_COMPRESS_ALL);
}

void
dns_compress_disable(dns_compress_t *cctx) {
	REQUIRE(VALID_CCTX(cctx));
	cctx->allowed &= ~DNS_COMPRESS_ENABLED;
}

void
dns_compress_setsensitive(dns_compress_t *cctx, bool sensitive) {
	REQUIRE(VALID_CCTX(cctx));

	if (sensitive)
		cctx->allowed |= DNS_COMPRESS_CASESENSITIVE;
	else
		cctx->allowed &= ~DNS_COMPRESS_CASESENSITIVE;
}

bool
dns_compress_getsensitive(dns_compress_t *cctx) {
	REQUIRE(VALID_CCTX(cctx));

	return (cctx->allowed & DNS_COMPRESS_CASESENSITIVE);
}

int
dns_compress_getedns(dns_compress_t *cctx) {
	REQUIRE(VALID_CCTX(cctx));
	return (cctx->edns);
}

#define NODENAME(node, name) \
do { \
	(name)->length = (node)->r.length; \
	(name)->labels = (node)->labels; \
	(name)->ndata = (node)->r.base; \
	(name)->attributes = DNS_NAMEATTR_ABSOLUTE; \
} while (0)

/*
 * Find the longest match of name in the table.
 * If match is found return true. prefix, suffix and offset are updated.
 * If no match is found return false.
 */
bool
dns_compress_findglobal(dns_compress_t *cctx, const dns_name_t *name,
			dns_name_t *prefix, uint16_t *offset)
{
	dns_name_t tname, nname;
	dns_compressnode_t *node = NULL;
	unsigned int labels, hash, n;

	REQUIRE(VALID_CCTX(cctx));
	REQUIRE(dns_name_isabsolute(name) == true);
	REQUIRE(offset != NULL);

	if ((cctx->allowed & DNS_COMPRESS_ENABLED) == 0)
		return (false);

	TABLE_READY;

	if (cctx->count == 0)
		return (false);

	labels = dns_name_countlabels(name);
	INSIST(labels > 0);

	dns_name_init(&tname, NULL);
	dns_name_init(&nname, NULL);

	for (n = 0; n < labels - 1; n++) {
		dns_name_getlabelsequence(name, n, labels - n, &tname);
		hash = dns_name_hash(&tname, false) %
		       DNS_COMPRESS_TABLESIZE;
		for (node = cctx->table[hash]; node != NULL; node = node->next)
		{
			NODENAME(node, &nname);
			if ((cctx->allowed & DNS_COMPRESS_CASESENSITIVE) != 0) {
				if (dns_name_caseequal(&nname, &tname))
					break;
			} else {
				if (dns_name_equal(&nname, &tname))
					break;
			}
		}
		if (node != NULL)
			break;
	}

	/*
	 * If node == NULL, we found no match at all.
	 */
	if (node == NULL)
		return (false);

	if (n == 0)
		dns_name_reset(prefix);
	else
		dns_name_getlabelsequence(name, 0, n, prefix);

	*offset = (node->offset & 0x7fff);
	return (true);
}

static inline unsigned int
name_length(const dns_name_t *name) {
	isc_region_t r;
	dns_name_toregion(name, &r);
	return (r.length);
}

void
dns_compress_add(dns_compress_t *cctx, const dns_name_t *name,
		 const dns_name_t *prefix, uint16_t offset)
{
	dns_name_t tname, xname;
	unsigned int start;
	unsigned int n;
	unsigned int count;
	unsigned int hash;
	dns_compressnode_t *node;
	unsigned int length;
	unsigned int tlength;
	uint16_t toffset;
	unsigned char *tmp;
	isc_region_t r;

	REQUIRE(VALID_CCTX(cctx));
	REQUIRE(dns_name_isabsolute(name));

	if ((cctx->allowed & DNS_COMPRESS_ENABLED) == 0)
		return;

	TABLE_READY;

	if (offset >= 0x4000)
		return;
	dns_name_init(&tname, NULL);
	dns_name_init(&xname, NULL);

	n = dns_name_countlabels(name);
	count = dns_name_countlabels(prefix);
	if (dns_name_isabsolute(prefix))
		count--;
	if (count == 0)
		return;
	start = 0;
	dns_name_toregion(name, &r);
	length = r.length;
	tmp = isc_mem_get(cctx->mctx, length);
	if (tmp == NULL)
		return;
	/*
	 * Copy name data to 'tmp' and make 'r' use 'tmp'.
	 */
	memmove(tmp, r.base, r.length);
	r.base = tmp;
	dns_name_fromregion(&xname, &r);

	while (count > 0) {
		dns_name_getlabelsequence(&xname, start, n, &tname);
		hash = dns_name_hash(&tname, false) %
		       DNS_COMPRESS_TABLESIZE;
		tlength = name_length(&tname);
		toffset = (uint16_t)(offset + (length - tlength));
		if (toffset >= 0x4000)
			break;
		/*
		 * Create a new node and add it.
		 */
		if (cctx->count < DNS_COMPRESS_INITIALNODES)
			node = &cctx->initialnodes[cctx->count];
		else {
			node = isc_mem_get(cctx->mctx,
					   sizeof(dns_compressnode_t));
			if (node == NULL)
				break;
		}
		node->count = cctx->count++;
		/*
		 * 'node->r.base' becomes 'tmp' when start == 0.
		 * Record this by setting 0x8000 so it can be freed later.
		 */
		if (start == 0)
			toffset |= 0x8000;
		node->offset = toffset;
		dns_name_toregion(&tname, &node->r);
		node->labels = (uint8_t)dns_name_countlabels(&tname);
		node->next = cctx->table[hash];
		cctx->table[hash] = node;
		start++;
		n--;
		count--;
	}

	if (start == 0)
		isc_mem_put(cctx->mctx, tmp, length);
}

void
dns_compress_rollback(dns_compress_t *cctx, uint16_t offset) {
	unsigned int i;
	dns_compressnode_t *node;

	REQUIRE(VALID_CCTX(cctx));

	if ((cctx->allowed & DNS_COMPRESS_ENABLED) == 0)
		return;

	if ((cctx->allowed & DNS_COMPRESS_READY) == 0)
		return;

	for (i = 0; i < DNS_COMPRESS_TABLESIZE; i++) {
		node = cctx->table[i];
		/*
		 * This relies on nodes with greater offsets being
		 * closer to the beginning of the list, and the
		 * items with the greatest offsets being at the end
		 * of the initialnodes[] array.
		 */
		while (node != NULL && (node->offset & 0x7fff) >= offset) {
			cctx->table[i] = node->next;
			if ((node->offset & 0x8000) != 0)
				isc_mem_put(cctx->mctx, node->r.base,
					    node->r.length);
			if (node->count >= DNS_COMPRESS_INITIALNODES)
				isc_mem_put(cctx->mctx, node, sizeof(*node));
			cctx->count--;
			node = cctx->table[i];
		}
	}
}

/***
 ***	Decompression
 ***/

void
dns_decompress_init(dns_decompress_t *dctx, int edns,
		    dns_decompresstype_t type) {

	REQUIRE(dctx != NULL);
	REQUIRE(edns >= -1 && edns <= 255);

	dctx->allowed = DNS_COMPRESS_NONE;
	dctx->edns = edns;
	dctx->type = type;
	dctx->magic = DCTX_MAGIC;
}

void
dns_decompress_invalidate(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	dctx->magic = 0;
}

void
dns_decompress_setmethods(dns_decompress_t *dctx, unsigned int allowed) {

	REQUIRE(VALID_DCTX(dctx));

	switch (dctx->type) {
	case DNS_DECOMPRESS_ANY:
		dctx->allowed = DNS_COMPRESS_ALL;
		break;
	case DNS_DECOMPRESS_NONE:
		dctx->allowed = DNS_COMPRESS_NONE;
		break;
	case DNS_DECOMPRESS_STRICT:
		dctx->allowed = allowed;
		break;
	}
}

unsigned int
dns_decompress_getmethods(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	return (dctx->allowed);
}

int
dns_decompress_edns(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	return (dctx->edns);
}

dns_decompresstype_t
dns_decompress_type(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	return (dctx->type);
}
