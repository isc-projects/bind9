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

 /* $Id: compress.c,v 1.20 2000/02/03 23:43:45 halley Exp $ */

#include <config.h>
#include <string.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/buffer.h>

#include <dns/compress.h>
#include <dns/fixedname.h>

#define CCTX_MAGIC	0x43435458U	/* CCTX */
#define VALID_CCTX(x)	((x) != NULL && (x)->magic == CCTX_MAGIC)

#define DCTX_MAGIC	0x44435458U	/* DCTX */
#define VALID_DCTX(x)	((x) != NULL && (x)->magic == DCTX_MAGIC)

static void		free_offset(void *offset, void *mctx);
isc_boolean_t		compress_find(dns_rbt_t *root, dns_name_t *name,
				      dns_name_t *prefix, dns_name_t *suffix,
				      isc_uint16_t *offset,
				      isc_buffer_t *workspace);
void			compress_add(dns_rbt_t *root, dns_name_t *prefix,
				     dns_name_t *suffix, isc_uint16_t offset,
				     isc_boolean_t global16, isc_mem_t *mctx);

/***
 ***	Compression
 ***/

isc_result_t
dns_compress_init(dns_compress_t *cctx, int edns, isc_mem_t *mctx)
{
	isc_result_t result;

	REQUIRE(cctx != NULL);
	REQUIRE(mctx != NULL);

	cctx->allowed = 0;
	cctx->rdata = 0;
	cctx->global16 = (edns >= 1) ? ISC_TRUE : ISC_FALSE;
	cctx->edns = edns;
	cctx->local = NULL;
	cctx->global = NULL;
	result = dns_rbt_create(mctx, free_offset, mctx, &cctx->global);
	if (result != DNS_R_SUCCESS)
		return (result);
	cctx->mctx = mctx;
	cctx->magic = CCTX_MAGIC;
	return (DNS_R_SUCCESS);
}

isc_result_t
dns_compress_localinit(dns_compress_t *cctx, dns_name_t *owner,
		       isc_buffer_t *target)
{
	isc_result_t result;
	unsigned int labels;
	unsigned int ll;	/* logical label length w/o root label */
	unsigned int wl;	/* wire labels  */
	unsigned int bits;
	dns_name_t name;
	dns_name_t prefix;
	dns_name_t suffix;
	dns_label_t label;
	isc_uint16_t *data;
	unsigned char buf[34];
	unsigned char namebuf[255];
	isc_buffer_t t;
	isc_region_t region;

	REQUIRE(VALID_CCTX(cctx));
	REQUIRE(cctx->local == NULL);
	REQUIRE(dns_name_isabsolute(owner) == ISC_TRUE);
	REQUIRE(isc_buffer_type(target) == ISC_BUFFERTYPE_BINARY);

	result = dns_rbt_create(cctx->mctx, free_offset, cctx->mctx,
				&cctx->local);
	if (result != DNS_R_SUCCESS)
		return (result);

	/*
	 * Errors from here on are not passed back up.
	 */
	cctx->rdata = target->used;	/* XXX layer violation */
	labels = dns_name_countlabels(owner);
	if (labels <= 1)		/* can't compress root label */
		return (DNS_R_SUCCESS);
	ll = 0;	/* logical label index 0 == TLD not root */
	wl = 2; /* minimum number of wire labels */
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_init(&suffix, NULL);
	/*
	 * Work from the TLD label to the least signfiant label.
	 */
	while (labels >= wl) {
		dns_name_getlabelsequence(owner, labels - wl, wl, &name);
		dns_name_getlabel(&name, 0, &label);
		/*
		 * If it is not a bit string label add to tree.
		 */
		if (dns_label_type(&label) != dns_labeltype_bitstring) {
			data = isc_mem_get(cctx->mctx, sizeof *data);
			if (data == NULL)
				return (DNS_R_SUCCESS);
			*data = ll;
			result = dns_rbt_addname(cctx->local, &name, data);
			if (result != DNS_R_SUCCESS) {
				isc_mem_put(cctx->mctx, data, sizeof *data);
				return (DNS_R_SUCCESS);
			}
			wl++;
			ll++;
			if (ll > 254)
				return (DNS_R_SUCCESS);
			continue;
		}
		/*
		 * Have to compute logical for bit string labels.
		 */

		bits = dns_label_countbits(&label);
		INSIST(label.length < sizeof buf);
		memcpy(buf, label.base, label.length);
		region.base = buf;
		dns_name_getlabelsequence(owner, 1, wl - 1, &suffix);
		/*
		 * It is easier to do this the reverse way.
		 * Adding 'bits' to 'll' may exceed the maximum logical
		 * offset index.  Throw away bits until ll <= 254.
		 */
		ll += bits - 1;
		while (ll > 254 && bits > 0) {
			/* clear bit */
			bits--;
			buf[2 + bits / 8] &= ~(1 << (7 - (bits % 8)));
			ll--;
		}
		/*
		 * Add entries to tree.
		 */
		do {
			region.length = 2 + (bits + 7) / 8;
			buf[1] = bits;
			dns_name_fromregion(&prefix, &region);
			isc_buffer_init(&t, namebuf, sizeof namebuf,
					ISC_BUFFERTYPE_BINARY);
			result = dns_name_concatenate(&prefix, &suffix, &name,
						      &t);
			if (result != DNS_R_SUCCESS)
				return (DNS_R_SUCCESS);
			data = isc_mem_get(cctx->mctx, sizeof *data);
			if (data == NULL)
				return (DNS_R_SUCCESS);
			*data = ll;
			result = dns_rbt_addname(cctx->local, &name, data);
			if (result != DNS_R_SUCCESS) {
				isc_mem_put(cctx->mctx, data, sizeof *data);
				return (DNS_R_SUCCESS);
			}
			/* clear bit */
			bits--;
			buf[2 + bits / 8] &= ~(1 << (7 - (bits % 8)));
			ll--;
		} while (bits > 0);
		wl++;
		bits = dns_label_countbits(&label);
		ll += bits;
		if (ll > 254)
			return (DNS_R_SUCCESS);
	}
	return (DNS_R_SUCCESS);
}

void
dns_compress_invalidate(dns_compress_t *cctx) {

	REQUIRE(VALID_CCTX(cctx));

	cctx->magic = 0;
	if (cctx->global != NULL)
		dns_rbt_destroy(&cctx->global);
	if (cctx->local != NULL)
		dns_rbt_destroy(&cctx->local);
	cctx->allowed = 0;
	cctx->rdata = 0;
	cctx->global16 = ISC_FALSE;
	cctx->edns = -1;
}

void
dns_compress_localinvalidate(dns_compress_t *cctx) {

	REQUIRE(VALID_CCTX(cctx));

	if (cctx->local != NULL)
		dns_rbt_destroy(&cctx->local);
}

void
dns_compress_setmethods(dns_compress_t *cctx, unsigned int allowed) {
	REQUIRE(VALID_CCTX(cctx));

	if (cctx->edns >= 1 && (allowed & DNS_COMPRESS_GLOBAL14) != 0)
		allowed |= DNS_COMPRESS_GLOBAL16;
	cctx->allowed = allowed;
}

unsigned int
dns_compress_getmethods(dns_compress_t *cctx) {
	REQUIRE(VALID_CCTX(cctx));
	return (cctx->allowed);
}

int
dns_compress_getedns(dns_compress_t *cctx) {
	REQUIRE(VALID_CCTX(cctx));
	return (cctx->edns);
}

isc_boolean_t
dns_compress_findglobal(dns_compress_t *cctx, dns_name_t *name,
			dns_name_t *prefix, dns_name_t *suffix,
			isc_uint16_t *offset, isc_buffer_t *workspace)
{
	REQUIRE(VALID_CCTX(cctx));
	REQUIRE(dns_name_isabsolute(name) == ISC_TRUE);
	REQUIRE(offset != NULL);

	return (compress_find(cctx->global, name, prefix, suffix, offset,
			      workspace));
}

isc_boolean_t
dns_compress_findlocal(dns_compress_t *cctx, dns_name_t *name,
		       dns_name_t *prefix, dns_name_t *suffix,
		       isc_uint16_t *offset, isc_buffer_t *workspace)
{
	REQUIRE(VALID_CCTX(cctx));
	REQUIRE(dns_name_isabsolute(name) == ISC_TRUE);
	REQUIRE(offset != NULL);

	if (cctx->local == NULL)
		return (ISC_FALSE);
	return (compress_find(cctx->local, name, prefix, suffix, offset,
			      workspace));
}

void
dns_compress_add(dns_compress_t *cctx, dns_name_t *prefix,
		 dns_name_t *suffix, isc_uint16_t offset,
		 isc_boolean_t local)
{
	isc_uint16_t localoffset;
	REQUIRE(VALID_CCTX(cctx));

	if (cctx->local != NULL && (cctx->allowed & DNS_COMPRESS_LOCAL) != 0) {
		REQUIRE(cctx->rdata <= offset);
		localoffset = offset - cctx->rdata + 256;
		compress_add(cctx->local, prefix, suffix, localoffset, ISC_TRUE,
			     cctx->mctx);
	}
	if ((cctx->edns > -1) || !local)
		compress_add(cctx->global, prefix, suffix, offset,
			     cctx->global16, cctx->mctx);
}

void
dns_compress_rollback(dns_compress_t *cctx, isc_uint16_t offset) {
	dns_rbtnode_t *node;
	dns_fixedname_t foundfixed;
	dns_fixedname_t fullfixed;
	dns_fixedname_t originfixed;
	dns_name_t *foundname;
	dns_name_t *fullname;
	dns_name_t *origin;
	dns_rbtnodechain_t chain;
	isc_result_t result;

	REQUIRE(VALID_CCTX(cctx));

	/*
	 * Initalise things.
	 */
	dns_fixedname_init(&foundfixed);
	foundname = dns_fixedname_name(&foundfixed);
	dns_fixedname_init(&fullfixed);
	fullname = dns_fixedname_name(&fullfixed);
	dns_fixedname_init(&originfixed);
	origin = dns_fixedname_name(&originfixed);
	dns_rbtnodechain_init(&chain, cctx->mctx);

 again:
	result = dns_rbtnodechain_first(&chain, cctx->global, foundname,
					origin);

	while (result == DNS_R_NEWORIGIN || result == DNS_R_SUCCESS) {
		result = dns_rbtnodechain_current(&chain, foundname,
						  origin, &node);

		if (result != DNS_R_SUCCESS)
			break;

		if (node->data != NULL &&
		    (*(isc_uint16_t*)node->data >= offset)) {
			result = dns_name_concatenate(foundname,
					dns_name_isabsolute(foundname) ?
						      NULL : origin,
						      fullname, NULL);

			if (result != DNS_R_SUCCESS)
				break;

			result = dns_rbt_deletename(cctx->global, fullname,
						    ISC_FALSE);
			if (result != DNS_R_SUCCESS)
				break;
			/*
			 * If the delete is successful the chain is broken.
			 */
			dns_rbtnodechain_reset(&chain);
			goto again;
		}

		result = dns_rbtnodechain_next(&chain, foundname, origin);
	}
	dns_rbtnodechain_invalidate(&chain);
}

/***
 ***	Decompression
 ***/

void
dns_decompress_init(dns_decompress_t *dctx, int edns, isc_boolean_t strict) {

	REQUIRE(dctx != NULL);
	REQUIRE(edns >= -1 && edns <= 255);

	dctx->allowed = DNS_COMPRESS_NONE;
	dctx->edns = edns;
	dctx->strict = strict;
	dctx->rdata = 0;
	dns_name_init(&dctx->owner_name, NULL);
	dns_name_invalidate(&dctx->owner_name);
	dctx->magic = DCTX_MAGIC;
}

void
dns_decompress_localinit(dns_decompress_t *dctx, dns_name_t *name,
			 isc_buffer_t *source)
{
	REQUIRE(VALID_DCTX(dctx));
	REQUIRE(dns_name_isabsolute(name) == ISC_TRUE);
	REQUIRE(isc_buffer_type(source) == ISC_BUFFERTYPE_BINARY);

	dctx->rdata = source->current;	/* XXX layer violation */
	dctx->owner_name = *name;
}

void
dns_decompress_invalidate(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	dctx->magic = 0;
}

void
dns_decompress_localinvalidate(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	dns_name_invalidate(&dctx->owner_name);
}

void
dns_decompress_setmethods(dns_decompress_t *dctx, unsigned int allowed) {

	REQUIRE(VALID_DCTX(dctx));

	dctx->allowed = allowed;
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

isc_boolean_t
dns_decompress_strict(dns_decompress_t *dctx) {

	REQUIRE(VALID_DCTX(dctx));

	return (dctx->strict);
}

/***
 ***	Private
 ***/

static void
free_offset(void *offset, void *mctx) {
	REQUIRE(offset != NULL);
	REQUIRE(mctx != NULL);
	isc_mem_put(mctx, offset, sizeof(isc_uint16_t));
}

/*
 *	Add the labels in prefix to RBT.
 */
void
compress_add(dns_rbt_t *root, dns_name_t *prefix, dns_name_t *suffix,
	     isc_uint16_t offset, isc_boolean_t global16, isc_mem_t *mctx)
{

	dns_name_t name;
	dns_name_t full;
	dns_label_t label;
	unsigned int count;
	unsigned int start;
	unsigned int limit;
	isc_uint16_t *data;
	isc_result_t result;
	unsigned char buffer[255];
	isc_buffer_t target;
	dns_offsets_t offsets;

	count = dns_name_countlabels(prefix);
	limit = dns_name_isabsolute(prefix) ? 1 : 0;
	start = 0;
	dns_name_init(&full, offsets);
	dns_name_init(&name, NULL);
	while (count > limit) {
		if (offset >= 16384 && !global16)
			break;
		dns_name_getlabelsequence(prefix, start, count, &name);
		isc_buffer_init(&target, buffer, sizeof buffer,
				ISC_BUFFERTYPE_BINARY);
		result = dns_name_concatenate(&name, suffix, &full, &target);
		if (result != DNS_R_SUCCESS)
			return;
		data = isc_mem_get(mctx, sizeof *data);
		if (data == NULL)
			return;
		*data = offset;
		result = dns_rbt_addname(root, &full, data);
		if (result != DNS_R_SUCCESS) {
			isc_mem_put(mctx, data, sizeof *data);
			return;
		}
		dns_name_getlabel(&name, 0, &label);
		offset += label.length;
		start++;
		count--;
	}
}

/*
 *	Find the longest match of name in root.
 *	If match is found return ISC_TRUE. prefix, suffix and offset
 *	are updated.
 *	If no match is found return ISC_FALSE.
 */

isc_boolean_t
compress_find(dns_rbt_t *root, dns_name_t *name, dns_name_t *prefix,
	      dns_name_t *suffix, isc_uint16_t *offset,
	      isc_buffer_t *workspace)
{
	dns_fixedname_t found;
	dns_name_t *foundname;
	dns_name_t tmpprefix;
	dns_name_t tmpsuffix;
	isc_result_t result;
	isc_uint16_t *data = NULL;
	dns_label_t foundlabel;
	dns_label_t namelabel;
	unsigned int foundlabels;
	unsigned int namelabels;
	unsigned int foundbits;
	unsigned int namebits;
	unsigned int bits;
	unsigned int prefixlen;
	unsigned int j;
	unsigned char buf[2 + 256/8];	/* size of biggest bit label */
	dns_bitlabel_t bit;
	isc_region_t region;

	dns_fixedname_init(&found);
	foundname = dns_fixedname_name(&found);
	result = dns_rbt_findname(root, name, foundname, (void *)&data);
	if (result != DNS_R_SUCCESS && result != DNS_R_PARTIALMATCH)
		return (ISC_FALSE);
	if (data == NULL)		/* root label */
		return (ISC_FALSE);
	/*
	 * Do we have to do bit string processing?
	 */
	dns_name_getlabel(foundname, 0, &foundlabel);
	foundlabels = dns_name_countlabels(foundname);
	INSIST(foundlabels > 1);	/* root labels are not added to tree */
	namelabels = dns_name_countlabels(name);
	if (dns_label_type(&foundlabel) == dns_labeltype_bitstring) {
		dns_name_getlabel(name, namelabels - foundlabels, &namelabel);
		INSIST(dns_label_type(&namelabel) == dns_labeltype_bitstring);
		foundbits = dns_label_countbits(&foundlabel);
		namebits = dns_label_countbits(&namelabel);
	} else
		namebits = foundbits = 0;

	if (namebits == foundbits) {
		INSIST(namelabels >= foundlabels);
		prefixlen = namelabels - foundlabels;
		if (prefixlen == 0) {
			prefix->length = 0;
			prefix->labels = 0;
		} else
			dns_name_getlabelsequence(name, 0, prefixlen, prefix);
		result = dns_name_concatenate(NULL, foundname, suffix,
					     workspace);
		if (result != DNS_R_SUCCESS)
			return (ISC_FALSE);
		*offset = *data;
		return (ISC_TRUE);
	}
	/*
	 * At this stage we have a bit string label to split in two.
	 * There is potentially a prefix before this label and definitly
	 * a suffix after it (if only the root).
	 */
	INSIST(result == DNS_R_PARTIALMATCH);
	result = dns_name_concatenate(NULL, foundname, suffix, workspace);
	if (result != DNS_R_SUCCESS)
		return (ISC_FALSE);
	prefixlen = namelabels - foundlabels;
	dns_name_init(&tmpprefix, NULL);
	dns_name_init(&tmpsuffix, NULL);
	if (prefixlen != 0) {
		dns_name_getlabelsequence(name, 0, prefixlen, &tmpprefix);
	}
	INSIST(namebits > foundbits);
	bits = namebits - foundbits;
	j = 0;
	memset(buf, 0, sizeof buf);
	INSIST((bits / 8 + 1) < sizeof buf);
	/*
	 * Copy least significant bits.
	 */
	while (j < bits) {
		bit = dns_label_getbit(&namelabel, foundbits + j);
		if (bit)
			buf[2 + j / 8] |= (1 << (7 - (j % 8)));
		j++;
	}
	buf[0] = DNS_LABELTYPE_BITSTRING;
	buf[1] = j;
	region.base = buf;
	region.length = 2 + (j + 7) / 8;
	dns_name_fromregion(&tmpsuffix, &region);
	result = dns_name_concatenate(&tmpprefix, &tmpsuffix, prefix,
				      workspace);
	if (result != DNS_R_SUCCESS)
		return (ISC_FALSE);
	*offset = *data;
	return (ISC_TRUE);
}
