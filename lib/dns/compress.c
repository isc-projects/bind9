/*
 * Copyright (C) 1999 Internet Software Consortium.
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

 /* $Id: compress.c,v 1.2 1999/02/23 02:25:39 marka Exp $ */

#include <config.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/buffer.h>

#include <dns/compress.h>

#define CCTX_MAGIC	0x43435458U
#define VALID_CCTX(x)	((x) != NULL && (x)->magic == CCTX_MAGIC)

static void		free_offset(void *offset, void *mctx);
isc_boolean_t		compress_find(dns_rbt_t *root, dns_name_t *name,
				      dns_name_t *prefix, dns_name_t *suffix,
				      isc_uint16_t *offset,
				      isc_buffer_t *workspace);
void			compress_add(dns_rbt_t *root, dns_name_t *prefix,
				     dns_name_t *suffix, isc_uint16_t offset,
				     isc_boolean_t global16, isc_mem_t *mctx);


dns_result_t
dns_compress_init(dns_compress_t *cctx, int edns, isc_mem_t *mctx)
{
	dns_result_t result;

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

dns_result_t
dns_compress_localinit(dns_compress_t *cctx, dns_name_t *owner,
		       isc_buffer_t *target)
{
	dns_result_t result;
	unsigned int labels;
	unsigned int ll, wl;
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
	REQUIRE(target != NULL);

	result = dns_rbt_create(cctx->mctx, free_offset, cctx->mctx,
				&cctx->local);
	if (result != DNS_R_SUCCESS)
		return (result);

	/*
	 * Errors from here on are not passed back up.
	 */
	cctx->rdata = target->used;	/* XXX layer violation */
	labels = dns_name_countlabels(owner);
	ll = 0;
	wl = 0;
	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);
	dns_name_init(&suffix, NULL);
	/*
	 * XXX we should be adding all the logical label in a
	 * bit stream as well.
	 * See also compress_add().
	 */
	while (labels > 0) {
		dns_name_getlabelsequence(owner, wl, labels, &name);
		data = isc_mem_get(cctx->mctx, sizeof *data);
		if (data != NULL)
			return (DNS_R_SUCCESS);
		*data = ll;
		result = dns_rbt_addname(cctx->local, &name, data);
		if (result != DNS_R_SUCCESS) {
			isc_mem_put(cctx->mctx, data, sizeof *data);
			return (DNS_R_SUCCESS);
		}
		labels --;
		wl++;
		ll++;
		if (ll > 255)
			return (DNS_R_SUCCESS);
		dns_name_getlabel(&name, 0, &label);
		if (dns_label_type(&label) != dns_labeltype_bitstring)
			continue;
		bits = dns_label_countbits(&label);
		if (bits == 1)
			continue;
		INSIST(label.length < sizeof buf);
		memcpy(buf, label.base, label.length);
		region.base = buf;
		dns_name_getlabelsequence(owner, wl, labels, &suffix);
		do {
			/* clear bit */
			buf[2 + bits / 8] &= ~(1 << (7 - (bits % 8)));
			bits--;
			region.length = 2 + (bits + 7) / 8;
			buf[1] = bits;
			dns_name_fromregion(&prefix, &region);
			isc_buffer_init(&t, namebuf, sizeof namebuf,
					ISC_BUFFERTYPE_BINARY);
			result = dns_name_cat(&prefix, &suffix, &name, &t);
			if (result != DNS_R_SUCCESS)
				return (DNS_R_SUCCESS);
			data = isc_mem_get(cctx->mctx, sizeof *data);
			if (data != NULL)
				return (DNS_R_SUCCESS);
			*data = ll;
			result = dns_rbt_addname(cctx->local, &name, data);
			if (result != DNS_R_SUCCESS) {
				isc_mem_put(cctx->mctx, data, sizeof *data);
				return (DNS_R_SUCCESS);
			}
			ll++;
			if (ll > 255)
				return (DNS_R_SUCCESS);
		} while (bits > 1);
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
		 dns_name_t *suffix, isc_uint16_t offset)
{
	isc_uint16_t local;
	REQUIRE(VALID_CCTX(cctx));

	if (cctx->local != NULL && (cctx->allowed & DNS_COMPRESS_LOCAL) != 0) {
		REQUIRE(cctx->rdata <= offset);
		local = offset - cctx->rdata + 256;
		compress_add(cctx->local, prefix, suffix, local, ISC_TRUE,
			     cctx->mctx);
	}
	compress_add(cctx->global, prefix, suffix, offset, cctx->global16,
		     cctx->mctx);
}

void
dns_compress_backout(dns_compress_t *cctx, isc_uint16_t offset) {
	REQUIRE(VALID_CCTX(cctx));

	/* XXX need tree walking code */
	/* Remove all nodes in cctx->global that have *data >= offset. */

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
	dns_result_t result;
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
		result = dns_name_cat(&name, suffix, &full, &target);
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
 *	Find the loggest match of name in root.
 *	If match is found return ISC_TRUE. prefix, suffix and offset
 *	are updated.
 *	If no match is found return ISC_FALSE.
 *	XXX should used dns_rbt_findlongestmatch() when written.
 */

isc_boolean_t
compress_find(dns_rbt_t *root, dns_name_t *name, dns_name_t *prefix,
	      dns_name_t *suffix, isc_uint16_t *offset,
	      isc_buffer_t *workspace)
{
	unsigned int count;
	unsigned int labels;
	unsigned int start;
	unsigned int bits;
	isc_uint16_t *data;
	dns_name_t tmpname;
	dns_name_t tmpprefix;
	dns_name_t tmpsuffix;
	isc_region_t region;
	unsigned char buf[255];
	dns_label_t label;
	unsigned int i, j;
	dns_result_t result;
	dns_bitlabel_t bit;

	labels = count = dns_name_countlabels(name);
	start = 0;
	data = NULL;
	bits = 0;

	dns_name_init(&tmpname, NULL);
	dns_name_init(&tmpsuffix, NULL);
	dns_name_init(&tmpprefix, NULL);
	/* Don't look for the root label (count == 1). */
	while (count > 1) {
		dns_name_getlabelsequence(name, start, count, &tmpname);
		data = dns_rbt_findname(root, &tmpname);
		if (data != NULL)
			break;
		count--;
		start++;
		if (workspace == NULL)
			continue;
		dns_name_getlabel(&tmpname, 0, &label);
		if (dns_label_type(&label) != dns_labeltype_bitstring)
			continue;
		bits = dns_label_countbits(&label);
		if (bits == 1) {
			bits = 0;
			continue;
		}
		INSIST(label.length < sizeof buf);
		memcpy(buf, label.base, label.length);
		region.base = buf;
		dns_name_getlabelsequence(name, start, count, &tmpsuffix);
		do {
			/* clear lsb */
			buf[2 + bits / 8] &= ~(1 << (7 - (bits % 8)));
			bits--;
			region.length = 2 + (bits + 7) / 8;
			buf[1] = bits;
			dns_name_fromregion(&tmpprefix, &region);
			isc_buffer_clear(workspace);
			result = dns_name_cat(&tmpprefix, &tmpsuffix,
						&tmpname, workspace);
			if (result != DNS_R_SUCCESS)
				continue;
			data = dns_rbt_findname(root, &tmpname);
			if (data != NULL)
				break;
			if (bits == 1)
				bits = 0;
		} while (bits > 1);
		if (data != NULL)
			break;
	}
	if (data == NULL)
		return (ISC_FALSE);
	if (bits == 0) {
		if (start != 0)
			dns_name_getlabelsequence(name, 0, start, prefix);
		else {
			prefix->length = 0;
			prefix->labels = 0;
		}
		dns_name_getlabelsequence(name, start, count, suffix);
		*offset = *data;
		return (ISC_TRUE);
	}
	INSIST(start > 0);
	*suffix = tmpname;
	i = dns_label_countbits(&label);
	j = 0;
	while (bits < i) {
		bit = dns_label_getbit(&label, bits);
		bits++;
		if (bit)
			buf[2 + j / 8] |= (1 << (7 - (j % 8)));
		else
			buf[2 + j / 8] &= ~(1 << (7 - (j % 8)));
		j++;
	}
	buf[1] = j;
	while ((j % 8) != 0) {
		buf[2 + j / 8] &= ~(1 << (7 - (j % 8)));
		j++;
	}
	region.base = buf;
	region.length = 2 + j / 8;
	dns_name_fromregion(&tmpsuffix, &region);
	if (start == 1)
		dns_name_init(&tmpprefix, NULL);
	else
		dns_name_getlabelsequence(name, 0, start - 1, &tmpprefix);
	result = dns_name_cat(&tmpprefix, &tmpsuffix, prefix, workspace);
	if (result != DNS_R_SUCCESS)
		return (ISC_FALSE);
	*offset = *data;
	return (ISC_TRUE);
}
