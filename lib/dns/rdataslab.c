/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: rdataslab.c,v 1.20 2000/09/23 01:05:03 bwelling Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/mem.h>
#include <isc/region.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/result.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>

/* Note: the "const void *" are just to make qsort happy. */
static int
compare_rdata(const void *p1, const void *p2) {
	const dns_rdata_t *rdata1 = p1;
	const dns_rdata_t *rdata2 = p2;
	return (dns_rdata_compare(rdata1, rdata2));
}

isc_result_t
dns_rdataslab_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			   isc_region_t *region, unsigned int reservelen)
{
	dns_rdata_t    *rdatas;
	unsigned char  *rawbuf;
	unsigned int	buflen;
	isc_result_t	result;
	unsigned int	nitems;
	unsigned int	nalloc;
	unsigned int	i;

	buflen = reservelen + 2;

	nalloc = dns_rdataset_count(rdataset);
	nitems = nalloc;

	rdatas = isc_mem_get(mctx, nalloc * sizeof(dns_rdata_t));
	if (rdatas == NULL)
		return (ISC_R_NOMEMORY);

	/*
	 * Save all of the rdata members into an array.
	 */
	result = dns_rdataset_first(rdataset);
	INSIST(result == ISC_R_SUCCESS);
	for (i = 0; i < nalloc; i++) {
		INSIST(result == ISC_R_SUCCESS);
		dns_rdataset_current(rdataset, &rdatas[i]);
		result = dns_rdataset_next(rdataset);
	}
	INSIST(result == ISC_R_NOMORE);

	qsort(rdatas, nalloc, sizeof(dns_rdata_t), compare_rdata);

	/*
	 * Remove duplicates.
	 */
	for (i = 1; i < nalloc; i++) {
		if (compare_rdata(&rdatas[i-1], &rdatas[i]) == 0) {
			rdatas[i-1].data = NULL;
			rdatas[i-1].length = 0;
			nitems--;
		}
	}

	/*
	 * Run through the rdataset list once, counting up the size
	 * of all the rdata members within it.  We do not store the
	 * class, type, etc, just the rdata, so our overhead is 2 bytes
	 * for the number of records, and 2 for each rdata length, and
	 * then the rdata itself.
	 */
	for (i = 0; i < nalloc; i++) {
		if (rdatas[i].data != NULL)
			buflen += (2 + rdatas[i].length);
		result = dns_rdataset_next(rdataset);
	}

	if (result != ISC_R_NOMORE) {
		isc_mem_put(mctx, rdatas, nalloc * sizeof(dns_rdata_t));
		return (result);
	}

	/*
	 * Allocate the memory, set up a buffer, start copying in
	 * data.
	 */
	rawbuf = isc_mem_get(mctx, buflen);
	if (rawbuf == NULL) {
		result = ISC_R_NOMEMORY;
		goto free_rdatas;
	}

	region->base = rawbuf;
	region->length = buflen;

	rawbuf += reservelen;

	*rawbuf++ = (nitems & 0xff00) >> 8;
	*rawbuf++ = (nitems & 0x00ff);
	for (i = 0; i < nalloc; i++) {
		if (rdatas[i].data == NULL)
			continue;
		*rawbuf++ = (rdatas[i].length & 0xff00) >> 8;
		*rawbuf++ = (rdatas[i].length & 0x00ff);
		memcpy(rawbuf, rdatas[i].data, rdatas[i].length);
		rawbuf += rdatas[i].length;
	}
	result = ISC_R_SUCCESS;

 free_rdatas:
	isc_mem_put(mctx, rdatas, nalloc * sizeof(dns_rdata_t));
	return (result);
}

unsigned int
dns_rdataslab_size(unsigned char *slab, unsigned int reservelen) {
	unsigned int count, length;
	unsigned char *current;

	REQUIRE(slab != NULL);

	current = slab + reservelen;
	count = *current++ * 256;
	count += *current++;
	while (count > 0) {
		count--;
		length = *current++ * 256;
		length += *current++;
		current += length;
	}

	return ((unsigned int)(current - slab));
}

/*
 * Make the dns_rdata_t 'rdata' refer to the slab item
 * beginning at '*current', which is part of a slab of type
 * 'type' and class 'rdclass', and advance '*current' to
 * point to the next item in the slab.
 */
static inline void
rdata_from_slab(unsigned char **current,
	      dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      dns_rdata_t *rdata)
{
	unsigned char *tcurrent = *current;
	isc_region_t region;

	region.length = *tcurrent++ * 256;
	region.length += *tcurrent++;
	region.base = tcurrent;
	tcurrent += region.length;
	dns_rdata_fromregion(rdata, rdclass, type, &region);
	*current = tcurrent;
}

/*
 * Return true iff 'slab' (slab data of type 'type' and class 'rdclass')
 * contains an rdata identical to 'rdata'.  This does case insensitive
 * comparisons per DNSSEC.
 */
static inline isc_boolean_t
rdata_in_slab(unsigned char *slab, unsigned int reservelen,
	      dns_rdataclass_t rdclass, dns_rdatatype_t type,
	      dns_rdata_t *rdata)
{
	unsigned int count, i;
	unsigned char *current;
	dns_rdata_t trdata;

	current = slab + reservelen;
	count = *current++ * 256;
	count += *current++;

	dns_rdata_init(&trdata);

	for (i = 0; i < count; i++) {
		rdata_from_slab(&current, rdclass, type, &trdata);
		if (dns_rdata_compare(&trdata, rdata) == 0)
			return (ISC_TRUE);
	}
	return (ISC_FALSE);
}

isc_result_t
dns_rdataslab_merge(unsigned char *oslab, unsigned char *nslab,
		    unsigned int reservelen, isc_mem_t *mctx,
		    dns_rdataclass_t rdclass, dns_rdatatype_t type,
		    isc_boolean_t force, unsigned char **tslabp)
{
	unsigned char *ocurrent, *ostart, *ncurrent, *tstart, *tcurrent;
	unsigned int ocount, ncount, count, olength, tlength, tcount, length;
	isc_region_t nregion;
	dns_rdata_t ordata, nrdata;
	isc_boolean_t added_something = ISC_FALSE;
	unsigned int oadded = 0;
	unsigned int nadded = 0;
	unsigned int nncount = 0;

	/*
	 * XXX  Need parameter to allow "delete rdatasets in nslab" merge,
	 * or perhaps another merge routine for this purpose.
	 */

	REQUIRE(tslabp != NULL && *tslabp == NULL);
	REQUIRE(oslab != NULL && nslab != NULL);

	ocurrent = oslab + reservelen;
	ocount = *ocurrent++ * 256;
	ocount += *ocurrent++;
	ostart = ocurrent;
	ncurrent = nslab + reservelen;
	ncount = *ncurrent++ * 256;
	ncount += *ncurrent++;
	INSIST(ocount > 0 && ncount > 0);

	/*
	 * Yes, this is inefficient!
	 */

	/*
	 * Figure out the length of the old slab's data.
	 */
	olength = 0;
	for (count = 0; count < ocount; count++) {
		length = *ocurrent++ * 256;
		length += *ocurrent++;
		olength += length + 2;
		ocurrent += length;
	}

	/*
	 * Start figuring out the target length and count.
	 */
	tlength = reservelen + 2 + olength;
	tcount = ocount;

	/*
	 * Add in the length of rdata in the new slab that aren't in
	 * the old slab.
	 */
	do {
		nregion.length = *ncurrent++ * 256;
		nregion.length += *ncurrent++;
		nregion.base = ncurrent;
		dns_rdata_fromregion(&nrdata, rdclass, type, &nregion);
		if (!rdata_in_slab(oslab, reservelen, rdclass, type, &nrdata))
		{
			/*
			 * This rdata isn't in the old slab.
			 */
			tlength += nregion.length + 2;
			tcount++;
			nncount++;
			added_something = ISC_TRUE;
		}
		ncurrent += nregion.length;
		ncount--;
	} while (ncount > 0);
	ncount = nncount;

	if (!added_something && !force)
		return (DNS_R_UNCHANGED);

	/*
	 * Copy the reserved area from the new slab.
	 */
	tstart = isc_mem_get(mctx, tlength);
	if (tstart == NULL)
		return (ISC_R_NOMEMORY);
	memcpy(tstart, nslab, reservelen);
	tcurrent = tstart + reservelen;

	/*
	 * Write the new count.
	 */
	*tcurrent++ = (tcount & 0xff00) >> 8;
	*tcurrent++ = (tcount & 0x00ff);

	/*
	 * Merge the two slabs.
	 */
	ocurrent = ostart;
	INSIST(ocount != 0);
	rdata_from_slab(&ocurrent, rdclass, type, &ordata);

	ncurrent = nslab + reservelen + 2;
	if (ncount > 0) {
		do {
       			rdata_from_slab(&ncurrent, rdclass, type, &nrdata);
		} while (rdata_in_slab(oslab, reservelen, rdclass,
				       type, &nrdata));
	}

	while (oadded < ocount || nadded < ncount) {
		isc_boolean_t fromold;
		if (oadded == ocount)
			fromold = ISC_FALSE;
		else if (nadded == ncount)
			fromold = ISC_TRUE;
		else
			fromold = ISC_TF(compare_rdata(&ordata, &nrdata) < 0);
		if (fromold) {
			length = ordata.length;
			*tcurrent++ = (length & 0xff00) >> 8;
			*tcurrent++ = (length & 0x00ff);
			memcpy(tcurrent, ordata.data, length);
			tcurrent += length;
			oadded++;
			if (oadded < ocount) {
       				rdata_from_slab(&ocurrent, rdclass, type,
						&ordata);
			}
		} else {
			length = nrdata.length;
			*tcurrent++ = (length & 0xff00) >> 8;
			*tcurrent++ = (length & 0x00ff);
			memcpy(tcurrent, nrdata.data, length);
			tcurrent += length;
			nadded++;
			if (nadded < ncount) {
				do {
       					rdata_from_slab(&ncurrent, rdclass,
							type, &nrdata);
				} while (rdata_in_slab(oslab, reservelen,
						       rdclass, type,
						       &nrdata));
			}
		}
	}

	INSIST(tcurrent == tstart + tlength);

	*tslabp = tstart;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_rdataslab_subtract(unsigned char *mslab, unsigned char *sslab,
		       unsigned int reservelen, isc_mem_t *mctx,
		       dns_rdataclass_t rdclass, dns_rdatatype_t type,
		       unsigned char **tslabp)
{
	unsigned char *mcurrent, *sstart, *scurrent, *tstart, *tcurrent;
	unsigned int mcount, scount, count, tlength, tcount;
	dns_rdata_t srdata, mrdata;
	isc_boolean_t removed_something = ISC_FALSE;

	REQUIRE(tslabp != NULL && *tslabp == NULL);
	REQUIRE(mslab != NULL && sslab != NULL);

	mcurrent = mslab + reservelen;
	mcount = *mcurrent++ * 256;
	mcount += *mcurrent++;
	scurrent = sslab + reservelen;
	scount = *scurrent++ * 256;
	scount += *scurrent++;
	sstart = scurrent;
	INSIST(mcount > 0 && scount > 0);

	/*
	 * Yes, this is inefficient!
	 */

	/*
	 * Start figuring out the target length and count.
	 */
	tlength = reservelen + 2;
	tcount = 0;

	/*
	 * Add in the length of rdata in the mslab that aren't in
	 * the sslab.
	 */
	do {
		unsigned char *mrdatabegin = mcurrent;
		rdata_from_slab(&mcurrent, rdclass, type, &mrdata);
		scurrent = sstart;
		for (count = 0; count < scount; count++) {
			rdata_from_slab(&scurrent, rdclass, type, &srdata);
			if (dns_rdata_compare(&mrdata, &srdata) == 0)
				break;
		}
		if (count == scount) {
			/*
			 * This rdata isn't in the sslab, and thus isn't
			 * being subtracted.
			 */
			tlength += mcurrent - mrdatabegin;
			tcount++;
		} else
			removed_something = ISC_TRUE;
		mcount--;
	} while (mcount > 0);

	/*
	 * Don't continue if the new rdataslab would be empty.
	 */
	if (tcount == 0)
		return (DNS_R_NXRRSET);

	/*
	 * If nothing is going to change, we can stop.
	 */
	if (!removed_something)
		return (DNS_R_UNCHANGED);

	/*
	 * Copy the reserved area from the mslab.
	 */
	tstart = isc_mem_get(mctx, tlength);
	if (tstart == NULL)
		return (ISC_R_NOMEMORY);
	memcpy(tstart, mslab, reservelen);
	tcurrent = tstart + reservelen;

	/*
	 * Write the new count.
	 */
	*tcurrent++ = (tcount & 0xff00) >> 8;
	*tcurrent++ = (tcount & 0x00ff);

	/*
	 * Copy the parts of mslab not in sslab.
	 */
	mcurrent = mslab + reservelen;
	mcount = *mcurrent++ * 256;
	mcount += *mcurrent++;
	do {
		unsigned char *mrdatabegin = mcurrent;
		rdata_from_slab(&mcurrent, rdclass, type, &mrdata);
		scurrent = sstart;
		for (count = 0; count < scount; count++) {
			rdata_from_slab(&scurrent, rdclass, type, &srdata);
			if (dns_rdata_compare(&mrdata, &srdata) == 0)
				break;
		}
		if (count == scount) {
			/*
			 * This rdata isn't in the sslab, and thus should be
			 * copied to the tslab.
			 */
			unsigned int length = mcurrent - mrdatabegin;
			memcpy(tcurrent, mrdatabegin, length);
			tcurrent += length;
		}
		mcount--;
	} while (mcount > 0);

	INSIST(tcurrent == tstart + tlength);

	*tslabp = tstart;

	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_rdataslab_equal(unsigned char *slab1, unsigned char *slab2,
		    unsigned int reservelen)
{
	unsigned char *current1, *current2;
	unsigned int count1, count2;
	unsigned int length1, length2;

	current1 = slab1 + reservelen;
	count1 = *current1++ * 256;
	count1 += *current1++;

	current2 = slab2 + reservelen;
	count2 = *current2++ * 256;
	count2 += *current2++;

	if (count1 != count2)
		return (ISC_FALSE);

	while (count1 > 0) {
		length1 = *current1++ * 256;
		length1 += *current1++;

		length2 = *current2++ * 256;
		length2 += *current2++;

		if (length1 != length2 ||
		    memcmp(current1, current2, length1) != 0)
			return (ISC_FALSE);

		current1 += length1;
		current2 += length1;

		count1--;
	}
	return (ISC_TRUE);
}
