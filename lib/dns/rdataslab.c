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

/* $Id: rdataslab.c,v 1.9 2000/02/03 23:43:58 halley Exp $ */

#include <config.h>

#include <string.h>

#include <isc/region.h>
#include <isc/buffer.h>
#include <isc/assertions.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>

isc_result_t
dns_rdataslab_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			   isc_region_t *region, unsigned int reservelen)
{
	dns_rdata_t	rdata;
	unsigned char  *rawbuf;
	unsigned int	buflen;
	isc_result_t	result;
	unsigned int	nitems;

	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_SUCCESS);

	buflen = reservelen + 2;
	nitems = 0;

	/*
	 * Run through the rdataset list once, counting up the size
	 * of all the rdata members within it.  We do not store the
	 * class, type, etc, just the rdata, so our overhead is 2 bytes
	 * for the number of records, and 2 for each rdata length, and
	 * then the rdata itself.
	 */
	do {
		dns_rdataset_current(rdataset, &rdata);
		buflen += (2 + rdata.length);

		nitems++;

		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE)
		return (result);

	/*
	 * Allocate the memory, set up a buffer, start copying in
	 * data.
	 */
	rawbuf = isc_mem_get(mctx, buflen);
	if (rawbuf == NULL)
		return (DNS_R_NOMEMORY);

	region->base = rawbuf;
	region->length = buflen;

	rawbuf += reservelen;

	*rawbuf++ = (nitems & 0xff00) >> 8;
	*rawbuf++ = (nitems & 0x00ff);
	result = dns_rdataset_first(rdataset);
	REQUIRE(result == DNS_R_SUCCESS);
	do {
		dns_rdataset_current(rdataset, &rdata);
		*rawbuf++ = (rdata.length & 0xff00) >> 8;
		*rawbuf++ = (rdata.length & 0x00ff);
		memcpy(rawbuf, rdata.data, rdata.length);
		rawbuf += rdata.length;

		result = dns_rdataset_next(rdataset);
	} while (result == DNS_R_SUCCESS);

	if (result != DNS_R_NOMORE) {
		isc_mem_put(mctx, region->base, region->length);
		region->base = NULL;
		region->length = 0;

		return (result);
	}

	return (DNS_R_SUCCESS);
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

isc_result_t
dns_rdataslab_merge(unsigned char *oslab, unsigned char *nslab,
		    unsigned int reservelen, isc_mem_t *mctx,
		    dns_rdataclass_t rdclass, dns_rdatatype_t type,
		    isc_boolean_t force, unsigned char **tslabp)
{
	unsigned char *ocurrent, *ostart, *ncurrent, *tstart, *tcurrent;
	unsigned int ocount, ncount, count, olength, tlength, tcount, length;
	isc_region_t oregion, nregion;
	dns_rdata_t ordata, nrdata;
	isc_boolean_t added_something = ISC_FALSE;

	/*
	 * Merge 'oslab' and 'nslab'.
	 */

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
		ocurrent = ostart;
		for (count = 0; count < ocount; count++) {
			oregion.length = *ocurrent++ * 256;
			oregion.length += *ocurrent++;
			oregion.base = ocurrent;
			dns_rdata_fromregion(&ordata, rdclass, type, &oregion);
			ocurrent += oregion.length;
			if (dns_rdata_compare(&ordata, &nrdata) == 0)
				break;
		}
		if (count == ocount) {
			/*
			 * This rdata isn't in the old slab.
			 */
			tlength += nregion.length + 2;
			tcount++;
			added_something = ISC_TRUE;
		}
		ncurrent += nregion.length;
		ncount--;
	} while (ncount > 0);

	if (!added_something && !force)
		return (DNS_R_UNCHANGED);

	/*
	 * Copy the reserved area from the new slab.
	 */
	tstart = isc_mem_get(mctx, tlength);
	if (tstart == NULL)
		return (DNS_R_NOMEMORY);
	memcpy(tstart, nslab, reservelen);
	tcurrent = tstart + reservelen;
	
	/*
	 * Write the new count.
	 */
	*tcurrent++ = (tcount & 0xff00) >> 8;
	*tcurrent++ = (tcount & 0x00ff);

	/*
	 * Copy the old slab.
	 */
	memcpy(tcurrent, ostart, olength);
	tcurrent += olength;

	/*
	 * Copy the new parts of the new slab.
	 */
	ncurrent = nslab + reservelen;
	ncount = *ncurrent++ * 256;
	ncount += *ncurrent++;
	do {
		nregion.length = *ncurrent++ * 256;
		nregion.length += *ncurrent++;
		nregion.base = ncurrent;
		dns_rdata_fromregion(&nrdata, rdclass, type, &nregion);
		ocurrent = ostart;
		for (count = 0; count < ocount; count++) {
			oregion.length = *ocurrent++ * 256;
			oregion.length += *ocurrent++;
			oregion.base = ocurrent;
			dns_rdata_fromregion(&ordata, rdclass, type, &oregion);
			ocurrent += oregion.length;
			if (dns_rdata_compare(&ordata, &nrdata) == 0)
				break;
		}
		if (count == ocount) {
			/*
			 * This rdata isn't in the old slab.
			 */
			*tcurrent++ = (nregion.length & 0xff00) >> 8;
			*tcurrent++ = (nregion.length & 0x00ff);
			memcpy(tcurrent, nregion.base, nregion.length);
			tcurrent += nregion.length;
		}
		ncurrent += nregion.length;
		ncount--;
	} while (ncount > 0);

	*tslabp = tstart;

	return (DNS_R_SUCCESS);
}

isc_result_t
dns_rdataslab_subtract(unsigned char *mslab, unsigned char *sslab,
		       unsigned int reservelen, isc_mem_t *mctx,
		       dns_rdataclass_t rdclass, dns_rdatatype_t type,
		       unsigned char **tslabp)
{
	unsigned char *mcurrent, *sstart, *scurrent, *tstart, *tcurrent;
	unsigned int mcount, scount, count, tlength, tcount;
	isc_region_t mregion, sregion;
	dns_rdata_t srdata, mrdata;
	isc_boolean_t removed_something = ISC_FALSE;

	/*
	 * Subtract 'sslab' from 'mslab'.
	 */

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
		mregion.length = *mcurrent++ * 256;
		mregion.length += *mcurrent++;
		mregion.base = mcurrent;
		dns_rdata_fromregion(&mrdata, rdclass, type, &mregion);
		scurrent = sstart;
		for (count = 0; count < scount; count++) {
			sregion.length = *scurrent++ * 256;
			sregion.length += *scurrent++;
			sregion.base = scurrent;
			dns_rdata_fromregion(&srdata, rdclass, type, &sregion);
			scurrent += sregion.length;
			if (dns_rdata_compare(&mrdata, &srdata) == 0)
				break;
		}
		if (count == scount) {
			/*
			 * This rdata isn't in the sslab, and thus isn't
			 * being subtracted.
			 */
			tlength += mregion.length + 2;
			tcount++;
		} else
			removed_something = ISC_TRUE;
		mcurrent += mregion.length;
		mcount--;
	} while (mcount > 0);

	/*
	 * Don't continue if the new rdataslab would be empty.
	 */
	if (tcount == 0)
		return (DNS_R_NXRDATASET);

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
		return (DNS_R_NOMEMORY);
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
		mregion.length = *mcurrent++ * 256;
		mregion.length += *mcurrent++;
		mregion.base = mcurrent;
		dns_rdata_fromregion(&mrdata, rdclass, type, &mregion);
		scurrent = sstart;
		for (count = 0; count < scount; count++) {
			sregion.length = *scurrent++ * 256;
			sregion.length += *scurrent++;
			sregion.base = scurrent;
			dns_rdata_fromregion(&srdata, rdclass, type, &sregion);
			scurrent += sregion.length;
			if (dns_rdata_compare(&mrdata, &srdata) == 0)
				break;
		}
		if (count == scount) {
			/*
			 * This rdata isn't in the sslab, and thus should be
			 * copied to the tslab.
			 */
			*tcurrent++ = (mregion.length & 0xff00) >> 8;
			*tcurrent++ = (mregion.length & 0x00ff);
			memcpy(tcurrent, mregion.base, mregion.length);
			tcurrent += mregion.length;
		}
		mcurrent += mregion.length;
		mcount--;
	} while (mcount > 0);

	*tslabp = tstart;

	return (DNS_R_SUCCESS);
}
