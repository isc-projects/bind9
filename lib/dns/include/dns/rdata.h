/*
 * Copyright (C) 1998  Internet Software Consortium.
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

#ifndef DNS_RDATA_H
#define DNS_RDATA_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Rdata
 *
 * Provides facilities for manipulating DNS rdata, including conversions to
 * and from wire format and text format.
 *
 * Given the large amount of rdata possible in a nameserver, it was important
 * to come up with a very efficient way of storing rdata, but at the same
 * time allow it to be manipulated.
 *
 * The decision was to store rdata in uncompressed wire format,
 * and not to make it a fully abstracted object; i.e. certain parts of the
 * server know rdata is stored that way.  This saves a lot of memory, and
 * makes adding rdata to messages easy.  Having much of the server know
 * the representation would be perilous, and we certainly don't want each
 * user of rdata to be manipulating such a low-level structure.  This is
 * where the rdata module comes in.  The module allows rdata handles to be
 * created and attached to uncompressed wire format regions.  All rdata
 * operations and conversions are done through these handles.
 *
 * Implementation Notes:
 *
 *	The routines in this module are expected to be synthesized by the
 *	build process from a set of source files, one per rdata type.  For
 *	portability, it's probably best that the building be done by a C
 *	program.  Adding a new rdata type will be a simple matter of adding
 *	a file to a directory and rebuilding the server.  *All* knowlege of
 *	the format of a particular rdata type is in this file.
 *
 * MP:
 *	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *	This module deals with low-level byte streams.  Errors in any of
 *	the functions are likely to crash the server or corrupt memory.
 *
 *	Rdata is typed, and the caller must know what type of rdata it has.
 *	A caller that gets this wrong could crash the server.
 *
 *	The fromstruct() and tostruct() routines use a void * pointer to
 *	represent the structure.  The caller must ensure that it passes a
 *	pointer to the appropriate type, or the server could crash or memory
 *	could be corrupted.
 *
 * Resources:
 *	None.
 *
 * Security:
 *
 *	*** WARNING ***
 *
 *	dns_rdata_fromwire() deals with raw network data.  An error in
 *	this routine could result in the failure or hijacking of the server.
 *
 * Standards:
 *	RFC 1035
 *	Draft EDNS0 (0)
 *	Draft EDNS1 (0)
 *	Draft Binary Labels (2)
 *	Draft Local Compression (1)
 *	<Various RFCs for particular types; these will be documented in the
 *	 sources files of the types.>
 *
 */

/***
 *** Imports
 ***/

#include <dns/types.h>
#include <dns/name.h>


/*****
 ***** RData
 *****
 ***** An 'rdata' is a handle to a binary region.  The handle has an RR
 ***** class and type, and the data in the binary region is in the format
 ***** of the given class and type.
 *****/

/***
 *** Types
 ***/

/*
 * Clients are strongly discouraged from using this type directly.
 */
struct dns_rdata {
	unsigned char *data;
	unsigned int length;
	dns_rdataclass_t class;
	dns_rdatatype_t type;
	/*
	 * XXX should rdata be linkable (i.e. as in <isc/list.h>) to make
	 * rdata lists easy?
	 */
};

/***
 *** Initialization
 ***/

void dns_rdata_init(dns_rdata_t *rdata);
/*
 * Make 'rdata' empty.
 *
 * Requires:
 *	'rdata' is a valid rdata (i.e. not NULL, points to a struct dns_rdata)
 */

/***
 *** Comparisons
 ***/

int dns_rdata_compare(dns_rdata_t *rdata1, dns_rdata_t *rdata2);
/*
 * Determine the relative ordering under the DNSSEC order relation of
 * 'rdata1' and 'rdata2'.
 *
 * Requires:
 *
 *	'rdata1' is a valid, non-empty rdata
 *
 *	'rdata2' is a valid, non-empty rdata
 *
 * Returns:
 *	-1		'rdata1' is less than 'rdata2'
 *	0		'rdata1' is equal to 'rdata2'
 *	1		'rdata1' is greater than 'rdata2'
 */

/***
 *** Conversions
 ***/

void dns_rdata_fromregion(dns_rdata_t *rdata,
			  dns_rdataclass_t class, dns_rdatatype_t type,
			  isc_region_t *r);
/*
 * Make 'rdata' refer to region 'r'.
 *
 * Requires:
 *
 *	The data in 'r' is properly formatted for whatever type it is.
 */

void dns_rdata_toregion(dns_rdata_t *rdata, isc_region_t *r);
/*
 * Make 'r' refer to 'rdata'.
 */

dns_result_t dns_rdata_fromwire(dns_rdata_t *rdata,
				dns_rdataclass_t class, dns_rdatatype_t type,
				isc_region_t *source,
				dns_decompression_t *dctx,
				isc_boolean_t downcase,
				isc_region_t *target);
/*
 * Copy the possibly-compressed rdata at source into the target buffer.
 *
 * Notes:
 *	Name decompression policy is controlled by 'dctx'.
 *
 *	If 'downcase' is true, any uppercase letters in domain names in
 * 	'source' will be downcased when they are copied into 'target'.
 *
 * Requires:
 *
 *	'class' and 'type' are valid.
 *
 *	'source' is a valid buffer.
 *
 *	'target' is a valid buffer.
 *
 *	'dctx' is a valid decompression context.
 *
 * Ensures:
 *
 *	If result is success:
 *	 	If 'rdata' is not NULL, it is attached to the target.
 *
 *		The conditions dns_name_fromwire() ensures for names hold
 *		for all names in the rdata.
 *
 *		The current location in source is advanced, and the used space
 *		in target is updated.
 *
 * Result:
 *	Success
 *	<Any non-success status from dns_name_fromwire()>
 *	<Various 'Bad Form' class failures depending on class and type>
 *	Bad Form: Input too short
 *	Resource Limit: Not enough space
 */

dns_result_t dns_rdata_towire(dns_rdata_t *rdata,
			      dns_compression_t *cctx,
			      isc_region_t *target, unsigned int *bytesp);
/*
 * Convert 'rdata' into wire format, compressing it as specified by the
 * compression context 'cctx', and storing the result in 'target'.
 *	
 * Notes:
 *	If the compression context allows global compression, then the
 *	global compression table may be updated.
 *
 * Requires:
 *	'rdata' is a valid, non-empty rdata
 *
 *	target is a valid buffer
 *
 *	Any offsets specified in a global compression table are valid
 *	for buffer.
 *
 * Ensures:
 *	If the result is success:
 *		*bytesp is the number of bytes of the target region that
 *		were used.
 *
 * Returns:
 *	Success
 *	<Any non-success status from dns_name_towire()>
 *	Resource Limit: Not enough space
 */

dns_result_t dns_rdata_fromtext(dns_rdata_t *rdata,
				dns_rdataclass_t class, dns_rdatatype_t type,
				dns_lex_t *lexer,
				dns_name_t *origin,
				isc_boolean_t downcase,
				isc_region_t *target, unsigned int *bytesp);
/*
 * Convert the textual representation of a DNS rdata into uncompressed wire
 * form stored in target buffer.  Tokens constituting the text of the rdata
 * are taken from 'lexer'.
 *
 * Notes:
 *	Relative domain names in the rdata will have 'origin' appended to them.
 *	If 'origin' is NULL, then relative domain names will remain relative.
 *
 *	If 'downcase' is true, any uppercase letters in domain names in
 * 	'source' will be downcased when they are copied into 'target'.
 *
 * Requires:
 *
 *	'class' and 'type' are valid.
 *
 *	'lexer' is a valid dns_lex_context.
 *
 *	'target' is a valid region.
 *
 * Ensures:
 *	If result is success:
 *	 	If 'rdata' is not NULL, it is attached to the target.
 *
 *		The conditions dns_name_fromtext() ensures for names hold
 *		for all names in the rdata.
 *
 *		*bytesp is the number of bytes of the target region that
 *		were used.
 *
 * Result:
 *	Success
 *	<Any non-success status from dns_lex_gettoken()>
 *	<Any non-success status from dns_name_fromtext()>
 *	<Various 'Bad Form' class failures depending on class and type>
 *	Bad Form: Input too short
 *	Resource Limit: Not enough space
 */

dns_result_t dns_rdata_totext(dns_rdata_t rdata,
			      dns_name_t origin,
			      buffer_t target);
/*
 * Convert 'rdata' into text format, storing the result in 'target'.
 *	
 * Notes:
 *	If 'origin' is not NULL, then any names in the rdata that are
 *	subdomains of 'origin' will be made relative it.
 *
 * Requires:
 *
 *	'rdata' is a valid, non-empty rdata
 *
 *	'origin' is NULL, or is a valid name
 *
 *	'target' is a valid buffer
 *
 * Ensures:
 *	If the result is success:
 *
 *		The used space in target is updated.
 *
 * Returns:
 *	Success
 *	<Any non-success status from dns_name_totext()>
 *	Resource Limit: Not enough space
 */

dns_result_t dns_rdata_fromstruct(dns_rdata_t *rdata,
				  dns_rdataclass_t class, dns_rdatatype_t type,
				  void *source,
				  isc_region_t *target, unsigned int *bytesp);
/*
 * Convert the C structure representation of an rdata into uncompressed wire
 * format in 'target'.
 *
 * XXX  Should we have a 'size' parameter as a sanity check on target?
 *
 * Requires:
 *
 *	'class' and 'type' are valid.
 *
 *	'source' points to a valid C struct for the class and type.
 *
 *	'target' is a valid region.
 *
 * Ensures:
 *	If result is success:
 *	 	If 'rdata' is not NULL, it is attached to the target.
 *
 *		*bytesp is the number of bytes of the target region that
 *		were used.
 *
 * Result:
 *	Success
 *	<Various 'Bad Form' class failures depending on class and type>
 *	Resource Limit: Not enough space
 */

dns_result_t dns_rdata_tostruct(dns_rdata_t *rdata, void *target);
/*
 * Convert an rdata into its C structure representation.
 *
 * XXX  Should we have a 'size' parameter as a sanity check on target?
 *
 * Requires:
 *
 *	'rdata' is a valid, non-empty rdata.
 *
 *	'target' points to a valid C struct for the class and type.
 *
 * Result:
 *	Success
 */

#endif /* DNS_RDATA_H */
