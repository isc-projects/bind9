
#ifndef DNS_NAME_H
#define DNS_NAME_H 1

/*****
 ***** Module Info
 *****/

/*
 * DNS Names and Labels
 *
 * Provides facilities for manipulating DNS names and labels, including
 * conversions to and from wire format and text format.
 *
 * Given the large number of names possible in a nameserver, and because
 * names occur in rdata, it was important to come up with a very efficient
 * way of storing name data, but at the same time allow names to be
 * manipulated.  The decision was to store names in uncompressed wire format,
 * and not to make them fully abstracted objects; i.e. certain parts of the
 * server know names are stored that way.  This saves a lot of memory, and
 * makes adding names to messages easy.  Having much of the server know
 * the representation would be perilous, and we certainly don't want each
 * user of names to be manipulating such a low-level structure.  This is
 * where the Names and Labels module comes in.  The module allows name or
 * label handles to be created and attached to uncompressed wire format
 * regions.  All name operations and conversions are done through these
 * handles.
 *
 * MP:
 *	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *	This module deals with low-level byte streams.  Errors in any of
 *	the functions are likely to crash the server or corrupt memory.
 *
 * Resources:
 *	None.
 *
 * Security:
 *
 *	*** WARNING ***
 *
 *	dns_name_fromwire() deals with raw network data.  An error in
 *	this routine could result in the failure or hijacking of the server.
 *
 * Standards:
 *	RFC 1035
 *	Draft EDNS0 (0)
 *	Draft EDNS1 (0)
 *	Draft Binary Labels (2)
 *	Draft Local Compression (1)
 *
 */

/***
 *** Imports
 ***/

#include <isc/boolean.h>

#include <dns/types.h>



/*****
 ***** Labels
 *****
 ***** A 'label' is basically a region.  It contains one DNS wire format
 ***** label of either type 00 (ordinary) or type 01000001 (bitstring).
 *****/

#define DNS_LABELTYPE_BITSTRING		0x41

/***
 *** Properties
 ***/

dns_labeltype_t dns_label_type(dns_label_t label);
/*
 * Get the type of 'label'.
 *
 * Requires:
 *	'label' is a valid label (i.e. not NULL, points to a
 *	struct dns_label)
 *	'label' is a type 00 or type 01000001 label (i.e. not compressed).
 *
 * Returns:
 *	dns_labeltype_ordinary		type 00 label
 *	dns_labeltype_bitstring		type 01000001 label
 */

/***
 *** Bitstring Labels
 ***/

unsigned int dns_label_countbits(dns_label_t label);
/*
 * The number of bits in a bitstring label.
 *
 * Requires:
 *	'label' is a valid label
 *
 *	dns_label_type(label) == dns_labeltype_bitstring
 *
 * Ensures:
 *	Result is <= 256.
 *
 * Returns:
 *	The number of bits in the bitstring label.
 */

dns_bitlabel_t dns_label_getbit(dns_label_t label, unsigned int n);
/*
 * The 'n'th most significant bit of 'label'.
 *
 * Notes:
 *	Numbering starts at 0.
 *
 * Require:
 *	n < dns_label_countbits(label)
 *
 * Returns:
 *	dns_bitlabel_0		The bit was 0.
 *	dns_bitlabel_1		The bit was 1.
 */

/***
 *** Note
 ***
 *** Some provision still needs to be made for splitting bitstring labels,
 *** and for merging them, but doing either one requires memory in the
 *** obvious implementation.
 ***
 *** Perhaps we can simply leave merging to FromWire, and deal with splitting
 *** by some other, noncopying method.  I suspect copying is the way to go,
 *** however.
 ***/



/*****
 ***** Names
 *****
 ***** A 'name' is a handle to a binary region.  It contains a sequence of one
 ***** or more DNS wire format labels of either type 00 (ordinary) or type
 ***** 01000001 (bitstring).  Note that all names are not required to end
 ***** with the root label, as they are in the actual DNS wire protocol.
 *****/

/***
 *** Types
 ***/

/*
 * Clients are discouraged from using this type directly.
 */
struct dns_name {
	unsigned char *ndata;
	unsigned int length;
	unsigned int labels;
	unsigned char offsets[128];
};

extern dns_name_t dns_rootname;

/***
 *** Initialization
 ***/

void dns_name_init(dns_name_t name);
/*
 * Make 'name' empty.
 *
 * Requires:
 *	'name' is a valid name (i.e. not NULL, points to a struct dns_name)
 *
 * Ensures:
 *	dns_name_countlabels(name) == 0
 */


/***
 *** Properties
 ***/

isc_boolean_t dns_name_isabsolute(dns_name_t name);
/*
 * Does 'name' end in the root label?
 *
 * Requires:
 *	'name' is a valid name
 *
 *	dns_name_countlabels(name) > 0
 *
 * Returns:
 *	TRUE		The last label in 'name' is the root label.
 *	FALSE		The last label in 'name' is not the root label.
 */


/***
 *** Comparisons
 ***/

int dns_name_compare(dns_name_t name1, dns_name_t name2);
/*
 * Determine the relative ordering under the DNSSEC order relation of
 * 'name1' and 'name2'.
 *
 * Requires:
 *	'name1' is a valid name
 *
 *	dns_name_countlabels(name1) > 0
 *
 *	'name2' is a valid name
 *
 *	dns_name_countlabels(name2) > 0
 *
 * Returns:
 *	-1		'name1' is less than 'name2'
 *	0		'name1' is equal to 'name2'
 *	1		'name1' is greater than 'name2'
 */

isc_boolean_t
dns_name_issubdomain(dns_name_t name1, dns_name_t name2);
/*
 * Is 'name1' a subdomain of 'name2'?
 *
 * Notes:
 *	name1 is a subdomain of name2 if name1 is contained in name2, or
 *	name1 equals name2.
 *
 *	It makes no sense for one of the names to be relative and the
 *	other absolute.  If both names are relative, then to be meaningfully
 *	compared the caller must ensure that they are both relative to the
 *	same domain.
 *
 * Requires:
 *	'name1' is a valid name
 *
 *	dns_name_countlabels(name1) > 0
 *
 *	'name2' is a valid name
 *
 *	dns_name_countlabels(name2) > 0
 *
 * Returns:
 *	TRUE		'name1' is a subdomain of 'name2'
 *	FALSE		'name1' is not a subdomain of 'name2'
 */


/***
 *** Labels
 ***/
	
unsigned int dns_name_countlabels(dns_name_t name);
/*
 * How many labels does 'name' have?
 *
 * Notes:
 *	In this case, as in other places, a 'label' is an ordinary label
 *	or a bitstring label.  The term is not meant to refer to individual
 *	bit labels.
 *
 * Requires:
 *	'name' is a valid name
 *
 * Ensures:
 *	The result is <= 128.
 *
 * Returns:
 *	The number of labels in 'name'.
 */

void dns_name_getlabel(dns_name_t name, unsigned int n, dns_label_t label);
/*
 * Make 'label' refer to the 'n'th least significant label of 'name'.
 *
 * Notes:
 *	Numbering starts at 0.
 *
 *	Given "rc.vix.com.", the label 0 is "rc", and label 3 is the
 *	root label.
 *
 *	'label' refers to the same memory as 'name', so 'name' must not
 *	be changed while 'label' is still in use.
 *
 * Requires:
 *	n < dns_label_countlabels(name)
 */

void dns_name_getlabelsequence(dns_name_t source,
			       unsigned int first,
			       unsigned int n,
			       dns_name_t target);
/*
 * Make 'target' refer to the 'n' labels including and following 'first'
 * in 'source'.
 *
 * Notes:
 *	Numbering starts at 0.
 *
 *	'target' refers to the same memory as 'source', so 'source'
 *	must not be changed while 'target' is still in use.
 *
 * Requires:
 *	first < dns_label_countlabels(name)
 *	first + n <= dns_label_countlabels(name)
 */

/***
 *** Conversions
 ***/

void dns_name_fromregion(dns_name_t name, isc_region_t r);
/*
 * Make 'name' refer to region 'r'.
 *
 * Requires:
 *	The data in 'r' is a sequence of one or more type 00 or type 01000001
 *	labels.
 *	The length of 'r' is <= 255.
 */

void dns_name_toregion(dns_name_t name, isc_region_t r);
/*
 * Make 'r' refer to 'name'.
 *
 * Requires:
 *
 *	'name' is a valid name.
 *
 *	'r' is a valid region.
 */

dns_result_t dns_name_fromwire(dns_name_t name,
			       isc_region_t source,
			       dns_decompression_t dctx,
			       isc_boolean_t downcase,
			       isc_region_t target);
/*
 * Copy the possibly-compressed name at source into target, decompressing it.
 *
 * Notes:
 *	Decompression policy is controlled by 'dctx'.
 *
 *	If 'downcase' is true, any uppercase letters in 'source' will be
 *	downcased when they are copied into 'target'.
 *
 * Security:
 *
 *	*** WARNING ***
 *
 *	This routine will often be used when 'source' contains raw network
 *	data.  An error in this routine could result in a denial of service,
 *	or in the hijacking of the server.
 *
 * Requires:
 *
 *	'source' and 'target' are valid regions.
 *
 *	'dctx' is a valid decompression context.
 *
 * Ensures:
 *
 *	If result is success:
 *	 	'name' is attached to the target.
 *
 *		Uppercase letters are downcased in the copy iff. 'downcase' is
 *		true.
 *
 *		Any bitstring labels in source are canonicalized.
 *		(i.e. maximally packed and any padding bits zeroed.)
 *
 * Result:
 *	Success
 *	Bad Form: Label Length
 *	Bad Form: Unknown Label Type
 *	Bad Form: Name Length
 *	Bad Form: Local compression not allowed
 *	Bad Form: Compression pointer loop
 *	Bad Form: Input too short
 *	Resource Limit: Too many compression pointers
 *	Resource Limit: Not enough space in buffer
 */

dns_result_t dns_name_towire(dns_name_t name,
			     dns_compression_t cctx,
			     isc_region_t target, unsigned int *bytesp);
/*
 * Convert 'name' into wire format, compressing it as specified by the
 * compression context 'cctx', and storing the result in 'target'.
 *	
 * Notes:
 *	If the compression context allows global compression, then the
 *	global compression table may be updated.
 *
 * Requires:
 *	'name' is a valid name
 *
 *	dns_name_countlabels(name) > 0
 *
 *	dns_name_isabsolute(name) == TRUE
 *
 *	target is a valid region
 *
 *	Any offsets specified in a global compression table are valid
 *	for buffer.
 *
 * Ensures:
 *	If the result is success:
 *		Any bitstring labels are in canonical form.
 *
 *		*bytesp is the number of bytes of the target region that
 *		were used.
 *
 * Returns:
 *	Success
 *	Resource Limit: Not enough space in buffer
 */

dns_result_t dns_name_fromtext(dns_name_t name,
			       isc_region_t source,
			       dns_name_t origin,
			       isc_boolean_t downcase,
			       isc_region_t target);
/*
 * Convert the textual representation of a DNS name at source
 * into uncompressed wire form stored in target.
 *
 * Notes:
 *	Relative domain names will have 'origin' appended to them
 *	unless 'origin' is NULL, in which case relative domain names
 *	will remain relative.
 *
 *	If 'downcase' is true, any uppercase letters in 'source' will be
 *	downcased when they are copied into 'target'.
 *
 * Requires:
 *
 *	'source' and 'target' are valid regions.
 *	'name' is a valid name.
 *
 * Ensures:
 *	If result is success:
 *	 	'name' is attached to the target.
 *
 *		Any bitstring labels in source are canonicalized.
 *
 *		Uppercase letters are downcased in the copy iff. 'downcase' is
 *		true.
 *
 *		The current location in source is advanced, and the used space
 *		in target is updated.
 *
 * Result:
 *	Success
 *	Bad Form: Label Length
 *	Bad Form: Unknown Label Type
 *	Bad Form: Name Length
 *	Bad Form: Empty Label
 *	Bad Form: Input too short
 *	Resource Limit: Not enough space in buffer
 */

dns_result_t dns_name_totext(dns_name_t name,
			     isc_boolean_t omit_final_dot,
			     isc_region_t target, unsigned int *bytesp);
/*
 * Convert 'name' into text format, storing the result in 'target'.
 *	
 * Notes:
 *	If 'omit_final_dot' is true, then the final '.' in an absolute
 *	name will not be emitted.
 *
 * Requires:
 *	'name' is a valid name
 *
 *	'target' is a valid buffer
 *
 *	dns_name_countlabels(name) > 0
 *
 *	if dns_name_isabsolute == FALSE, then omit_final_dot == FALSE
 *
 * Ensures:
 *	If the result is success:
 *		Any bitstring labels are in canonical form.
 *
 *		*bytesp is the number of bytes of the target region that
 *		were used.
 *
 * Returns:
 *	Success
 *	Resource Limit: Not enough space in buffer
 */

#endif /* DNS_NAME_H */
