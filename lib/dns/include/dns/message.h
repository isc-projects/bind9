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

#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H 1

/***
 ***	Imports
 ***/

#include <isc/mem.h>
#include <isc/buffer.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/compress.h>

/*
 * How this beast works:
 *
 * When a dns message is received in a buffer, dns_message_fromwire() is called
 * on the memory region.  Various items are checked including the format
 * of the message (if counts are right, if counts consume the entire sections,
 * and if sections consume the entire message) and known pseudo-RRs in the
 * additional data section are analyzed and removed.
 *
 * TSIG checking is also done at this layer, and any DNSSEC information should
 * also be performed at this time.
 *
 * If dns_message_fromwire() returns DNS_R_MOREDATA additional
 * message packets are required.  This implies an EDNS message.
 *
 * When going from structure to wire, dns_message_towire() will return
 * DNS_R_MOREDATA if there is more data left in the output buffer that
 * could not be rendered into the exisiting buffer.
 *
 * XXX Needed:  ways to handle TSIG and DNSSEC, supply TSIG and DNSSEC
 * keys, set and retrieve EDNS information, add rdata to a section,
 * move rdata from one section to another, remove rdata, etc.
 */

ISC_LANG_BEGINDECLS

#define DNS_MESSAGEFLAG_QR		0x8000U
#define DNS_MESSAGEFLAG_AA		0x0400U
#define DNS_MESSAGEFLAG_TC		0x0200U
#define DNS_MESSAGEFLAG_RD		0x0100U
#define DNS_MESSAGEFLAG_RA		0x0080U

#define DNS_MESSAGE_OPCODE_MASK		0x7000U
#define DNS_MESSAGE_OPCODE_SHIFT	    11
#define DNS_MESSAGE_RCODE_MASK		0x000fU
#define DNS_MESSAGE_FLAG_MASK		0x1ff0U

#define DNS_MESSAGE_HEADER_LEN		    12 /* 6 u_int16_t's */

/*
 * Ordering here matters.  DNS_SECTION_ANY must be the lowest and negative,
 * and DNS_SECTION_MAX must be one greater than the last used section.
 */
typedef int dns_section_t;
#define DNS_SECTION_ANY			(-1)
#define DNS_SECTION_QUESTION		0
#define DNS_SECTION_ANSWER		1
#define DNS_SECTION_AUTHORITY		2
#define DNS_SECTION_ADDITIONAL		3
#define DNS_SECTION_OPT			4 /* pseudo-section */
#define DNS_SECTION_TSIG		5 /* pseudo-section */
#define DNS_SECTION_MAX			6

/*
 * These tell the message library how the created dns_message_t will be used.
 */
#define DNS_MESSAGE_INTENT_UNKNOWN	0 /* internal use only */
#define DNS_MESSAGE_INTENT_PARSE	1 /* parsing messages */
#define DNS_MESSAGE_INTENT_RENDER	2 /* rendering */

typedef struct dns_msgblock dns_msgblock_t;

typedef struct {
	unsigned int			magic;

	unsigned int			id;
	unsigned int			flags;
	unsigned int			rcode;
	unsigned int			opcode;
	dns_rdataclass_t		rdclass;

	/* 4 real, 2 pseudo */
	unsigned int			counts[DNS_SECTION_MAX];
	dns_namelist_t			sections[DNS_SECTION_MAX];
	dns_name_t		       *cursors[DNS_SECTION_MAX];

	int				state;
	unsigned int			from_to_wire : 2;
	unsigned int			reserved;

	isc_buffer_t		       *buffer;
	dns_compress_t			cctx;
	isc_boolean_t			need_cctx_cleanup;

	isc_mem_t		       *mctx;
	ISC_LIST(isc_dynbuffer_t)	scratchpad;
	ISC_LIST(dns_msgblock_t)	names;
	ISC_LIST(dns_msgblock_t)	rdatas;
	ISC_LIST(dns_msgblock_t)	rdatasets;
	ISC_LIST(dns_msgblock_t)	rdatalists;
	dns_name_t		       *nextname;
	dns_rdata_t		       *nextrdata;
	dns_rdataset_t		       *nextrdataset;
	dns_rdatalist_t		       *nextrdatalist;
} dns_message_t;

dns_result_t
dns_message_create(isc_mem_t *mctx, dns_message_t **msg, unsigned int intent);
/*
 * Initialize msg structure.  Must be called on a new (or reused) structure.
 *
 * This function will allocate some internal blocks of memory that are
 * exptected to be needed for parsing or rendering nearly any type of message.
 *
 * Requires:
 *	'mctx' be a valid memory context.
 *
 *	'msg' be non-null and '*msg' be NULL.
 *
 *	'intent' must be one of DNS_MESSAGE_INTENT_PARSE or
 *	DNS_MESSAGE_INTENT_RENDER.
 *
 * Ensures:
 *	The data in "*msg" is set to indicate an unused and empty msg
 *	structure.
 *
 * Returns:
 *	DNS_R_NOMEMORY		-- out of memory
 *	DNS_R_SUCCESS		-- success
 */

void
dns_message_reset(dns_message_t *msg);
/*
 * Reset a message structure to default state.  All internal lists are freed
 * or reset to a default state as well.  This is simply a more efficient
 * way to call dns_message_destroy() followed by dns_message_allocate(),
 * since it avoid many memory allocations.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	If any data loanouts (buffers, names, rdatas, etc) were requested,
 *	the caller must no longer use them after this call.
 */

void
dns_message_destroy(dns_message_t **msg);
/*
 * Destroy all state in the message.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	'msg' be "empty" with no message elements on the internal lists.
 *
 * Ensures:
 *	'msg' can be reused via re-initialization with dns_message_init()
 */

dns_result_t
dns_message_parse(dns_message_t *msg, isc_buffer_t *source);
/*
 * Parse raw wire data pointed to by "buffer" and bounded by "buflen" as a
 * DNS message.
 *
 * OPT records are detected and stored in the pseudo-section "opt".
 * TSIGs are detected and stored in the pseudo-section "tsig".  At detection
 * time, the TSIG is verified (XXX) and the message fails if the TSIG fails
 * to verify.
 *
 * If this is a multi-packet message (edns) and more data is required to
 * build the full message state, DNS_R_MOREDATA is returned.  In this case,
 * this function should be repeated with all input buffers until DNS_R_SUCCESS
 * (or an error) is returned.
 *
 * Requires:
 *	"msg" be valid.
 *
 *	"buffer" have "sane" contents.
 *
 * Ensures:
 *	The buffer's data format is correct.
 *
 *	The buffer's contents verify as correct regarding header bits, buffer
 * 	and rdata sizes, etc.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all is well
 *	DNS_R_NOMEMORY		-- no memory
 *	DNS_R_MOREDATA		-- more packets needed for complete message
 *	DNS_R_???		-- bad signature (XXX need more of these)
 */

dns_result_t
dns_message_renderbegin(dns_message_t *msg, isc_buffer_t *buffer);
/*
 * Begin rendering on a message.  Only one call can be made to this function
 * per message.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	buffer != NULL.
 *
 *	buffer is empty.
 */

dns_result_t
dns_message_renderchangebuffer(dns_message_t *msg, isc_buffer_t *buffer);
/*
 * Reset the buffer.  This can be used after growing the old buffer
 * on a DNS_R_NOSPACE return from most of the render functions.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	dns_message_renderbegin() was called.
 *
 *	buffer != NULL.
 *
 * Returns:
 *
 *	DNS_R_NOSPACE		-- new buffer is too small
 *	DNS_R_SUCCESS		-- all is well.
 */

dns_result_t
dns_message_renderreserve(dns_message_t *msg, unsigned int space);
/*
 * Reserve "space" bytes in the given buffer.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	dns_message_renderbegin() was called.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOSPACE		-- not enough free space in the buffer.
 */

dns_result_t
dns_message_renderrelease(dns_message_t *msg, unsigned int space);
/*
 * Release "space" bytes in the given buffer that was previously reserved.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	dns_message_renderbegin() was called.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOSPACE		-- trying to release more than was reserved.
 */

dns_result_t
dns_message_rendersection(dns_message_t *msg, dns_section_t section,
			  unsigned int priority, unsigned int flags);
/*
 * Render all names, rdatalists, etc from the given section at the
 * specified priority or higher.
 *
 * Requires:
 *	'msg' be valid.
 *
 *	'section' be a valid section.
 *
 *	'buffer' be non-NULL and be initialized to point to a valid memory
 *	block.
 *
 *	dns_message_renderbegin() was called.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all records were written, and there are
 *				   no more records for this section.
 *	DNS_R_NOSPACE		-- Not enough room in the buffer to write
 *				   all records requested.
 *	DNS_R_MOREDATA		-- All requested records written, and there
 *				   are records remaining for this section.
 */

dns_result_t
dns_message_renderend(dns_message_t *msg);
/*
 * Finish rendering to the buffer.  Note that more data can be in the
 * 'msg' structure.  Destroying the structure will free this, or in a multi-
 * part EDNS1 message this data can be rendered to another buffer later.
 *
 * Requires:
 *
 *	'msg' be a valid message.
 *
 *	dns_message_renderbegin() was called.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 */
		      

dns_result_t
dns_message_firstname(dns_message_t *msg, dns_section_t section);
/*
 * Set internal per-section name pointer to the beginning of the section.
 *
 * Requires:
 *
 *   	'msg' be valid.
 *
 *	'section' be a valid section.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMORE		-- No names on given section.
 */

dns_result_t
dns_message_nextname(dns_message_t *msg, dns_section_t section);
/*
 * Sets the internal per-section name pointer to point to the next name
 * in that section.
 *
 * Requires:
 *
 *   	'msg' be valid.
 *
 *	'section' be a valid section.
 *
 *	dns_message_firstname() must have been called on this section,
 *	and the result was DNS_R_SUCCESS.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMORE		-- No names in given section.
 */

void
dns_message_currentname(dns_message_t *msg, dns_section_t section,
			dns_name_t **name);
/*
 * Sets 'name' to point to the name where the per-section internal name
 * pointer is currently set.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	'name' be non-NULL, and *name be NULL.
 *
 *	'section' be a valid section.
 *
 *	dns_message_firstname() must have been called on this section,
 *	and the result of it and any dns_message_nextname() calls was
 *	DNS_R_SUCCESS.
 */

dns_result_t
dns_message_findname(dns_message_t *msg, dns_section_t section,
		     dns_name_t *target, dns_rdatatype_t type,
		     dns_name_t **name, dns_rdataset_t **rdataset);
/*
 * Search for a name in the specified section.  If it is found, *name is
 * set to point to the name, and *rdataset is set to point to the found
 * rdataset (if type is specified as other than dns_rdatatype_any.)
 *
 * Requires:
 *	'msg' be valid.
 *
 *	'section' be a valid section.
 *
 *	If a pointer to the name is desired, 'name' should be non-NULL.
 *	If it is non-NULL, '*name' MUST be NULL.
 *
 *	If a type other than dns_datatype_any is searched for, 'rdataset'
 *	may be non-NULL, '*rdataset' be NULL, and will point at the found
 *	rdataset.
 *
 *	'target' be a valid name.
 *
 *	'type' be a valid type.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NXDOMAIN		-- name does not exist in that section.
 *	DNS_R_NXRDATASET	-- The name does exist, but the desired
 *				   type does not.
 */

void
dns_message_movename(dns_message_t *msg, dns_name_t *name,
		     dns_section_t fromsection,
		     dns_section_t tosection);
/*
 * Move a name from one section to another.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	'name' must be in 'fromsection'.
 *
 *	'fromsection' must be a valid section.
 *
 *	'tosection' must be a valid section, and be renderable.
 *
 *	'fromsection' and 'tosection' cannot be the same section.
 */

void
dns_message_addname(dns_message_t *msg, dns_name_t *name,
		    dns_section_t section);
/*
 * Adds the name to the given section.
 *
 * Caller must ensure that the name does not already exist.  This condition
 * is NOT checked for by this function.
 *
 * Requires:
 *
 *	'msg' be valid, and be a renderable message.
 *
 *	'name' be a valid name.
 *
 *	'section' be a named section.
 */

ISC_LANG_ENDDECLS

#endif	/* DNS_DNS_H */
