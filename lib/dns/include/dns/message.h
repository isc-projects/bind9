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

#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H 1

/***
 ***	Imports
 ***/

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/buffer.h>
#include <isc/bufferlist.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/compress.h>

#include <dst/dst.h>

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
 *
 * Notes on using the gettemp*() and puttemp*() functions:
 *
 * These functions return items (names, rdatasets, etc) allocated from some
 * internal state of the dns_message_t.  These items must be put back into
 * the dns_message_t in one of two ways.  Assume a name was allocated via
 * dns_message_gettempname():
 *
 *	(1) insert it into a section, using dns_message_addname().
 *
 *	(2) return it to the message using dns_message_puttempname().
 *
 * The same applies to rdata, rdatasets, and rdatalists which were
 * allocated using this group of functions.
 *
 * Buffers allocated using isc_buffer_allocate() can be automatically freed
 * as well by giving the buffer to the message using dns_message_takebuffer().
 * Doing this will cause the buffer to be freed using isc_buffer_free()
 * when the section lists are cleared, such as in a reset or in a destroy.
 * Since the buffer itself exists until the message is destroyed, this sort
 * of code can be written:
 *
 *	buffer = isc_buffer_allocate(mctx, 512, ISC_BUFFERTYPE_BINARY);
 *	name = NULL;
 *	name = dns_message_gettempname(message, &name);
 *	dns_name_init(name, NULL);
 *	result = dns_name_fromtext(name, &source, dns_rootname, ISC_FALSE,
 *				   buffer);
 *	dns_message_takebuffer(message, &buffer);
 *
 *
 * TODO:
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
#define DNS_MESSAGEFLAG_AD		0x0020U
#define DNS_MESSAGEFLAG_CD		0x0010U

#define DNS_MESSAGE_REPLYPRESERVE	(DNS_MESSAGEFLAG_RD)

#define DNS_MESSAGE_HEADERLEN		12 /* 6 isc_uint16_t's */

#define DNS_MESSAGE_MAGIC		0x4d534740U	/* MSG@ */
#define DNS_MESSAGE_VALID(msg)		ISC_MAGIC_VALID(msg, DNS_MESSAGE_MAGIC)

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
#define DNS_SECTION_TSIG		4 /* pseudo-section */
#define DNS_SECTION_SIG0		5 /* pseudo-section */
#define DNS_SECTION_MAX			6

/*
 * Dynamic update names for these sections.
 */
#define DNS_SECTION_ZONE		DNS_SECTION_QUESTION
#define DNS_SECTION_PREREQUISITE	DNS_SECTION_ANSWER
#define DNS_SECTION_UPDATE		DNS_SECTION_AUTHORITY

/*
 * These tell the message library how the created dns_message_t will be used.
 */
#define DNS_MESSAGE_INTENTUNKNOWN	0 /* internal use only */
#define DNS_MESSAGE_INTENTPARSE		1 /* parsing messages */
#define DNS_MESSAGE_INTENTRENDER	2 /* rendering */

/*
 * Control behavior of rendering
 */
#define DNS_MESSAGERENDER_ORDERED	0x0001	/* don't change order */

typedef struct dns_msgblock dns_msgblock_t;

struct dns_message {
	/* public from here down */
	unsigned int			magic;

	dns_messageid_t			id;
	unsigned int			flags;
	unsigned int			rcode;
	unsigned int			opcode;
	dns_rdataclass_t		rdclass;

	/* 4 real, 1 pseudo */
	unsigned int			counts[DNS_SECTION_MAX];

	/* private from here down */
	dns_namelist_t			sections[DNS_SECTION_MAX];
	dns_name_t		       *cursors[DNS_SECTION_MAX];
	dns_rdataset_t		       *opt;

	int				state;
	unsigned int			from_to_wire : 2;
	unsigned int			need_cctx_cleanup : 1;
	unsigned int			header_ok : 1;
	unsigned int			question_ok : 1;
	unsigned int			tcp_continuation : 1;
	unsigned int			verified_sig0 : 1;

	unsigned int			opt_reserved;
	unsigned int			reserved; /* reserved space (render) */

	isc_buffer_t		       *buffer;
	dns_compress_t			cctx;

	isc_mem_t		       *mctx;
	isc_mempool_t		       *namepool;
	isc_mempool_t		       *rdspool;

	isc_bufferlist_t		scratchpad;
	isc_bufferlist_t		cleanup;

	ISC_LIST(dns_msgblock_t)	rdatas;
	ISC_LIST(dns_msgblock_t)	rdatalists;

	ISC_LIST(dns_rdata_t)		freerdata;
	ISC_LIST(dns_rdatalist_t)	freerdatalist;

	dns_rcode_t			tsigstatus;
	dns_rcode_t			querytsigstatus;
	dns_rdata_any_tsig_t	       *tsig;
	dns_rdata_any_tsig_t	       *querytsig;
	dns_tsigkey_t		       *tsigkey;
	void			       *tsigctx;
	int				sigstart;

	dst_key_t		       *sig0key;
	dns_rcode_t			sig0status;
	isc_region_t		       *query;
	isc_region_t		       *saved;
};

isc_result_t
dns_message_create(isc_mem_t *mctx, unsigned int intent,
		   dns_message_t **msgp);
		   
/*
 * Create msg structure.
 *
 * This function will allocate some internal blocks of memory that are
 * expected to be needed for parsing or rendering nearly any type of message.
 *
 * Requires:
 *	'mctx' be a valid memory context.
 *
 *	'msgp' be non-null and '*msg' be NULL.
 *
 *	'intent' must be one of DNS_MESSAGE_INTENTPARSE or
 *	DNS_MESSAGE_INTENTRENDER.
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
dns_message_reset(dns_message_t *msg, unsigned int intent);
/*
 * Reset a message structure to default state.  All internal lists are freed
 * or reset to a default state as well.  This is simply a more efficient
 * way to call dns_message_destroy() followed by dns_message_allocate(),
 * since it avoid many memory allocations.
 *
 * If any data loanouts (buffers, names, rdatas, etc) were requested,
 * the caller must no longer use them after this call.
 *
 * The intended next use of the message will be 'intent'.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	'intent' is DNS_MESSAGE_INTENTPARSE or DNS_MESSAGE_INTENTRENDER
 */

void
dns_message_destroy(dns_message_t **msgp);
/*
 * Destroy all state in the message.
 *
 * Requires:
 *
 *	'msgp' be valid.
 *
 * Ensures:
 *	'*msgp' == NULL
 */

isc_result_t
dns_message_parse(dns_message_t *msg, isc_buffer_t *source,
		  isc_boolean_t preserve_order);
/*
 * Parse raw wire data pointed to by "buffer" and bounded by "buflen" as a
 * DNS message.
 *
 * OPT records are detected and stored in the pseudo-section "opt".
 * TSIGs are detected and stored in the pseudo-section "tsig".
 *
 * If 'preserve_order' is true, or if the opcode of the message is UPDATE,
 * a separate dns_name_t object will be created for each RR in the message.
 * Each such dns_name_t will have a single rdataset containing the single RR,
 * and the order of the RRs in the message is preserved.
 * Otherwise, only one dns_name_t object will be created for each unique
 * owner name in the section, and each such dns_name_t will have a list
 * of rdatasets.  To access the names and their data, use 
 * dns_message_firstname() and dns_message_nextname(). 
 *
 * OPT and TSIG records are always handled specially, regardless of the
 * 'preserve_order' setting.
 *
 * If this is a multi-packet message (edns) and more data is required to
 * build the full message state, DNS_R_MOREDATA is returned.  In this case,
 * this function should be repeated with all input buffers until DNS_R_SUCCESS
 * (or an error) is returned.
 *
 * Requires:
 *	"msg" be valid.
 *
 *	"buffer" be a wire format binary buffer.
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
 *	DNS_R_???		-- bad signature (XXXMLG need more of these)
 *	Many other errors possible XXXMLG
 */

isc_result_t
dns_message_renderbegin(dns_message_t *msg, isc_buffer_t *buffer);
/*
 * Begin rendering on a message.  Only one call can be made to this function
 * per message.
 *
 * The buffer is "owned" by the message library until dns_message_renderend()
 * is called.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	buffer is a valid binary buffer.
 *
 * Side Effects:
 *
 *	The buffer is cleared before it is used.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all is well
 *	DNS_R_NOSPACE		-- output buffer is too small
 *	Anything that dns_compress_init() can return.
 */

isc_result_t
dns_message_renderchangebuffer(dns_message_t *msg, isc_buffer_t *buffer);
/*
 * Reset the buffer.  This can be used after growing the old buffer
 * on a DNS_R_NOSPACE return from most of the render functions.
 *
 * On successful completion, the old buffer is no longer used by the
 * library.  The new buffer is owned by the library until
 * dns_message_renderend() is called.
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
 *	DNS_R_NOSPACE		-- new buffer is too small
 *	DNS_R_SUCCESS		-- all is well.
 */

isc_result_t
dns_message_renderreserve(dns_message_t *msg, unsigned int space);
/*
 * XXXMLG should use size_t rather than unsigned int once the buffer
 * API is cleaned up
 *
 * Reserve "space" bytes in the given buffer.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	dns_message_renderbegin() was called.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOSPACE		-- not enough free space in the buffer.
 */

void
dns_message_renderrelease(dns_message_t *msg, unsigned int space);
/*
 * XXXMLG should use size_t rather than unsigned int once the buffer
 * API is cleaned up
 *
 * Release "space" bytes in the given buffer that was previously reserved.
 *
 * Requires:
 *
 *	'msg' be valid.
 *
 *	'space' is less than or equal to the total amount of space reserved
 *	via prior calls to dns_message_renderreserve().
 *
 *	dns_message_renderbegin() was called.
 */

isc_result_t
dns_message_rendersection(dns_message_t *msg, dns_section_t section,
			  unsigned int options);
/*
 * Render all names, rdatalists, etc from the given section at the
 * specified priority or higher.
 *
 * Requires:
 *	'msg' be valid.
 *
 *	'section' be a valid section.
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

void
dns_message_renderheader(dns_message_t *msg, isc_buffer_t *target);
/*
 * Render the message header.  This is implicitly called by
 * dns_message_renderend().
 *
 * Requires:
 *
 *	'msg' be a valid message.
 *
 *	dns_message_renderbegin() was called.
 *
 *	'target' is a valid buffer with enough space to hold a message header
 */

isc_result_t
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
 *	DNS_R_SUCCESS		-- all is well.
 */
		      

isc_result_t
dns_message_firstname(dns_message_t *msg, dns_section_t section);
/*
 * Set internal per-section name pointer to the beginning of the section.
 *
 * The functions dns_message_firstname() and dns_message_nextname() may
 * be used for iterating over the owner names in a section. 
 *
 * Requires:
 *
 *   	'msg' be valid.
 *
 *	'section' be a valid section.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMORE		-- No names on given section.
 */

isc_result_t
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
 * This function returns the name in the database, so any data associated
 * with it (via the name's "list" member) contains the actual rdatasets.
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

isc_result_t
dns_message_findname(dns_message_t *msg, dns_section_t section,
		     dns_name_t *target, dns_rdatatype_t type,
		     dns_rdatatype_t covers, dns_name_t **foundname,
		     dns_rdataset_t **rdataset);
/*
 * Search for a name in the specified section.  If it is found, *name is
 * set to point to the name, and *rdataset is set to point to the found
 * rdataset (if type is specified as other than dns_rdatatype_any).
 *
 * Requires:
 *	'msg' be valid.
 *
 *	'section' be a valid section.
 *
 *	If a pointer to the name is desired, 'foundname' should be non-NULL.
 *	If it is non-NULL, '*foundname' MUST be NULL.
 *
 *	If a type other than dns_datatype_any is searched for, 'rdataset'
 *	may be non-NULL, '*rdataset' be NULL, and will point at the found
 *	rdataset.  If the type is dns_datatype_any, 'rdataset' must be NULL.
 *
 *	'target' be a valid name.
 *
 *	'type' be a valid type.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NXDOMAIN		-- name does not exist in that section.
 *	DNS_R_NXRDATASET	-- The name does exist, but the desired
 *				   type does not.
 */

isc_result_t
dns_message_findtype(dns_name_t *name, dns_rdatatype_t type,
		     dns_rdatatype_t covers, dns_rdataset_t **rdataset);
/*
 * Search the name for the specified type.  If it is found, *rdataset is
 * filled in with a pointer to that rdataset.
 *
 * Requires:
 *	if '**rdataset' is non-NULL, *rdataset needs to be NULL.
 *
 *	'type' be a valid type, and NOT dns_rdatatype_any.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all is well.
 *	DNS_R_NOTFOUND		-- the desired type does not exist.
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
 *	'name' must be a name already in 'fromsection'.
 *
 *	'fromsection' must be a valid section.
 *
 *	'tosection' must be a valid section.
 */

void
dns_message_addname(dns_message_t *msg, dns_name_t *name,
		    dns_section_t section);
/*
 * Adds the name to the given section.
 *
 * It is the caller's responsibility to enforce any unique name requirements
 * in a section.
 *
 * Requires:
 *
 *	'msg' be valid, and be a renderable message.
 *
 *	'name' be a valid name.
 *
 *	'section' be a named section.
 */

/*
 * LOANOUT FUNCTIONS
 *
 * Each of these functions loan a particular type of data to the caller.
 * The storage for these will vanish when the message is destroyed or
 * reset, and must NOT be used after these operations.
 */

isc_result_t
dns_message_gettempname(dns_message_t *msg, dns_name_t **item);
/*
 * Return a name that can be used for any temporary purpose, including
 * inserting into the message's linked lists.  The name must be returned
 * to the message code using dns_message_puttempname() or inserted into
 * one of the message's sections before the message is destroyed.
 *
 * It is the caller's responsibility to initialize this name.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item == NULL
 *
 * Returns:
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMEMORY		-- No item can be allocated.
 */

isc_result_t
dns_message_gettemprdata(dns_message_t *msg, dns_rdata_t **item);
/*
 * Return a rdata that can be used for any temporary purpose, including
 * inserting into the message's linked lists.  The storage associated with
 * this rdata will be destroyed when the message is destroyed or reset.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item == NULL
 *
 * Returns:
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMEMORY		-- No item can be allocated.
 */

isc_result_t
dns_message_gettemprdataset(dns_message_t *msg, dns_rdataset_t **item);
/*
 * Return a rdataset that can be used for any temporary purpose, including
 * inserting into the message's linked lists.  The storage associated with
 * this rdataset will be destroyed when the message is destroyed or reset.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item == NULL
 *
 * Returns:
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMEMORY		-- No item can be allocated.
 */

isc_result_t
dns_message_gettemprdatalist(dns_message_t *msg, dns_rdatalist_t **item);
/*
 * Return a rdatalist that can be used for any temporary purpose, including
 * inserting into the message's linked lists.  The storage associated with
 * this rdatalist will be destroyed when the message is destroyed or reset.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item == NULL
 *
 * Returns:
 *	DNS_R_SUCCESS		-- All is well.
 *	DNS_R_NOMEMORY		-- No item can be allocated.
 */

void
dns_message_puttempname(dns_message_t *msg, dns_name_t **item);
/*
 * Return a borrowed name to the message's name free list.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item point to a name returned by
 *	dns_message_gettempname()
 *
 * Ensures:
 *	*item == NULL
 */

void
dns_message_puttemprdata(dns_message_t *msg, dns_rdata_t **item);
/*
 * Return a borrowed rdata to the message's rdata free list.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item point to a rdata returned by
 *	dns_message_gettemprdata()
 *
 * Ensures:
 *	*item == NULL
 */

void
dns_message_puttemprdataset(dns_message_t *msg, dns_rdataset_t **item);
/*
 * Return a borrowed rdataset to the message's rdataset free list.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item point to a rdataset returned by
 *	dns_message_gettemprdataset()
 *
 * Ensures:
 *	*item == NULL
 */

void
dns_message_puttemprdatalist(dns_message_t *msg, dns_rdatalist_t **item);
/*
 * Return a borrowed rdatalist to the message's rdatalist free list.
 *
 * Requires:
 *	msg be a valid message
 *
 *	item != NULL && *item point to a rdatalist returned by
 *	dns_message_gettemprdatalist()
 *
 * Ensures:
 *	*item == NULL
 */

isc_result_t
dns_message_peekheader(isc_buffer_t *source, dns_messageid_t *idp,
		       unsigned int *flagsp);
/*
 * Assume the remaining region of "source" is a DNS message.  Peek into
 * it and fill in "*idp" with the message id, and "*flagsp" with the flags.
 *
 * Requires:
 *
 *	source != NULL
 *
 * Ensures:
 *
 *	if (idp != NULL) *idp == message id.
 *
 *	if (flagsp != NULL) *flagsp == message flags.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *
 *	DNS_R_UNEXPECTEDEND	-- buffer doesn't contain enough for a header.
 */

isc_result_t
dns_message_reply(dns_message_t *msg, isc_boolean_t want_question_section);
/*
 * Start formatting a reply to the query in 'msg'.
 *
 * Requires:
 *
 *	'msg' is a valid message with parsing intent, and contains a query.
 * 
 * Ensures:
 *
 *	The message will have a rendering intent.  If 'want_question_section'
 *	is true, the message opcode is query or notify, and the question
 *	section is present and properly formatted, then the question section
 *	will be included in the reply.  All other sections will be cleared.
 *	The QR flag will be set, the RD flag will be preserved, and all other
 *	flags will be cleared.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *
 *	DNS_R_FORMERR		-- the header or question section of the
 *				   message is invalid, replying is impossible.
 *				   If DNS_R_FORMERR is returned when
 *				   want_question_section is ISC_FALSE, then
 *				   it's the header section that's bad;
 *				   otherwise either of the header or question
 *				   sections may be bad.
 */

dns_rdataset_t *
dns_message_getopt(dns_message_t *msg);
/*
 * Get the OPT record for 'msg'.
 *
 * Requires:
 *
 *	'msg' is a valid message.
 *
 * Returns:
 *
 *	The OPT rdataset of 'msg', or NULL if there isn't one.
 */

isc_result_t
dns_message_setopt(dns_message_t *msg, dns_rdataset_t *opt);
/*
 * Set the OPT record for 'msg'.
 *
 * Requires:
 *
 *	'msg' is a valid message with rendering intent,
 *	dns_message_renderbegin() has been called, and no sections have been
 *	rendered.
 *
 *	'opt' is a valid OPT record.
 *
 * Ensures:
 *
 *	The OPT record will be rendered when dns_message_renderend() is
 *	called.
 *
 * Returns:
 *
 *	DNS_R_SUCCESS		-- all is well.
 *
 *	DNS_R_NOSPACE		-- there is no space for the OPT record.
 */

void
dns_message_takebuffer(dns_message_t *msg, isc_buffer_t **buffer);
/*
 * Give the *buffer to the message code to clean up when it is no
 * longer needed.  This is usually when the message is reset or
 * destroyed.
 *
 * Requires:
 *
 *	msg be a valid message.
 *
 *	buffer != NULL && *buffer is a valid isc_buffer_t, which was
 *	dynamincally allocated via isc_buffer_allocate().
 */

isc_result_t
dns_message_signer(dns_message_t *msg, dns_name_t *signer);
/*
 * If this message was signed, return the identity of the signer.
 * Unless ISC_R_NOTFOUND is returned, signer will reflect the name of the
 * key that signed the message.
 *
 * Requires:
 *
 *	msg is a valid parsed message.
 *	signer is a valid name
 *
 * Returns:
 *
 *	ISC_R_SUCCESS		- the message was signed, and *signer
 *				  contains the signing identity
 *
 *	ISC_R_NOTFOUND		- no TSIG or SIG(0) record is present in the
 *				  message
 *
 *	DNS_R_TSIGVERIFYFAILURE	- the message was signed by a TSIG, but the
 *				  signature failed to verify
 *
 *	DNS_R_TSIGERRORSET	- the message was signed by a TSIG and
 *				  verified, but the query was rejected by
 *				  the server
 *
 *	DNS_R_NOIDENTITY	- the message was signed by a TSIG and
 *				  verified, but the key has no identity since
 *				  it was generated by an unsigned TKEY process
 *
 *	DNS_R_SIGINVALID	- the message was signed by a SIG(0), but
 *				  the signature failed to verify
 *
 *	DNS_R_SIGNOTVERIFIEDYET	- the message was signed by a SIG(0), but
 *				  the signature has not been verified yet
 */

isc_result_t
dns_message_checksig(dns_message_t *msg, dns_view_t *view);
/*
 * If this message was signed, verify the signature.
 *
 * Requires:
 *
 *	msg is a valid parsed message.
 *	view is a valid view
 *
 * Returns:
 *
 *	ISC_R_SUCCESS		- the message was unsigned, or the message
 *				  was signed correctly.
 *
 *	DNS_R_EXPECTEDTSIG	- A TSIG was expected, but not seen
 *	DNS_R_UNEXPECTEDTSIG	- A TSIG was seen but not expected
 *	DNS_R_TSIGVERIFYFAILURE - The TSIG failed to verify
 */

ISC_LANG_ENDDECLS

#endif	/* DNS_MESSAGE_H */
