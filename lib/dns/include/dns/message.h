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

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdataset.h>
#include <dns/callbacks.h>

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

#define DNS_MESSAGE_QR			0x8000U
#define DNS_MESSAGE_AA			0x0400U
#define DNS_MESSAGE_TC			0x0200U
#define DNS_MESSAGE_RD			0x0100U
#define DNS_MESSAGE_RA			0x0080U

#define DNS_MESSAGE_OPCODE_MASK		0x7000U
#define DNS_MESSAGE_OPCODE_SHIFT	    11
#define DNS_MESSAGE_RCODE_MASK		0x000fU

typedef struct {
	unsigned int			magic;		/* magic */

	unsigned int			id;
	unsigned int			flags;		/* this msg's flags */
	unsigned int			rcode;		/* this msg's rcode */
	unsigned int			opcode;		/* this msg's opcode */
	unsigned int			qcount;		/* this msg's counts */
	unsigned int			ancount;
	unsigned int			aucount;
	unsigned int			adcount;
	dns_namelist_t			question;
	dns_namelist_t			answer;
	dns_namelist_t			authority;
	dns_namelist_t			additional;

	/* XXX should be an isc_buffer_t? */
	unsigned char		       *data;		/* start of raw data */
	unsigned int			datalen;	/* length of data */

	ISC_LINK(dns_messageelem_t)	link;		/* next msg */
} dns_messageelem_t;


/*
 * This structure doesn't directly map into a wire format, but is used
 * to keep track of multiple DNS messages which all refer to the same
 * "logical message" (as in edns0)
 *
 * When reading a stream of messages in, the namelists can be "flattened"
 * or "consumed" into the dns_namelist_t fields below as messages arrive.  The
 * message counts will be updated in the appropriate manner in the message.
 *
 * When rendering the "logical message" into multiple wire messages, the
 * various dns_namelist_t fields are removed from these lists and added
 * (in order, of course) to the wire format messages.  Rendering can
 * happen immediately or as time permits.
 */
typedef struct {
	unsigned int			magic;

	unsigned int			id;		/* overall ID */
	unsigned int			flags;		/* overall flags */
	unsigned int			qcount;		/* total qcount */
	unsigned int			ancount;
	unsigned int			aucount;
	unsigned int			adcount;
	dns_namelist_t			question;	/* see above */
	dns_namelist_t			answer;
	dns_namelist_t			authority;
	dns_namelist_t			additional;

	unsigned int			nmsgs;
	ISC_LIST(dns_messageelem_t)	msgs;
} dns_message_t;

void dns_message_init(dns_message_t *msg);
/*
 * initialize msg structure.  Must be called on a new (or reused) structure.
 *
 * Ensures:
 *	The data in "msg" is set to indicate an unused and empty msg
 *	structure.
 */

dns_result_t dns_message_associate(dns_message_t *msg,
				   void *buffer, size_t buflen);
/*
 * Associate a buffer with a message structure.  This function will
 * validate the buffer, allocate an internal message element to hold
 * the buffer's information, and update various counters.  Also, any
 * DNSSEC or TSIG signatures are verified at this time.
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
 *	The buffer's contents verify as correct regarding signatures,
 *	bits set, etc.
 *
 * Returns:
 *	DNS_R_SUCCESS		-- all is well
 *	DNS_R_NOMEM		-- no memory
 *	DNS_R_MOREDATA		-- more packets needed for complete message
 *	DNS_R_???		-- bad signature (XXX need more of these)
 */

dns_messageelem_t *dns_messageelem_first(dns_message_t *msg);
/*
 * Return the first message element's pointer.
 *
 * Requires:
 *	"msg" be valid.
 *
 * Returns:
 *	The first element on the message buffer list, or NULL if no buffers
 *	are associated.
 */

dns_messageelem_t *dns_messageelem_next(dns_message_t *msg,
					dns_messageelem_t *elem);
/*
 * Return the next message element pointer.
 *
 * Requires:
 *	"msg" be valid.
 *
 *	"msgelem" be valid, and part of the chain of elements for "msg".
 *
 * Returns:
 *	The next element on the message buffer list, or NULL if no more
 *	exist.
 */

dns_name_t *dns_message_firstname(dns_message_t *msg, dns_namelist_t *section);
/*
 * Returns a pointer to the first name in the specified section.
 */

dns_name_t *dns_message_nextname(dns_message_t *msg, dns_namelist_t *section,
				 dns_name_t *name);
/*
 * Returns a pointer to the next name in the specified section.
 */

void dns_message_movename(dns_message_t *msg, dns_namelist_t *fromsection,
			  dns_namelist_t *tosection);
/*
 * Move a name from one section to another.
 */

dns_result_t dns_message_addname(dns_message_t *msg, dns_namelist_t *section,
				 dns_name_t *name);
/*
 * Adds the name to the given section.
 *
 * Caller must ensure that the name does not already exist.
 */

ISC_LANG_ENDDECLS

#endif	/* DNS_DNS_H */
