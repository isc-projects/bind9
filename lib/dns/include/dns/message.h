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

#ifndef DNS_MSG_H
#define DNS_MSG_H 1

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
 * When a dns message is received in a buffer, dns_msg_fromwire() is called
 * on the memory region.  Various items are checked including the format
 * of the message (if counts are right, if counts consume the entire sections,
 * and if sections consume the entire message) and known pseudo-RRs in the
 * additional data section are analyzed and removed.
 *
 * TSIG checking is also done at this layer, and any DNSSEC information should
 * also be performed at this time.
 *
 * If dns_msg_fromwire() returns DNS_R_MOREDATA additional
 * message packets are required.  This implies an EDNS message.
 *
 * When going from structure to wire, dns_msg_towire() will return
 * DNS_R_MOREDATA if there is more data left in the output buffer that
 * could not be rendered into the exisiting buffer.
 *
 * XXX Needed:  ways to handle TSIG and DNSSEC, supply TSIG and DNSSEC
 * keys, set and retrieve EDNS information, add rdata to a section,
 * move rdata from one section to another, remove rdata, etc.
 */

ISC_LANG_BEGINDECLS

#define DNS_MSG_QR			0x8000U
#define DNS_MSG_AA			0x0400U
#define DNS_MSG_TC			0x0200U
#define DNS_MSG_RD			0x0100U
#define DNS_MSG_RA			0x0080U

#define DNS_MSG_OPCODE_MASK		0x7000U
#define DNS_MSG_OPCODE_SHIFT		11
#define DNS_MSG_RCODE_MASK		0x000fU

typedef struct {
	unsigned int			magic;		/* magic */

	unsigned int			msg_id;
	unsigned int			msg_flags;	/* this msg's flags */
	unsigned int			msg_rcode;	/* this msg's rcode */
	unsigned int			msg_opcode;	/* this msg's opcode */
	unsigned int			msg_qcount;	/* this msg's counts */
	unsigned int			msg_ancount;
	unsigned int			msg_aucount;
	unsigned int			msg_adcount;
	dns_namelist_t			msg_question;
	dns_namelist_t			msg_answer;
	dns_namelist_t			msg_authority;
	dns_namelist_t			msg_additional;

	/* XXX should be an isc_buffer_t? */
	unsigned char		       *data;		/* start of raw data */
	unsigned int			datalen;	/* length of data */

	ISC_LINK(dns_msg_t)		link;		/* next msg */
} dns_msg_t;


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
	ISC_LIST(dns_msg_t)		msgs;
} dns_msg_list_t;

ISC_LANG_ENDDECLS

#endif	/* DNS_DNS_H */
