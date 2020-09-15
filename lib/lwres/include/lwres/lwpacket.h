/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef LWRES_LWPACKET_H
#define LWRES_LWPACKET_H 1

#include <inttypes.h>

#include <lwres/lang.h>
#include <lwres/lwbuffer.h>
#include <lwres/result.h>

/*% lwres_lwpacket_t */
typedef struct lwres_lwpacket lwres_lwpacket_t;

/*% lwres_lwpacket structure */
struct lwres_lwpacket {
	/*! The overall packet length, including the
	 *  entire packet header.
	 *  This field is filled in by the
	 *  \link lwres_gabn.c lwres_gabn_*()\endlink
	 *  and \link lwres_gnba.c lwres_gnba_*()\endlink calls.
	 */
	uint32_t		length;
	/*! Specifies the header format.  Currently,
	 *  there is only one format, #LWRES_LWPACKETVERSION_0.
	 *  This field is filled in by the
	 *  \link lwres_gabn.c lwres_gabn_*()\endlink
	 *  and \link lwres_gnba.c lwres_gnba_*()\endlink calls.
	 */
	uint16_t		version;
	/*! Specifies library-defined flags for this packet, such as
	 *  whether the packet is a request or a reply.  None of
	 *  these are definable by the caller, but library-defined values
	 *  can be set by the caller.  For example, one bit in this field
	 *  indicates if the packet is a request or a response.
	 *  This field is filled in by
	 *  the application wits the exception of the
	 *  #LWRES_LWPACKETFLAG_RESPONSE bit, which is set by the library
	 *  in the
	 *  \link lwres_gabn.c lwres_gabn_*()\endlink
	 *  and \link lwres_gnba.c lwres_gnba_*()\endlink calls.
	 */
	uint16_t		pktflags;
	/*! Set by the requestor and is returned in all replies.
	 *  If two packets from the same source have the same serial
	 *  number and are from the same source, they are assumed to
	 *  be duplicates and the latter ones may be dropped.
	 *  (The library does not do this by default on replies, but
	 * does so on requests.)
	 */
	uint32_t		serial;
	/*! Opcodes between 0x04000000 and 0xffffffff
	 *  are application defined.  Opcodes between
	 *  0x00000000 and 0x03ffffff are
	 * reserved for library use.
	 *  This field is filled in by the
	 *  \link lwres_gabn.c lwres_gabn_*()\endlink
	 *  and \link lwres_gnba.c lwres_gnba_*()\endlink calls.
	 */
	uint32_t		opcode;
	/*! Only valid for results.
	 *  Results between 0x04000000 and 0xffffffff are application
	 *  defined.
	 * Results between 0x00000000 and 0x03ffffff are reserved for
	 * library use.
	 * (This is the same reserved range defined in <isc/resultclass.h>,
	 * so it
	 * would be trivial to map ISC_R_* result codes into packet result
	 * codes when appropriate.)
	 *  This field is filled in by the
	 *  \link lwres_gabn.c lwres_gabn_*()\endlink
	 *  and \link lwres_gnba.c lwres_gnba_*()\endlink calls.
	 */
	uint32_t		result;
	/*! Set to the maximum buffer size that the receiver can
	 *  handle on requests, and the size of the buffer needed to
	 *  satisfy a request
	 *  when the buffer is too large for replies.
	 *  This field is supplied by the application.
	 */
	uint32_t		recvlength;
	/*! The packet level auth type used.
	 *  Authtypes between 0x1000 and 0xffff are application defined.
	 *  Authtypes
	 *  between 0x0000 and 0x0fff are reserved for library use.
	 *  This is currently
	 *  unused and MUST be set to zero.
	 */
	uint16_t		authtype;
	/*! The length of the authentication data.
	 *  See the specific
	 * authtypes for more information on what is contained
	 * in this field.  This is currently unused, and
	 * MUST be set to zero.
	 */
	uint16_t		authlength;
};

#define LWRES_LWPACKET_LENGTH		(4 * 5 + 2 * 4) /*%< Overall length. */

#define LWRES_LWPACKETFLAG_RESPONSE	0x0001U	/*%< If set, pkt is a response. */


#define LWRES_LWPACKETVERSION_0		0	/*%< Header format. */

/*! \file lwres/lwpacket.h
 *
 *
 * The remainder of the packet consists of two regions, one described by
 * "authlen" and one of "length - authlen - sizeof(lwres_lwpacket_t)".
 *
 * That is:
 *
 * \code
 *	pkt header
 *	authlen bytes of auth information
 *	data bytes
 * \endcode
 *
 * Currently defined opcodes:
 *
 *\li	#LWRES_OPCODE_NOOP.  Success is always returned, with the packet contents echoed.
 *
 *\li	#LWRES_OPCODE_GETADDRSBYNAME.  Return all known addresses for a given name.
 *		This may return NIS or /etc/hosts info as well as DNS
 *		information.  Flags will be provided to indicate ip4/ip6
 *		addresses are desired.
 *
 *\li	#LWRES_OPCODE_GETNAMEBYADDR.	Return the hostname for the given address.  Once
 *		again, it will return data from multiple sources.
 */

LWRES_LANG_BEGINDECLS

/* XXXMLG document */
lwres_result_t
lwres_lwpacket_renderheader(lwres_buffer_t *b, lwres_lwpacket_t *pkt);

lwres_result_t
lwres_lwpacket_parseheader(lwres_buffer_t *b, lwres_lwpacket_t *pkt);

LWRES_LANG_ENDDECLS

#endif /* LWRES_LWPACKET_H */
