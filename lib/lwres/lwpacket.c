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

/*! \file */

/**
 *    These functions rely on a struct lwres_lwpacket which is defined in
 *    \link lwpacket.h lwres/lwpacket.h.\endlink
 *
 *    The following opcodes are currently defined:
 *
 * \li   #LWRES_OPCODE_NOOP
 *           Success is always returned and the packet contents are
 *           echoed. The \link lwres_noop.c lwres_noop_*()\endlink functions should be used for this
 *           type.
 *
 * \li   #LWRES_OPCODE_GETADDRSBYNAME
 *           returns all known addresses for a given name. The
 *           \link lwres_gabn.c lwres_gabn_*()\endlink functions should be used for this type.
 *
 * \li   #LWRES_OPCODE_GETNAMEBYADDR
 *           return the hostname for the given address. The
 *           \link lwres_gnba.c lwres_gnba_*() \endlink functions should be used for this type.
 *
 *    lwres_lwpacket_renderheader() transfers the contents of lightweight
 *    resolver packet structure #lwres_lwpacket_t *pkt in network byte
 *    order to the lightweight resolver buffer, *b.
 *
 *    lwres_lwpacket_parseheader() performs the converse operation. It
 *    transfers data in network byte order from buffer *b to resolver
 *    packet *pkt. The contents of the buffer b should correspond to a
 *    #lwres_lwpacket_t.
 *
 * \section lwpacket_return Return Values
 *
 *    Successful calls to lwres_lwpacket_renderheader() and
 *    lwres_lwpacket_parseheader() return #LWRES_R_SUCCESS. If there is
 *    insufficient space to copy data between the buffer *b and
 *    lightweight resolver packet *pkt both functions return
 *    #LWRES_R_UNEXPECTEDEND.
 */

#include <config.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <lwres/lwbuffer.h>
#include <lwres/lwpacket.h>
#include <lwres/result.h>

#include "assert_p.h"

/*% Length of Packet */
#define LWPACKET_LENGTH \
	(sizeof(uint16_t) * 4 + sizeof(uint32_t) * 5)

/*% transfers the contents of lightweight resolver packet structure lwres_lwpacket_t *pkt in network byte order to the lightweight resolver buffer, *b. */

lwres_result_t
lwres_lwpacket_renderheader(lwres_buffer_t *b, lwres_lwpacket_t *pkt) {
	REQUIRE(b != NULL);
	REQUIRE(pkt != NULL);

	if (!SPACE_OK(b, LWPACKET_LENGTH))
		return (LWRES_R_UNEXPECTEDEND);

	lwres_buffer_putuint32(b, pkt->length);
	lwres_buffer_putuint16(b, pkt->version);
	lwres_buffer_putuint16(b, pkt->pktflags);
	lwres_buffer_putuint32(b, pkt->serial);
	lwres_buffer_putuint32(b, pkt->opcode);
	lwres_buffer_putuint32(b, pkt->result);
	lwres_buffer_putuint32(b, pkt->recvlength);
	lwres_buffer_putuint16(b, pkt->authtype);
	lwres_buffer_putuint16(b, pkt->authlength);

	return (LWRES_R_SUCCESS);
}

/*% transfers data in network byte order from buffer *b to resolver packet *pkt. The contents of the buffer b should correspond to a lwres_lwpacket_t. */

lwres_result_t
lwres_lwpacket_parseheader(lwres_buffer_t *b, lwres_lwpacket_t *pkt) {
	uint32_t space;

	REQUIRE(b != NULL);
	REQUIRE(pkt != NULL);

	space = LWRES_BUFFER_REMAINING(b);
	if (space < LWPACKET_LENGTH)
		return (LWRES_R_UNEXPECTEDEND);

	pkt->length = lwres_buffer_getuint32(b);
	/*
	 * XXXBEW/MLG Checking that the buffer is long enough probably
	 * shouldn't be done here, since this function is supposed to just
	 * parse the header.
	 */
	if (pkt->length > space)
		return (LWRES_R_UNEXPECTEDEND);
	pkt->version = lwres_buffer_getuint16(b);
	pkt->pktflags = lwres_buffer_getuint16(b);
	pkt->serial = lwres_buffer_getuint32(b);
	pkt->opcode = lwres_buffer_getuint32(b);
	pkt->result = lwres_buffer_getuint32(b);
	pkt->recvlength = lwres_buffer_getuint32(b);
	pkt->authtype = lwres_buffer_getuint16(b);
	pkt->authlength = lwres_buffer_getuint16(b);

	return (LWRES_R_SUCCESS);
}
