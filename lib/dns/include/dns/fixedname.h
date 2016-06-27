/*
 * Copyright (C) 1999-2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: fixedname.h,v 1.19 2007/06/19 23:47:16 tbox Exp $ */

#ifndef DNS_FIXEDNAME_H
#define DNS_FIXEDNAME_H 1

/*****
 ***** Module Info
 *****/

/*! \file dns/fixedname.h
 * \brief
 * Fixed-size Names
 *
 * dns_fixedname_t is a convenience type containing a name, an offsets table,
 * and a dedicated buffer big enough for the longest possible name.
 *
 * MP:
 *\li	The caller must ensure any required synchronization.
 *
 * Reliability:
 *\li	No anticipated impact.
 *
 * Resources:
 *\li	Per dns_fixedname_t:
 *\code
 *		sizeof(dns_name_t) + sizeof(dns_offsets_t) +
 *		sizeof(isc_buffer_t) + 255 bytes + structure padding
 *\endcode
 *
 * Security:
 *\li	No anticipated impact.
 *
 * Standards:
 *\li	None.
 */

/*****
 ***** Imports
 *****/

#include <isc/buffer.h>

#include <dns/name.h>

/*****
 ***** Types
 *****/

struct dns_fixedname {
	dns_name_t			name;
	dns_offsets_t			offsets;
	isc_buffer_t			buffer;
	unsigned char			data[DNS_NAME_MAXWIRE];
};

#define dns_fixedname_init(fn) \
	do { \
		dns_name_init(&((fn)->name), (fn)->offsets); \
		isc_buffer_init(&((fn)->buffer), (fn)->data, \
				  DNS_NAME_MAXWIRE); \
		dns_name_setbuffer(&((fn)->name), &((fn)->buffer)); \
	} while (0)

#define dns_fixedname_invalidate(fn) \
	dns_name_invalidate(&((fn)->name))

#define dns_fixedname_name(fn)		(&((fn)->name))

#endif /* DNS_FIXEDNAME_H */
