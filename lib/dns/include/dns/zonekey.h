/*
 * Copyright (C) 2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: zonekey.h,v 1.10 2007/06/19 23:47:17 tbox Exp $ */

#ifndef DNS_ZONEKEY_H
#define DNS_ZONEKEY_H 1

/*! \file dns/zonekey.h */

#include <isc/lang.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

isc_boolean_t
dns_zonekey_iszonekey(dns_rdata_t *keyrdata);
/*%<
 *	Determines if the key record contained in the rdata is a zone key.
 *
 *	Requires:
 *		'keyrdata' is not NULL.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_ZONEKEY_H */
