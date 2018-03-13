/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef DNS_ZONE_P_H
#define DNS_ZONE_P_H

/*! \file */

/*%
 *     Types and functions below not be used outside this module and its
 *     associated unit tests.
 */

ISC_LANG_BEGINDECLS

typedef struct {
	dns_diff_t	*diff;
	isc_boolean_t	offline;
} dns__zonediff_t;

ISC_LANG_ENDDECLS

#endif /* DNS_ZONE_P_H */
