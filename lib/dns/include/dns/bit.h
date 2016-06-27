/*
 * Copyright (C) 2000, 2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: bit.h,v 1.14 2007/06/19 23:47:16 tbox Exp $ */

#ifndef DNS_BIT_H
#define DNS_BIT_H 1

/*! \file dns/bit.h */

#include <isc/int.h>
#include <isc/boolean.h>

typedef isc_uint64_t dns_bitset_t;

#define DNS_BIT_SET(bit, bitset) \
     (*(bitset) |= ((dns_bitset_t)1 << (bit)))
#define DNS_BIT_CLEAR(bit, bitset) \
     (*(bitset) &= ~((dns_bitset_t)1 << (bit)))
#define DNS_BIT_CHECK(bit, bitset) \
     ISC_TF((*(bitset) & ((dns_bitset_t)1 << (bit))) \
	    == ((dns_bitset_t)1 << (bit)))

#endif /* DNS_BIT_H */

