/*
 * Copyright (C) 2008, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: iterated_hash.h,v 1.3 2008/09/25 04:02:39 tbox Exp $ */

#ifndef ISC_ITERATED_HASH_H
#define ISC_ITERATED_HASH_H 1

#include <isc/lang.h>
#include <isc/sha1.h>

/*
 * The maximal hash length that can be encoded in a name
 * using base32hex.  floor(255/8)*5
 */
#define NSEC3_MAX_HASH_LENGTH 155

/*
 * The maximum has that can be encoded in a single label using
 * base32hex.  floor(63/8)*5
 */
#define NSEC3_MAX_LABEL_HASH 35

ISC_LANG_BEGINDECLS

int isc_iterated_hash(unsigned char out[NSEC3_MAX_HASH_LENGTH],
		      unsigned int hashalg, int iterations,
		      const unsigned char *salt, int saltlength,
		      const unsigned char *in, int inlength);


ISC_LANG_ENDDECLS

#endif /* ISC_ITERATED_HASH_H */
