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


#include <config.h>

#include <stdio.h>

#include <isc/md.h>
#include <isc/iterated_hash.h>
#include <isc/util.h>

#define RETERR(fn, ...)							\
	if ((err = fn ( __VA_ARGS__ )) != ISC_R_SUCCESS) {              \
		isc_md_free(md);					\
		return (0);                                           \
	}

int
isc_iterated_hash(unsigned char *out,
		  const unsigned int hashalg, const int iterations,
		  const unsigned char *salt, const int saltlength,
		  const unsigned char *in, const int inlength)
{
	isc_md_t *md;
	isc_result_t err;
	int n = 0;
	unsigned int outlength = 0;
	size_t len;
	const unsigned char *buf;

	REQUIRE(out != NULL);

	if (hashalg != 1) {
		return (0);
	}

	if ((md = isc_md_new()) == NULL) {
		return (0);
	}

	len = inlength;
	buf = in;
	do {
		RETERR(isc_md_init, md, ISC_MD_SHA1);
		RETERR(isc_md_update, md, buf, len);
		RETERR(isc_md_update, md, salt, saltlength);
		RETERR(isc_md_final, md, out, &outlength);
		buf = out;
		len = outlength;
	} while (n++ < iterations);

	isc_md_free(md);

	return (outlength);
}
#undef RETERR
