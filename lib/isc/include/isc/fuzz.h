/*
 * Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef ISC_FUZZ_H
#define ISC_FUZZ_H

typedef enum {
	isc_fuzz_none,
	isc_fuzz_client,
	isc_fuzz_tcpclient,
	isc_fuzz_resolver,
	isc_fuzz_http,
	isc_fuzz_rndc
} isc_fuzztype_t;

#endif /* ISC_FUZZ_H */
