/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef NAMED_FUZZ_H
#define NAMED_FUZZ_H

void
named_fuzz_notify(void);

void
named_fuzz_setup(void);

typedef enum {
	ns_fuzz_none,
	ns_fuzz_client,
	ns_fuzz_tcpclient,
	ns_fuzz_resolver,
	ns_fuzz_http,
	ns_fuzz_rndc
} ns_fuzz_t;

#endif /* NAMED_FUZZ_H */
