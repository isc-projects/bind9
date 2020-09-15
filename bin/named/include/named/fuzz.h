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
