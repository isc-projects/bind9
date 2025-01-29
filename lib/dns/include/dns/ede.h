/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <isc/mem.h>

#include <dns/message.h>

/*
 * From RFC 8914:
 * Because long EXTRA-TEXT fields may trigger truncation (which is undesirable
 * given the supplemental nature of EDE), implementers and operators creating
 * EDE options SHOULD avoid lengthy EXTRA-TEXT contents.
 *
 * Following this advice we limit the EXTRA-TEXT length to 64 characters.
 */
#define DNS_EDE_EXTRATEXT_LEN 64

#define DNS_EDE_MAX_ERRORS 3

typedef struct dns_edectx dns_edectx_t;
struct dns_edectx {
	int	       magic;
	isc_mem_t     *mctx;
	dns_ednsopt_t *ede[DNS_EDE_MAX_ERRORS];
};

void
dns_ede_init(isc_mem_t *mctx, dns_edectx_t *edectx);

void
dns_ede_reset(dns_edectx_t *edectx);

void
dns_ede_invalidate(dns_edectx_t *edectx);

void
dns_ede_add(dns_edectx_t *edectx, uint16_t code, const char *text);
/*%<
 * Set extended error with INFO-CODE <code> and EXTRA-TEXT <text>.
 */

void
dns_ede_copy(dns_edectx_t *edectx_to, dns_edectx_t *edectx_from);
