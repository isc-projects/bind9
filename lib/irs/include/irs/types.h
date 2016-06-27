/*
 * Copyright (C) 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: types.h,v 1.3 2009/09/02 23:48:02 tbox Exp $ */

#ifndef IRS_TYPES_H
#define IRS_TYPES_H 1

/* Core Types.  Alphabetized by defined type. */

/*%< per-thread IRS context */
typedef struct irs_context		irs_context_t;
/*%< resolv.conf configuration information */
typedef struct irs_resconf		irs_resconf_t;
/*%< advanced DNS-related configuration information */
typedef struct irs_dnsconf		irs_dnsconf_t;

#endif /* IRS_TYPES_H */
