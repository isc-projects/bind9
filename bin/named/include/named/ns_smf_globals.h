/*
 * Copyright (C) 2005, 2007, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: ns_smf_globals.h,v 1.7 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NS_SMF_GLOBALS_H
#define NS_SMF_GLOBALS_H 1

#include <libscf.h>

#undef EXTERN
#undef INIT
#ifdef NS_MAIN
#define EXTERN
#define INIT(v) = (v)
#else
#define EXTERN extern
#define INIT(v)
#endif

EXTERN unsigned int	ns_smf_got_instance	INIT(0);
EXTERN unsigned int	ns_smf_chroot		INIT(0);
EXTERN unsigned int	ns_smf_want_disable	INIT(0);

isc_result_t ns_smf_add_message(isc_buffer_t **text);
isc_result_t ns_smf_get_instance(char **name, int debug, isc_mem_t *mctx);

#undef EXTERN
#undef INIT

#endif /* NS_SMF_GLOBALS_H */
