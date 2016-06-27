/*
 * Copyright (C) 2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: check.h,v 1.9 2007/06/19 23:47:16 tbox Exp $ */

#ifndef BIND9_CHECK_H
#define BIND9_CHECK_H 1

/*! \file bind9/check.h */

#include <isc/lang.h>
#include <isc/types.h>

#include <isccfg/cfg.h>

ISC_LANG_BEGINDECLS

isc_result_t
bind9_check_namedconf(const cfg_obj_t *config, isc_log_t *logctx,
		      isc_mem_t *mctx);
/*%<
 * Check the syntactic validity of a configuration parse tree generated from
 * a named.conf file.
 *
 * Requires:
 *\li	config is a valid parse tree
 *
 *\li	logctx is a valid logging context.
 *
 * Returns:
 * \li	#ISC_R_SUCCESS
 * \li	#ISC_R_FAILURE
 */

isc_result_t
bind9_check_key(const cfg_obj_t *config, isc_log_t *logctx);
/*%<
 * Same as bind9_check_namedconf(), but for a single 'key' statement.
 */

ISC_LANG_ENDDECLS

#endif /* BIND9_CHECK_H */
