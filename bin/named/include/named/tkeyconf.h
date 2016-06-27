/*
 * Copyright (C) 1999-2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: tkeyconf.h,v 1.16 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NS_TKEYCONF_H
#define NS_TKEYCONF_H 1

/*! \file */

#include <isc/types.h>
#include <isc/lang.h>

#include <isccfg/cfg.h>

ISC_LANG_BEGINDECLS

isc_result_t
ns_tkeyctx_fromconfig(const cfg_obj_t *options, isc_mem_t *mctx,
		      isc_entropy_t *ectx, dns_tkeyctx_t **tctxp);
/*%<
 * 	Create a TKEY context and configure it, including the default DH key
 *	and default domain, according to 'options'.
 *
 *	Requires:
 *\li		'cfg' is a valid configuration options object.
 *\li		'mctx' is not NULL
 *\li		'ectx' is not NULL
 *\li		'tctx' is not NULL
 *\li		'*tctx' is NULL
 *
 *	Returns:
 *\li		ISC_R_SUCCESS
 *\li		ISC_R_NOMEMORY
 */

ISC_LANG_ENDDECLS

#endif /* NS_TKEYCONF_H */
