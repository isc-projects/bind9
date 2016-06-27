/*
 * Copyright (C) 1999-2001, 2004-2007, 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: tsigconf.h,v 1.18 2009/06/11 23:47:55 tbox Exp $ */

#ifndef NS_TSIGCONF_H
#define NS_TSIGCONF_H 1

/*! \file */

#include <isc/types.h>
#include <isc/lang.h>

ISC_LANG_BEGINDECLS

isc_result_t
ns_tsigkeyring_fromconfig(const cfg_obj_t *config, const cfg_obj_t *vconfig,
			  isc_mem_t *mctx, dns_tsig_keyring_t **ringp);
/*%<
 * Create a TSIG key ring and configure it according to the 'key'
 * statements in the global and view configuration objects.
 *
 *	Requires:
 *	\li	'config' is not NULL.
 *	\li	'vconfig' is not NULL.
 *	\li	'mctx' is not NULL
 *	\li	'ringp' is not NULL, and '*ringp' is NULL
 *
 *	Returns:
 *	\li	ISC_R_SUCCESS
 *	\li	ISC_R_NOMEMORY
 */

ISC_LANG_ENDDECLS

#endif /* NS_TSIGCONF_H */
