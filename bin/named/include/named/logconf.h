/*
 * Copyright (C) 1999-2001, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: logconf.h,v 1.17 2007/06/19 23:46:59 tbox Exp $ */

#ifndef NAMED_LOGCONF_H
#define NAMED_LOGCONF_H 1

/*! \file */

#include <isc/log.h>

isc_result_t
ns_log_configure(isc_logconfig_t *logconf, const cfg_obj_t *logstmt);
/*%<
 * Set up the logging configuration in '*logconf' according to
 * the named.conf data in 'logstmt'.
 */

#endif /* NAMED_LOGCONF_H */
