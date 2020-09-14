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

#ifndef ISC_HTTPD_H
#define ISC_HTTPD_H 1

/*! \file */

#include <stdbool.h>

#include <isc/event.h>
#include <isc/eventclass.h>
#include <isc/mutex.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/types.h>

/*%
 * HTTP urls.  These are the URLs we manage, and the function to call to
 * provide the data for it.  We pass in the base url (so the same function
 * can handle multiple requests), and a structure to fill in to return a
 * result to the client.  We also pass in a pointer to be filled in for
 * the data cleanup function.
 */
struct isc_httpdurl {
	char *		   url;
	isc_httpdaction_t *action;
	void *		   action_arg;
	bool		   isstatic;
	isc_time_t	   loadtime;
	ISC_LINK(isc_httpdurl_t) link;
};

#define HTTPD_EVENTCLASS ISC_EVENTCLASS(4300)
#define HTTPD_SHUTDOWN	 (HTTPD_EVENTCLASS + 0x0001)

#define ISC_HTTPDMGR_SHUTTINGDOWN 0x00000001

isc_result_t
isc_httpdmgr_create(isc_nm_t *nm, isc_mem_t *mctx, isc_sockaddr_t *addr,
		    isc_httpdclientok_t * client_ok,
		    isc_httpdondestroy_t *ondestroy, void *cb_arg,
		    isc_httpdmgr_t **httpdmgrp);

void
isc_httpdmgr_shutdown(isc_httpdmgr_t **httpdp);

isc_result_t
isc_httpdmgr_addurl(isc_httpdmgr_t *httpdmgr, const char *url, bool isstatic,
		    isc_httpdaction_t *func, void *arg);

void
isc_httpd_setfinishhook(void (*fn)(void));

#endif /* ISC_HTTPD_H */
