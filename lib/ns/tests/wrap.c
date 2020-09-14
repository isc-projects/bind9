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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/util.h>

#include <dns/view.h>

#include <ns/client.h>

/*
 * This overrides calls to isc_nmhandle_attach/detach(), sending them to
 * __wrap_isc_nmhandle_attach/detach() instead, when libtool is in use
 * and LD_WRAP can't be used.
 */

void
__wrap_isc_nmhandle_attach(isc_nmhandle_t *source, isc_nmhandle_t **targetp);
extern void
__wrap_isc_nmhandle_detach(isc_nmhandle_t **handlep);

void
isc_nmhandle_attach(isc_nmhandle_t *source, isc_nmhandle_t **targetp) {
	__wrap_isc_nmhandle_attach(source, targetp);
}

void
isc_nmhandle_detach(isc_nmhandle_t **handlep) {
	__wrap_isc_nmhandle_detach(handlep);
}
