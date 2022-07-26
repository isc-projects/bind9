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

/*!
 * \file
 */

#include <isc/event.h>
#include <isc/mem.h>
#include <isc/util.h>

/***
 *** Events.
 ***/

static void
destroy(isc_event_t *event) {
	isc_mem_t *mctx = event->ev_destroy_arg;

	isc_mem_put(mctx, event, event->ev_size);
}

isc_event_t *
isc__event_allocate(isc_mem_t *mctx, void *sender, isc_eventtype_t type,
		    isc_taskaction_t action, void *arg,
		    size_t size ISC__EVENT_FLARG) {
	isc_event_t *event;

	REQUIRE(size >= sizeof(struct isc_event));
	REQUIRE(action != NULL);

	event = isc_mem_get(mctx, size);

	ISC_EVENT_INIT_PASS(event, size, 0, type, action, arg, sender, destroy,
			    mctx);

	return (event);
}

void
isc_event_free(isc_event_t **eventp) {
	isc_event_t *event;

	REQUIRE(eventp != NULL);
	event = *eventp;
	*eventp = NULL;
	REQUIRE(event != NULL);

	REQUIRE(!ISC_LINK_LINKED(event, ev_link));
	REQUIRE(!ISC_LINK_LINKED(event, ev_ratelink));

	if (event->ev_destroy != NULL) {
		(event->ev_destroy)(event);
	}
}
