/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <config.h>

#include <string.h>

#include <isc/result.h>
#include <isc/once.h>
#include <isc/util.h>

#include <ns/hooks.h>

static ns_hooklist_t hooktab[NS_QUERY_HOOKS_COUNT];
LIBNS_EXTERNAL_DATA ns_hooktable_t *ns__hook_table = &hooktab;

void
ns_hooktable_init(ns_hooktable_t *hooktable) {
	int i;

	if (hooktable == NULL) {
		hooktable = ns__hook_table;
	}

	for (i = 0; i < NS_QUERY_HOOKS_COUNT; i++) {
		ISC_LIST_INIT((*hooktable)[i]);
	}
}

ns_hooktable_t *
ns_hooktable_save() {
	return (ns__hook_table);
}

void
ns_hooktable_reset(ns_hooktable_t *hooktable) {
	if (hooktable != NULL) {
		ns__hook_table = hooktable;
	} else {
		ns__hook_table = &hooktab;
	}
}

void
ns_hook_add(ns_hooktable_t *hooktable, ns_hookpoint_t hookpoint,
	    ns_hook_t *hook)
{
	REQUIRE(hookpoint < NS_QUERY_HOOKS_COUNT);
	REQUIRE(hook != NULL);

	if (hooktable == NULL) {
		hooktable = ns__hook_table;
	}

	ISC_LINK_INIT(hook, link);
	ISC_LIST_APPEND((*hooktable)[hookpoint], hook, link);
}
