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

#include <string.h>

#include <isc/mem.h>
#include <isc/util.h>

#include "viewname_p.h"

static const char default_view[] = "_default";
static const char bind_view[] = "_bind";

const char *
dns__viewname_get(const dns_viewname_t *name) {
	return name->name;
}

const char *
dns__viewname_display(const dns_viewname_t *name) {
	if (name->name == default_view || name->name == bind_view) {
		return NULL;
	}
	return name->name;
}

void
dns__viewname_free(dns_viewname_t *name, isc_mem_t *mctx) {
	if (dns__viewname_display(name) != NULL) {
		char *value = (char *)name->name;
		isc_mem_free(mctx, value);
	}
	name->name = NULL;
}

void
dns__viewname_set(dns_viewname_t *name, isc_mem_t *mctx, const char *value) {
	REQUIRE(value != NULL);

	/* Reattaching a view of the same name leaves logging storage intact. */
	if (name->name != NULL && strcmp(name->name, value) == 0) {
		return;
	}

	const char *replacement = NULL;
	if (value[0] == '_' && strcmp(value, default_view) == 0) {
		replacement = default_view;
	} else if (value[0] == '_' && strcmp(value, bind_view) == 0) {
		replacement = bind_view;
	} else {
		replacement = isc_mem_strdup(mctx, value);
	}
	dns__viewname_free(name, mctx);
	name->name = replacement;
}
