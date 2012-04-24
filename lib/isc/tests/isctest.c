/*
 * Copyright (C) 2011, 2012  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id$ */

/*! \file */

#include <config.h>

#include <isc/app.h>
#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/string.h>
#include <isc/util.h>

#include "isctest.h"

isc_mem_t *mctx = NULL;
isc_entropy_t *ectx = NULL;
isc_log_t *lctx = NULL;
isc_taskmgr_t *taskmgr = NULL;
int ncpus;

static isc_boolean_t hash_active = ISC_FALSE;

/*
 * Logging categories: this needs to match the list in bin/named/log.c.
 */
static isc_logcategory_t categories[] = {
		{ "",                0 },
		{ "client",          0 },
		{ "network",         0 },
		{ "update",          0 },
		{ "queries",         0 },
		{ "unmatched",       0 },
		{ "update-security", 0 },
		{ "query-errors",    0 },
		{ NULL,              0 }
};

isc_result_t
isc_test_begin(FILE *logfile) {
	isc_result_t result;

	isc_mem_debugging |= ISC_MEM_DEBUGRECORD;
	CHECK(isc_mem_create(0, 0, &mctx));
	CHECK(isc_entropy_create(mctx, &ectx));

	CHECK(isc_hash_create(mctx, ectx, 255));
	hash_active = ISC_TRUE;

	if (logfile != NULL) {
		isc_logdestination_t destination;
		isc_logconfig_t *logconfig = NULL;

		CHECK(isc_log_create(mctx, &lctx, &logconfig));
		isc_log_registercategories(lctx, categories);
		isc_log_setcontext(lctx);

		destination.file.stream = logfile;
		destination.file.name = NULL;
		destination.file.versions = ISC_LOG_ROLLNEVER;
		destination.file.maximum_size = 0;
		CHECK(isc_log_createchannel(logconfig, "stderr",
					    ISC_LOG_TOFILEDESC,
					    ISC_LOG_DYNAMIC,
					    &destination, 0));
		CHECK(isc_log_usechannel(logconfig, "stderr", NULL, NULL));
	}

#ifdef ISC_PLATFORM_USETHREADS
	ncpus = isc_os_ncpus();
#else
	ncpus = 1;
#endif

	CHECK(isc_taskmgr_create(mctx, ncpus, 0, &taskmgr));

	return (ISC_R_SUCCESS);

  cleanup:
	isc_test_end();
	return (result);
}

void
isc_test_end() {
	if (taskmgr != NULL)
		isc_taskmgr_destroy(&taskmgr);
	if (lctx != NULL)
		isc_log_destroy(&lctx);
	if (hash_active) {
		isc_hash_destroy();
		hash_active = ISC_FALSE;
	}
	if (ectx != NULL)
		isc_entropy_detach(&ectx);
	if (mctx != NULL)
		isc_mem_destroy(&mctx);
}

