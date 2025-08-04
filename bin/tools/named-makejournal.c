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

/*! \file */

#include <stdbool.h>
#include <stdlib.h>

#include <isc/commandline.h>
#include <isc/hash.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/serial.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/journal.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/types.h>

char jbuf[PATH_MAX];

static void
usage(int ret) {
	fprintf(stderr, "usage: %s [-hm] origin oldfile newfile [journal]\n",
		isc_commandline_progname);
	exit(ret);
}

static isc_result_t
loadzone(dns_db_t **db, const char *origin, const char *filename) {
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;

	name = dns_fixedname_initname(&fixed);

	result = dns_name_fromstring(name, origin, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_db_create(isc_g_mctx, ZONEDB_DEFAULT, name,
			       dns_dbtype_zone, dns_rdataclass_in, 0, NULL, db);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_db_load(*db, filename, dns_masterformat_text, 0);
	if (result == DNS_R_SEENINCLUDE) {
		result = ISC_R_SUCCESS;
	}
	return result;
}

static isc_result_t
loadjournal(dns_db_t *db, const char *file) {
	dns_journal_t *jnl = NULL;
	isc_result_t result;

	result = dns_journal_open(isc_g_mctx, file, DNS_JOURNAL_READ, &jnl);
	if (result == ISC_R_NOTFOUND) {
		return ISC_R_SUCCESS;
	} else if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Error: unable to open journal %s: %s\n", file,
			isc_result_totext(result));
		return result;
	}

	if (dns_journal_empty(jnl)) {
		dns_journal_destroy(&jnl);
		return ISC_R_SUCCESS;
	}

	result = dns_journal_rollforward(jnl, db, 0);
	switch (result) {
	case ISC_R_SUCCESS:
		break;
	case DNS_R_UPTODATE:
		result = ISC_R_SUCCESS;
		break;

	case ISC_R_NOTFOUND:
	case ISC_R_RANGE:
		fprintf(stderr, "Error: journal %s out of sync with zone",
			file);
		break;

	default:
		fprintf(stderr, "Error: journal %s: %s\n", file,
			isc_result_totext(result));
	}

	dns_journal_destroy(&jnl);
	return result;
}

int
main(int argc, char **argv) {
	isc_result_t result;
	const char *origin = NULL;
	const char *file1 = NULL, *file2 = NULL;
	const char *journal = NULL;
	dns_db_t *olddb = NULL, *newdb = NULL;
	isc_logconfig_t *logconfig = NULL;
	uint32_t s1, s2, s3;
	int ch;

	isc_commandline_init(argc, argv);

	while ((ch = isc_commandline_parse(argc, argv, "hm")) != -1) {
		switch (ch) {
		case 'h':
			usage(0);
			break;
		case 'm':
			isc_mem_debugon(ISC_MEM_DEBUGRECORD);
			break;
		default:
			usage(1);
		}
	}
	argc -= isc_commandline_index;
	argv += isc_commandline_index;
	if (argc < 3 || argc > 4) {
		usage(1);
	}

	origin = argv[0];
	file1 = argv[1];
	file2 = argv[2];

	if (argc == 4) {
		journal = argv[3];
	} else {
		snprintf(jbuf, sizeof(jbuf), "%s.jnl", file1);
		journal = (const char *)jbuf;
	}

	logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	result = loadzone(&olddb, origin, file1);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Unable to load %s: %s\n", file1,
			isc_result_totext(result));
		goto cleanup;
	}

	result = loadzone(&newdb, origin, file2);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Unable to load %s: %s\n", file1,
			isc_result_totext(result));
		goto cleanup;
	}

	result = dns_db_getsoaserial(olddb, NULL, &s1);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Error: %s: SOA lookup failed\n", file1);
		goto cleanup;
	}

	result = loadjournal(olddb, journal);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = dns_db_getsoaserial(olddb, NULL, &s2);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_db_getsoaserial(newdb, NULL, &s3);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Error: %s: SOA lookup failed\n", file2);
		goto cleanup;
	}

	if (isc_serial_eq(s1, s3)) {
		fprintf(stderr,
			"Error: SOA serial (%u) unchanged between files\n", s1);
		result = ISC_R_FAILURE;
		goto cleanup;
	} else if (isc_serial_eq(s2, s3)) {
		fprintf(stderr, "Journal %s already has serial %u\n", journal,
			s3);
		goto cleanup;
	}

	result = dns_db_diff(isc_g_mctx, newdb, NULL, olddb, NULL, journal);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "Comparison failed: %s\n",
			isc_result_totext(result));
	}

cleanup:
	if (newdb != NULL) {
		dns_db_detach(&newdb);
	}
	if (olddb != NULL) {
		dns_db_detach(&olddb);
	}

	return (result != ISC_R_SUCCESS) ? 1 : 0;
}
