/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* $Id: log_test.c,v 1.7 2000/02/03 23:03:46 halley Exp $ */

/* Principal Authors: DCL */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/log.h>
#include <isc/result.h>

#include <dns/log.h>
#include <dns/result.h>

#define TEST_FILE "/tmp/test_log"
#define SYSLOG_FILE "/var/log/daemon.log"
#define FILE_VERSIONS 10

char usage[] = "Usage: %s [-m] [-s syslog_logfile] [-r file_versions]\n";

#define CHECK_ISC(expr) result = expr; \
	if (result != ISC_R_SUCCESS) { \
		fprintf(stderr, "%s: " #expr "%s: exiting\n", \
			progname, isc_result_totext(result)); \
	}

#define CHECK_DNS(expr) result = expr; \
	if (result != DNS_R_SUCCESS) { \
		fprintf(stderr, "%s: " #expr "%s: exiting\n", \
			progname, dns_result_totext(result)); \
	}

	
int
main (int argc, char **argv) {
	char *progname, *syslog_file, *message;
	int ch, i, file_versions;
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_log_t *lctx;
	isc_mem_t *mctx;
	isc_result_t result;
	isc_logdestination_t destination;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	syslog_file = SYSLOG_FILE;
	file_versions = FILE_VERSIONS;

	while ((ch = isc_commandline_parse(argc, argv, "ms:r:")) != -1) {
		switch (ch) {
		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		case 's':
			syslog_file = isc_commandline_argument;
			break;
		case 'r':
			file_versions = atoi(isc_commandline_argument);
			if (file_versions < 0 &&
			    file_versions != ISC_LOG_ROLLNEVER &&
			    file_versions != ISC_LOG_ROLLINFINITE) {
				fprintf(stderr, "%s: file rotations must be "
					"%d (ISC_LOG_ROLLNEVER), "
					"%d (ISC_LOG_ROLLINFINITE) "
					"or > 0\n", progname,
					ISC_LOG_ROLLNEVER,
					ISC_LOG_ROLLINFINITE);
				exit(1);
			}
			break;
		case '?':
			fprintf(stderr, usage, progname);
			exit(1);
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc > 0) {
		fprintf(stderr, usage, progname);
		exit(1);
	}

	fprintf(stderr, "==> stderr begin\n");
	isc_log_opensyslog(progname, LOG_PID, LOG_DAEMON);

	mctx = NULL;
	lctx = NULL;

	CHECK_ISC(isc_mem_create(0, 0, &mctx));
	CHECK_ISC(isc_log_create(mctx, &lctx));
	CHECK_DNS(dns_log_init(lctx));

	/*
	 * Create a file channel to test file opening, size limiting and
	 * version rolling.
	 */

	destination.file.name = TEST_FILE;
	destination.file.maximum_size = 1;
	destination.file.versions = file_versions;

	CHECK_ISC(isc_log_createchannel(lctx, "file_test", ISC_LOG_TOFILE,
					ISC_LOG_INFO, &destination,
					ISC_LOG_PRINTTIME|
					ISC_LOG_PRINTLEVEL|
					ISC_LOG_PRINTCATEGORY|
					ISC_LOG_PRINTMODULE));

	/*
	 * Create a dynamic debugging channel to a file descriptor.
	 */
	destination.file.stream = stderr;

	CHECK_ISC(isc_log_createchannel(lctx, "debug_test", ISC_LOG_TOFILEDESC,
					ISC_LOG_DYNAMIC, &destination,
					ISC_LOG_PRINTTIME|
					ISC_LOG_PRINTLEVEL));

	/*
	 * Test the usability of the four predefined logging channels.
	 */
	CHECK_ISC(isc_log_usechannel(lctx, "default_syslog",
				     DNS_LOGCATEGORY_DATABASE,
				     DNS_LOGMODULE_CACHE));
	CHECK_ISC(isc_log_usechannel(lctx, "default_stderr",
				     DNS_LOGCATEGORY_DATABASE,
				     DNS_LOGMODULE_CACHE));
	CHECK_ISC(isc_log_usechannel(lctx, "default_debug",
				     DNS_LOGCATEGORY_DATABASE,
				     DNS_LOGMODULE_CACHE));
	CHECK_ISC(isc_log_usechannel(lctx, "null",
				     DNS_LOGCATEGORY_DATABASE,
				     NULL));

	/*
	 * Use the custom channels.
	 */
	CHECK_ISC(isc_log_usechannel(lctx, "file_test",
				     DNS_LOGCATEGORY_GENERAL,
				     DNS_LOGMODULE_DB));

	CHECK_ISC(isc_log_usechannel(lctx, "debug_test",
				     DNS_LOGCATEGORY_GENERAL,
				     DNS_LOGMODULE_RBTDB));

	/*
	 * Write to the internal default by testing both a category for which
	 * no channel has been specified and a category which was specified
	 * but not with the named module.
	 */
	isc_log_write(lctx, DNS_LOGCATEGORY_SECURITY, DNS_LOGMODULE_RBT,
		      ISC_LOG_CRITICAL, "%s",
		      "Unspecified category and unspecified module to stderr");
	isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBT,
		      ISC_LOG_CRITICAL, "%s",
		      "Specified category and unspecified module to stderr");

	/*
	 * Write to default_syslog, default_stderr and default_debug.
	 */
	isc_log_write(lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_CACHE,
		      ISC_LOG_WARNING, "%s%s",
		      "Using the predefined channels to send ",
		      "to syslog+stderr+stderr");

	/*
	 * Write to predefined null channel.
	 */
	isc_log_write(lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_RBTDB,
		      ISC_LOG_INFO, "This is to null and should not appear!");

	/*
	 * Reset the internal default to use syslog instead of stderr,
	 * and test it.
	 */
	CHECK_ISC(isc_log_usechannel(lctx, "default_syslog",
				     ISC_LOGCATEGORY_DEFAULT,
				     NULL));
	isc_log_write(lctx, DNS_LOGCATEGORY_SECURITY, DNS_LOGMODULE_RBT,
		      ISC_LOG_ERROR, "%s%s",
		      "This message to the redefined default category should ",
		      "be second in syslog");
	/*
	 * Write to the file channel.
	 */
	if (file_versions >= 0 || file_versions == ISC_LOG_ROLLINFINITE) {

		if (file_versions == ISC_LOG_ROLLINFINITE)
			file_versions = FILE_VERSIONS; /* Whatever. */

		else
			isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_DB, ISC_LOG_NOTICE,
				      "This should be rolled over "
				      "and not appear!");

		for (i = file_versions - 1; i >= 0; i--)
			isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_DB, ISC_LOG_NOTICE,
				      "This should be in file %d/%d", i,
				      file_versions - 1);

		isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_DB, ISC_LOG_NOTICE,
			      "This should be in the base file");

	} else {
		file_versions = FILE_VERSIONS;
		for (i = 1; i <= file_versions; i++)
			isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL,
				      DNS_LOGMODULE_DB, ISC_LOG_NOTICE,
				      "This is message %d in the log file", i);
	}


	/*
	 * Write a debugging message to a category that has no
	 * debugging channels for the named module.
	 */
	isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_DB,
		      ISC_LOG_DEBUG(1),
		      "This debug message should not appear!");

	/*
	 * Write debugging messages to a dynamic debugging channel.
	 */
	isc_log_setdebuglevel(lctx, 3);

	isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBTDB,
		      ISC_LOG_DEBUG(1), "Dynamic debugging to stderr");
	isc_log_write(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBTDB,
		      ISC_LOG_DEBUG(5),
		      "This debug level is too high and should not appear!");

	/*
	 * Test out the duplicate filtering using the debug_test channel.
	 */
	isc_log_setduplicateinterval(lctx, 10);
	message = "This message should appear only once on stderr";

	isc_log_write1(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBTDB,
		       ISC_LOG_CRITICAL, message);
	isc_log_write1(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBTDB,
		       ISC_LOG_CRITICAL, message);

	isc_log_setduplicateinterval(lctx, 1);
	message = "This message should appear twice on stderr";
	
	isc_log_write1(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBTDB,
		       ISC_LOG_CRITICAL, message);
	sleep(2);
	isc_log_write1(lctx, DNS_LOGCATEGORY_GENERAL, DNS_LOGMODULE_RBTDB,
		       ISC_LOG_CRITICAL, message);

	/*
	 * Review where everything went.
	 * XXXDCL NT
	 */
	fputc('\n', stderr);
	system("head " TEST_FILE "*; rm -f " TEST_FILE "*");

	freopen(syslog_file, "r", stdin);
	fprintf(stderr, "\n==> %s <==\n", syslog_file);
	system("tail -2");
	fputc('\n', stderr);

	isc_log_destroy(&lctx);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	exit(0);
}
