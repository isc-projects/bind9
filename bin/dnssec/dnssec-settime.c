/*
 * Copyright (C) 2009  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id: dnssec-settime.c,v 1.6 2009/07/21 02:57:39 jinmei Exp $ */

/*! \file */

#include <config.h>

#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/entropy.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/result.h>

#include <dst/dst.h>

#include "dnssectool.h"

const char *program = "dnssec-settime";
int verbose;

static isc_mem_t	*mctx = NULL;

static void
usage(void) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,	"    %s [options] keyfile\n\n", program);
	fprintf(stderr, "Version: %s\n", VERSION);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -f:                 force update of old-style "
						 "keys\n");
	fprintf(stderr, "    -K directory:       set key file location\n");
	fprintf(stderr, "    -h:	         help\n");
	fprintf(stderr, "    -v level:	         set level of verbosity\n");
	fprintf(stderr, "Timing options:\n");
	fprintf(stderr, "    -P date/[+-]offset: set key publication date\n");
	fprintf(stderr, "    -A date/[+-]offset: set key activation date\n");
	fprintf(stderr, "    -R date/[+-]offset: set key revocation date\n");
	fprintf(stderr, "    -U date/[+-]offset: set key unpublication date\n");
	fprintf(stderr, "    -D date/[+-]offset: set key deletion date\n");
	fprintf(stderr, "Output:\n");
	fprintf(stderr, "     K<name>+<alg>+<new id>.key, "
			     "K<name>+<alg>+<new id>.private\n");

	exit (-1);
}

static void
printtime(dst_key_t *key, int type, const char *tag, FILE *stream) {
	isc_result_t result;
	time_t when;
	const char *output;

	result = dst_key_gettime(key, type, (isc_stdtime_t *) &when);
	if (result == ISC_R_NOTFOUND || when == 0) {
		fprintf(stream, "%s: NOT SET\n", tag);
		return;
	}

	output = ctime(&when);
	fprintf(stream, "%s: %s", tag, output);
}

int
main(int argc, char **argv) {
	isc_result_t result;
	char *filename = NULL, *directory = NULL;
	char newname[1024];
	char keystr[KEY_FORMATSIZE];
	char *endp;
	int ch;
	isc_entropy_t *ectx = NULL;
	dst_key_t *key = NULL;
	isc_buffer_t buf;
	isc_stdtime_t	now, when;
	isc_stdtime_t	pub = 0, act = 0, rev = 0, unpub = 0, del = 0;
	isc_boolean_t	setpub = ISC_FALSE, setact = ISC_FALSE;
	isc_boolean_t	setrev = ISC_FALSE, setunpub = ISC_FALSE;
	isc_boolean_t	setdel = ISC_FALSE;
	isc_boolean_t	forceupdate = ISC_FALSE;
	isc_boolean_t	print = ISC_TRUE;

	if (argc == 1)
		usage();

	result = isc_mem_create(0, 0, &mctx);
	if (result != ISC_R_SUCCESS)
		fatal("Out of memory");

	dns_result_register();

	isc_commandline_errprint = ISC_FALSE;

	isc_stdtime_get(&now);

	while ((ch = isc_commandline_parse(argc, argv,
					   "fK:hv:P:A:R:U:D:")) != -1) {
		switch (ch) {
		case 'f':
			forceupdate = ISC_TRUE;
			break;
		case 'K':
			/*
			 * We don't have to copy it here, but do it to
			 * simplify cleanup later
			 */
			directory = isc_mem_strdup(mctx,
						   isc_commandline_argument);
			if (directory == NULL) {
				fatal("Failed to memory allocation for "
				      "directory");
			}
			break;
		case 'v':
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				fatal("-v must be followed by a number");
			break;
		case 'P':
			print = ISC_FALSE;
			setpub = ISC_TRUE;
			pub = strtotime(isc_commandline_argument, now, now);
			break;
		case 'A':
			print = ISC_FALSE;
			setact = ISC_TRUE;
			act = strtotime(isc_commandline_argument, now, now);
			break;
		case 'R':
			print = ISC_FALSE;
			setrev = ISC_TRUE;
			rev = strtotime(isc_commandline_argument, now, now);
			break;
		case 'U':
			print = ISC_FALSE;
			setunpub = ISC_TRUE;
			unpub = strtotime(isc_commandline_argument, now, now);
			break;
		case 'D':
			print = ISC_FALSE;
			setdel = ISC_TRUE;
			del = strtotime(isc_commandline_argument, now, now);
			break;
		case '?':
			if (isc_commandline_option != '?')
				fprintf(stderr, "%s: invalid argument -%c\n",
					program, isc_commandline_option);
			/* Falls into */
		case 'h':
			usage();

		default:
			fprintf(stderr, "%s: unhandled option -%c\n",
				program, isc_commandline_option);
			exit(1);
		}
	}

	if (argc < isc_commandline_index + 1 ||
	    argv[isc_commandline_index] == NULL)
		fatal("The key file name was not specified");
	if (argc > isc_commandline_index + 1)
		fatal("Extraneous arguments");

	if (directory == NULL) {
		char *slash;
#ifdef _WIN32
		char *backslash;
#endif

		directory = isc_mem_strdup(mctx, argv[isc_commandline_index]);
		if (directory == NULL)
			fatal("Failed to memory allocation for directory");
		filename = directory;

		/* Figure out the directory name from the key name */
		slash = strrchr(directory, '/');
#ifdef _WIN32
		backslash = strrchr(directory, '\\');
		if ((slash != NULL && backslash != NULL && backslash > slash) ||
		    (slash == NULL && backslash != NULL))
			slash = backslash;
#endif
		if (slash != NULL) {
			*slash++ = '\0';
			filename = slash;
		} else {
			isc_mem_free(mctx, directory);
			/* strdup could be skipped (see above) */
			directory = isc_mem_strdup(mctx, ".");
			if (directory == NULL) {
				fatal("Failed to memory allocation "
				      "for directory");
			}
		}
	} else
		filename = argv[isc_commandline_index];

	if (ectx == NULL)
		setup_entropy(mctx, NULL, &ectx);
	result = isc_hash_create(mctx, ectx, DNS_NAME_MAXWIRE);
	if (result != ISC_R_SUCCESS)
		fatal("Could not initialize hash");
	result = dst_lib_init(mctx, ectx,
			      ISC_ENTROPY_BLOCKING | ISC_ENTROPY_GOODONLY);
	if (result != ISC_R_SUCCESS)
		fatal("Could not initialize dst");
	isc_entropy_stopcallbacksources(ectx);

	result = dst_key_fromnamedfile(filename, directory,
				       DST_TYPE_PUBLIC | DST_TYPE_PRIVATE,
				       mctx, &key);
	if (result != ISC_R_SUCCESS)
		fatal("Invalid keyfile %s: %s",
		      filename, isc_result_totext(result));

	if (!dst_key_isprivate(key))
		fatal("%s is not a private key", filename);

	key_format(key, keystr, sizeof(keystr));

	/* Is this an old-style key? */
	result = dst_key_gettime(key, DST_TIME_CREATED, &when);
	if (result == ISC_R_NOTFOUND) {
		if (forceupdate)
			dst_key_settime(key, DST_TIME_CREATED, now);
		else
			fatal("Incompatible key %s, "
			      "use -f force update.", keystr);
	}

	if (verbose > 2)
		fprintf(stderr, "%s: %s\n", program, keystr);

	if (print) {
		printtime(key, DST_TIME_CREATED, "Created", stdout);
		printtime(key, DST_TIME_PUBLISH, "Publish", stdout);
		printtime(key, DST_TIME_ACTIVATE, "Activate", stdout);
		printtime(key, DST_TIME_REVOKE, "Revoke", stdout);
		printtime(key, DST_TIME_REMOVE, "Remove", stdout);
		printtime(key, DST_TIME_DELETE, "Delete", stdout);
	} else {
		if (setpub)
			dst_key_settime(key, DST_TIME_PUBLISH, pub);

		if (setact)
			dst_key_settime(key, DST_TIME_ACTIVATE, act);

		if (setrev)
			dst_key_settime(key, DST_TIME_REVOKE, rev);

		if (setunpub)
			dst_key_settime(key, DST_TIME_REMOVE, unpub);

		if (setdel)
			dst_key_settime(key, DST_TIME_DELETE, del);

		isc_buffer_init(&buf, newname, sizeof(newname));
		result = dst_key_buildfilename(key, DST_TYPE_PUBLIC, directory,
					       &buf);
		if (result != ISC_R_SUCCESS) {
			fatal("Failed to build public key filename: %s",
			      isc_result_totext(result));
		}

		result = dst_key_tofile(key, DST_TYPE_PUBLIC|DST_TYPE_PRIVATE,
					directory);
		if (result != ISC_R_SUCCESS) {
			key_format(key, keystr, sizeof(keystr));
			fatal("Failed to write key %s: %s", keystr,
			      isc_result_totext(result));
		}

		printf("%s\n", newname);

		isc_buffer_clear(&buf);
		result = dst_key_buildfilename(key, DST_TYPE_PRIVATE, directory,
					       &buf);
		if (result != ISC_R_SUCCESS) {
			fatal("Failed to build private key filename: %s",
			      isc_result_totext(result));
		}
		printf("%s\n", newname);
	}

	dst_key_free(&key);
	dst_lib_destroy();
	isc_hash_destroy();
	cleanup_entropy(&ectx);
	if (verbose > 10)
		isc_mem_stats(mctx, stdout);
	isc_mem_free(mctx, directory);
	isc_mem_destroy(&mctx);

	return (0);
}
