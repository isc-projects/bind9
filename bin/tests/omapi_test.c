/*
 * Copyright (C) 1996, 1997, 1998, 1999  Internet Software Consortium.
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

/* 
 * Test code for OMAPI.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/commandline.h>

#include <omapi/omapip.h>

char *progname;
isc_mem_t *mctx;

int
main (int argc, char **argv) {
	omapi_object_t *listener = NULL;
	omapi_object_t *connection = NULL;
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_result_t result;
	int ch;

	progname = strrchr(*argv, '/');
	if (progname != NULL)
		progname++;
	else
		progname = *argv;

	while ((ch = isc_commandline_parse(argc, argv, "m")) != -1) {
		switch (ch) {
		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	result = isc_mem_create(0, 0, &mctx);
	if (result != ISC_R_SUCCESS) {
		printf("%s: isc_mem_create: %s: exiting\n",
		       progname, isc_result_totext(result));
		exit(1);
	}

	result = omapi_init(mctx);
	if (result != ISC_R_SUCCESS) {
		printf("%s: omapi_init: %s: exiting\n",
		       progname, isc_result_totext(result));
		exit(1);
	}

	if (argc > 1 && strcmp(argv[0], "listen") == 0) {
		if (argc < 2) {
			fprintf(stderr, "Usage: %s listen port\n", progname);
			exit (1);
		}
		result = omapi_generic_new(&listener, "main");
		if (result != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_generic_new: %s\n",
				 isc_result_totext(result));
			exit (1);
		}
		result = omapi_protocol_listen(listener, atoi(argv[1]), 1);
		if (result != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_listen: %s\n",
				 isc_result_totext(result));
			exit (1);
		}
		omapi_dispatch(NULL);

	} else if (argc > 1 && !strcmp (argv[0], "connect")) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s connect address port\n",
				progname);
			exit (1);
		}
		result = omapi_generic_new(&connection, "main");
		if (result != ISC_R_SUCCESS) {
			fprintf(stderr, "omapi_generic_new: %s\n",
				isc_result_totext(result));
			exit (1);
		}
		result = omapi_protocol_connect(connection, argv[1],
						atoi(argv[2]), 0);
		fprintf(stderr, "connect: %s\n", isc_result_totext(result));
		if (result != ISC_R_SUCCESS)
			exit (1);

		omapi_protocol_disconnect(connection, ISC_FALSE);
		fprintf(stderr, "completed\n");
		/* ... */

	} else {
		fprintf(stderr, "Usage: %s [-m] [listen | connect] ...\n",
			progname);
		exit (1);
	}

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	return (0);
}
