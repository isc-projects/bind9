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
#include <isc/result.h>
#include <omapi/omapip.h>

int
main (int argc, char **argv) {
	omapi_object_t *listener = NULL;
	omapi_object_t *connection = NULL;
	isc_result_t result;

	omapi_init();

	if (argc > 1 && strcmp(argv[1], "listen") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: test listen port\n");
			exit (1);
		}
		result = omapi_generic_new(&listener, "main");
		if (result != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_generic_new: %s\n",
				 isc_result_totext(result));
			exit (1);
		}
		result = omapi_protocol_listen(listener, atoi(argv[2]), 1);
		if (result != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_listen: %s\n",
				 isc_result_totext(result));
			exit (1);
		}
		omapi_dispatch(0);

	} else if (argc > 1 && !strcmp (argv[1], "connect")) {
		if (argc < 4) {
			fprintf(stderr, "Usage: test listen address port\n");
			exit (1);
		}
		result = omapi_generic_new(&connection, "main");
		if (result != ISC_R_SUCCESS) {
			fprintf(stderr, "omapi_generic_new: %s\n",
				isc_result_totext(result));
			exit (1);
		}
		result = omapi_protocol_connect(connection,
						 argv[2], atoi(argv[3]), 0);
		fprintf(stderr, "connect: %s\n", isc_result_totext(result));
		if (result != ISC_R_SUCCESS)
			exit (1);
		result = omapi_wait_for_completion(connection, 0);
		fprintf(stderr, "completion: %s\n", isc_result_totext(result));
		if (result != ISC_R_SUCCESS)
			exit (1);
		/* ... */
	} else {
		fprintf(stderr, "Usage: test [listen | connect] ...\n");
		exit (1);
	}

	return (0);
}
