/* test.c

   Test code for omapip... */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <isc/result.h>
#include <omapip/omapip.h>

int main (int argc, char **argv)
{
	omapi_object_t *listener = (omapi_object_t*)0;
	omapi_object_t *connection = (omapi_object_t*)0;
	isc_result_t status;

	omapi_init ();

	if (argc > 1 && !strcmp (argv [1], "listen")) {
		if (argc < 3) {
			fprintf (stderr, "Usage: test listen port\n");
			exit (1);
		}
		status = omapi_generic_new (&listener, "main");
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_generic_new: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		status = omapi_protocol_listen (listener,
						atoi (argv [2]), 1);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_listen: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		omapi_dispatch (0);
	} else if (argc > 1 && !strcmp (argv [1], "connect")) {
		if (argc < 4) {
			fprintf (stderr, "Usage: test listen address port\n");
			exit (1);
		}
		status = omapi_generic_new (&connection, "main");
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "omapi_generic_new: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
		status = omapi_protocol_connect (connection,
						 argv [2], atoi (argv [3]), 0);
		fprintf (stderr, "connect: %s\n", isc_result_totext (status));
		if (status != ISC_R_SUCCESS)
			exit (1);
		status = omapi_wait_for_completion (connection, 0);
		fprintf (stderr, "completion: %s\n",
			 isc_result_totext (status));
		if (status != ISC_R_SUCCESS)
			exit (1);
		/* ... */
	} else {
		fprintf (stderr, "Usage: test [listen | connect] ...\n");
		exit (1);
	}

	return 0;
}
