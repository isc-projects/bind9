/* alloc.h

   Definitions for the object management API protocol memory allocation... */

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

isc_result_t omapi_buffer_new (omapi_buffer_t **, const char *);
isc_result_t omapi_buffer_reference (omapi_buffer_t **,
				     omapi_buffer_t *, const char *);
isc_result_t omapi_buffer_dereference (omapi_buffer_t **, const char *);
