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

/* $Id: dispatch.c,v 1.7 2000/01/13 06:13:22 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * I/O dispatcher.
 */
#include <stddef.h>		/* NULL */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/int.h>

#include <omapi/private.h>

isc_result_t
omapi_dispatch(struct timeval *t) {
	/*
	 * XXXDCL sleep forever?  The socket thread will be doing all the work.
	 */

	select(0, NULL, NULL, NULL, t ? t : NULL);
	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_io_setvalue(omapi_object_t *io, omapi_object_t *id,
		  omapi_data_string_t *name, omapi_typed_data_t *value)
{
	REQUIRE(io != NULL && io->type == omapi_type_io_object);

	PASS_SETVALUE(io);
}

isc_result_t
omapi_io_getvalue(omapi_object_t *io, omapi_object_t *id,
		  omapi_data_string_t *name, omapi_value_t **value)
{
	REQUIRE(io != NULL && io->type == omapi_type_io_object);
	
	PASS_GETVALUE(io);
}

void
omapi_io_destroy(omapi_object_t *io, const char *name) {
	REQUIRE(io != NULL && io->type == omapi_type_io_object);

	(void)name;		/* Unused. */
}

isc_result_t
omapi_io_signalhandler(omapi_object_t *io, const char *name, va_list ap)
{
	REQUIRE(io != NULL && io->type == omapi_type_io_object);

	PASS_SIGNAL(io);
}

isc_result_t
omapi_io_stuffvalues(omapi_object_t *connection, omapi_object_t *id,
		      omapi_object_t *io)
{
	REQUIRE(io != NULL && io->type == omapi_type_io_object);

	PASS_STUFFVALUES(io);
}

isc_result_t
omapi_waiter_signal_handler(omapi_object_t *h, const char *name, va_list ap) {
	omapi_waiter_object_t *waiter;

	fprintf(stderr, "omapi_waiter_signal_handler\n");

	REQUIRE(h != NULL && h->type == omapi_type_waiter);
	
	if (strcmp(name, "ready") == 0) {
		fprintf(stderr, "unblocking waiter\n");
		waiter = (omapi_waiter_object_t *)h;
		isc_condition_signal(&waiter->ready);
		return (ISC_R_SUCCESS);
	}

	PASS_SIGNAL(h);
}

