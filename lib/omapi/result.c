/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: result.c,v 1.10.4.1 2001/01/09 22:53:04 bwelling Exp $ */
#include <config.h>

#include <isc/once.h>
#include <isc/util.h>

#include <omapi/result.h>
#include <omapi/lib.h>

static const char *text[OMAPI_R_NRESULTS] = {
	"data not yet available",		/* 0 */
	"not connected",			/* 1 */
	"no key specified",			/* 2 */
	"invalid argument",			/* 3 */
	"protocol version mismatch",		/* 4 */
	"protocol error",			/* 5 */
};


#define OMAPI_RESULT_RESULTSET			2

static isc_once_t		once = ISC_ONCE_INIT;

static void
initialize_action(void) {
	isc_result_t result;

	result = isc_result_register(ISC_RESULTCLASS_OMAPI, OMAPI_R_NRESULTS,
				     text, omapi_msgcat,
				     OMAPI_RESULT_RESULTSET);
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_result_register() failed: %u", result);
}

static void
initialize(void) {
	omapi_lib_initmsgcat();
	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);
}

const char *
omapi_result_totext(isc_result_t result) {
	initialize();

	return (isc_result_totext(result));
}

void
omapi_result_register(void) {
	initialize();
}
