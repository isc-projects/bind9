/*
 * Copyright (C) 2000  Internet Software Consortium.
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

#include <config.h>

#include <stddef.h>

#include <isc/once.h>
#include <isc/error.h>
#include <isc/msgcat.h>

#include <omapi/lib.h>
#include <omapi/private.h>

/***
 *** Library Globals.
 ***/

isc_msgcat_t *omapi_msgcat = NULL;

omapi_objecttype_t *omapi_type_connection;
omapi_objecttype_t *omapi_type_listener;
omapi_objecttype_t *omapi_type_generic;
omapi_objecttype_t *omapi_type_protocol;
omapi_objecttype_t *omapi_type_message;
omapi_objecttype_t *omapi_object_types;

isc_mem_t *omapi_mctx;
isc_taskmgr_t *omapi_taskmgr;
isc_socketmgr_t *omapi_socketmgr;

isc_boolean_t omapi_ipv6 = ISC_FALSE;

/***
 *** Private to lib.c.
 ***/

static isc_once_t msgcat_once = ISC_ONCE_INIT;

/***
 *** Functions.
 ***/

static void
open_msgcat(void) {
	isc_msgcat_open("libomapi.cat", &omapi_msgcat);
}

void
omapi_lib_initmsgcat(void) {

	/*
	 * Initialize the OMAPI library's message catalog, omapi_msgcat, if it
	 * has not already been initialized.
	 */
	RUNTIME_CHECK(isc_once_do(&msgcat_once, open_msgcat) == ISC_R_SUCCESS);
}

isc_result_t
omapi_lib_init(isc_mem_t *mctx) {
	isc_result_t result;

	if (mctx != NULL)
		omapi_mctx = mctx;

	else {
		omapi_mctx = NULL;
		result = isc_mem_create(0, 0, &omapi_mctx);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	omapi_socketmgr = NULL;
	result = isc_socketmgr_create(omapi_mctx, &omapi_socketmgr);
	if (result != ISC_R_SUCCESS)
		return (result);

	omapi_taskmgr = NULL;
	result = isc_taskmgr_create(omapi_mctx, 1, 0, &omapi_taskmgr);
	if (result != ISC_R_SUCCESS)
		return (result);

	if (isc_net_probeipv6() == ISC_R_SUCCESS)
		omapi_ipv6 = ISC_TRUE;
	else
		omapi_ipv6 = ISC_FALSE;
	
	/*
	 * Initialize the standard object types.
	 */
	result = generic_init();
	if (result == ISC_R_SUCCESS)
		result = listener_init();

	if (result == ISC_R_SUCCESS)
		result = connection_init();

	if (result == ISC_R_SUCCESS)
		result = protocol_init();

	if (result == ISC_R_SUCCESS)
		result = message_init();

	return (result);
}

/*
 * This does not free connections and other in-use objects, only the
 * things created by omapi_lib_init().  It is the callers responsibility to
 * free the other things (as via omapi_connection_disconnect or
 * omapi_object_dereference).
 */
void
omapi_lib_destroy() {
	isc_socketmgr_destroy(&omapi_socketmgr);
	isc_taskmgr_destroy(&omapi_taskmgr);

	object_destroytypes();
}
