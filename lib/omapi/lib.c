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

/* $ID: $ */

#include <stddef.h>

#include <isc/assertions.h>
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
isc_task_t *omapi_task;
isc_taskmgr_t *omapi_taskmgr;
isc_socketmgr_t *omapi_socketmgr;

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
omapi_lib_init(isc_mem_t *mctx, isc_taskmgr_t *taskmgr,
	       isc_socketmgr_t *socketmgr)
{
	isc_result_t result;

	/*
	 * Can only be called once without an intervening omapi_lib_destroy.
	 */
	REQUIRE(omapi_mctx == NULL &&
		omapi_socketmgr == NULL &&
		omapi_taskmgr == NULL &&
		omapi_task == NULL &&
		omapi_object_types == NULL);

	REQUIRE(mctx != NULL && taskmgr != NULL && socketmgr != NULL);

	omapi_mctx = mctx;
	omapi_taskmgr = taskmgr;
	omapi_socketmgr = socketmgr;

	result = isc_task_create(omapi_taskmgr, omapi_mctx, 0, &omapi_task);
	if (result == ISC_R_SUCCESS)
		isc_task_setname(omapi_task, "omapi", NULL);

	/*
	 * Initialize the standard object types.
	 */
	if (result == ISC_R_SUCCESS)
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
	object_destroytypes();

	handle_destroy();

	auth_destroy();

	isc_task_destroy(&omapi_task);

	omapi_mctx = NULL;
	omapi_socketmgr = NULL;
	omapi_taskmgr = NULL;
}
