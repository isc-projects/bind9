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

/* $Id: omapi.c,v 1.13 2000/05/08 14:32:57 tale Exp $ */

/*
 * Principal Author: DCL
 */

#include <config.h>

#include <isc/event.h>
#include <isc/util.h>

#include <named/log.h>
#include <named/omapi.h>
#include <named/server.h>

/*
 * The control_object structure is used for receiving commands that
 * request the server to perform some action, but that do not set or
 * get any state.
 */
typedef struct control_object {
	OMAPI_OBJECT_PREAMBLE;
} control_object_t;

static control_object_t control;
static omapi_objecttype_t *control_type;

static void
listen_done(isc_task_t *task, isc_event_t *event);

#undef REGION_FMT
/*
 * Ok, kind of gross.  Sorry.  A little.
 */
#define REGION_FMT(r) (int)(r)->length, (r)->base

/*
 * This is the function that is called when an incoming OMAPI_OP_OPEN
 * message is received with either the create or update option set.
 * It is called once for each name/value pair in the message's object
 * value list.
 */
static isc_result_t
control_setvalue(omapi_object_t *handle, omapi_string_t *name,
		 omapi_data_t *value)
{
	isc_region_t region;
	isc_result_t result;

	INSIST(handle == (omapi_object_t *)&control);

	omapi_string_totext(name, &region);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_OMAPI, ISC_LOG_DEBUG(1),
		      "control_setvalue: '%.*s' control command received",
		      REGION_FMT(&region));

	/*
	 * Compare the 'name' parameter against all known control commands.
	 */
	if (omapi_string_strcmp(name, NS_OMAPI_COMMAND_RELOAD) == 0) {
		if (omapi_data_getint(value) != 0)
			ns_server_reloadwanted(ns_g_server);

		result = ISC_R_SUCCESS;

	} else if (omapi_string_strcmp(name,
				       NS_OMAPI_COMMAND_RELOADCONFIG) == 0 ||
		   omapi_string_strcmp(name,
				       NS_OMAPI_COMMAND_RELOADZONES) == 0) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
			      "control_setvalue: '%.*s' not yet implemented",
			      REGION_FMT(&region));
		result = ISC_R_NOTIMPLEMENTED;

	} else {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
			      "control_setvalue: unknown name: '%.*s'",
			      REGION_FMT(&region));
		result = omapi_object_passsetvalue(handle, name, value);
	}

	return (result);
}

/*
 * This is the function that is called by the library's internal
 * message_process function when an incoming OMAPI_OP_OPEN message is received.
 * It is supposed to look up the object in the server that corresponds to the
 * key data (name/value pair(s)) in 'key'.
 */
static isc_result_t
control_lookup(omapi_object_t **control_object, omapi_object_t *key) {
	/*
	 * There is only one control object so no key is needed to look it up.
	 */
	UNUSED(key);

	omapi_object_reference(control_object, (omapi_object_t *)&control);

	return (ISC_R_SUCCESS);
}

/*
 * This function is called when the server is sending a reply to a client
 * that opened an object of its type.  It needs to output all published
 * name/value pairs for the object, and will typically also put the data
 * for any inner objects (but in this program, there will be no inner
 * objects).  The handle parameter is an object of the type registered
 * in ns_omapi_listen.
 */
static isc_result_t
control_stuffvalues(omapi_object_t *connection, omapi_object_t *handle) {
	/*
	 * Currently the server has no values to publish, but it needs
	 * to publish something for its OMAPI_OP_UPDATE function to work
	 * when received by the client.
	 */
	return (omapi_object_passstuffvalues(connection, handle));
}

isc_result_t
ns_omapi_init(void) {
	isc_result_t result;

	result = omapi_lib_init(ns_g_mctx, ns_g_taskmgr, ns_g_socketmgr);

	if (result == ISC_R_SUCCESS)
		/*
		 * Register the control_object.  NS_OMAPI_CONTROL is
		 * what a client would need to specify as a value for
		 * the value of "type" in a message when contacting
		 * the server to perform a control function.
		 */
		result = omapi_object_register(&control_type, NS_OMAPI_CONTROL,
					       control_setvalue,
					       NULL, 	/* getvalue */
					       NULL,	/* destroy */
					       NULL,	/* signalhandler */
					       control_stuffvalues,
					       control_lookup,
					       NULL,	/* create */
					       NULL);	/* remove */

	if (result == ISC_R_SUCCESS) {
		/*
		 * Initialize the static control object.
		 */
		control.refcnt = 1;
		control.type = control_type;
	}

	return (result);
}

isc_result_t
ns_omapi_listen(omapi_object_t **managerp) {
	omapi_object_t *manager = NULL;
	isc_result_t result;
	isc_sockaddr_t sockaddr;
	isc_netaddr_t netaddr;
	dns_acl_t *acl;		/* XXXDCL make a parameter */
	dns_aclelement_t elt;
	struct in_addr inaddr4;

	REQUIRE(managerp != NULL && *managerp == NULL);

	/*
	 * Listen on localhost (127.0.0.1).
	 * XXXDCL should be configurable.
	 */
	inaddr4.s_addr = htonl(0x7F000001);
	isc_sockaddr_fromin(&sockaddr, &inaddr4, NS_OMAPI_PORT);

	/*
	 * XXXDCL this is not right either
	 */
	isc_netaddr_fromsockaddr(&netaddr, &sockaddr);
	elt.type = dns_aclelementtype_ipprefix;
	elt.negative = ISC_FALSE;
	elt.u.ip_prefix.address = netaddr;
	elt.u.ip_prefix.prefixlen = 32;

	result = dns_acl_create(ns_g_mctx, 1, &acl);

	if (result == ISC_R_SUCCESS)
		result = dns_acl_appendelement(acl, &elt);

	if (result == ISC_R_SUCCESS)
		/*
		 * Create a generic object to be the manager for handling
		 * incoming server connections.
		 */
		result = omapi_object_create(&manager, NULL, 0);

	if (result == ISC_R_SUCCESS) {
		/*
		 * Start listening for connections.
		 */
		result = omapi_protocol_listen(manager, &sockaddr, acl, 1,
					       listen_done, ns_g_omapimgr);
		dns_acl_detach(&acl);
	}

	if (result == ISC_R_SUCCESS)
		*managerp = manager;

	else
		if (manager != NULL)
			omapi_object_dereference(&manager);

	return (result);
}

static void
listen_done(isc_task_t *task, isc_event_t *event) {
	isc_event_free(&event);

	UNUSED(task);

	if (ns_g_omapimgr != NULL)
		omapi_object_dereference(&ns_g_omapimgr);

	omapi_lib_destroy();
}
