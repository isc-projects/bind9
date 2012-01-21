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

/* $Id: omapiconf.c,v 1.4.2.6 2000/09/15 16:24:12 gson Exp $ */

/*
 * Principal Author: DCL
 */

#include <config.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/event.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dst/result.h>

#include <named/log.h>
#include <named/omapi.h>
#include <named/server.h>

typedef struct ns_omapilistener ns_omapilistener_t;

typedef ISC_LIST(ns_omapilistener_t) ns_omapilistenerlist_t;

struct ns_omapilistener {
	/* XXXDCL magic */
	isc_mem_t *			mctx;
	omapi_object_t *		manager;
	isc_sockaddr_t			address;
	dns_acl_t *			acl;
	dns_c_kidlist_t *		keyids;
	LINK(ns_omapilistener_t)	link;
};

static ns_omapilistenerlist_t listeners;
static isc_mutex_t listeners_lock;
static isc_once_t once = ISC_ONCE_INIT;
static isc_boolean_t server_exiting = ISC_FALSE;

static void
initialize_mutex(void) {
	RUNTIME_CHECK(isc_mutex_init(&listeners_lock) == ISC_R_SUCCESS);
}

static void
free_listener(ns_omapilistener_t *listener) {
	if (listener->keyids != NULL)
		dns_c_kidlist_delete(&listener->keyids);

	if (listener->acl != NULL)
		dns_acl_detach(&listener->acl);

	if (listener->manager != NULL)
		omapi_object_dereference(&listener->manager);

	isc_mem_put(listener->mctx, listener, sizeof(*listener));
}

static void
listen_done(isc_task_t *task, isc_event_t *event) {
	ns_omapilistener_t *listener;

	UNUSED(task);

	listener = event->ev_arg;

	LOCK(&listeners_lock);

	ISC_LIST_UNLINK(listeners, listener, link);
	free_listener(listener);

	if (server_exiting && ISC_LIST_EMPTY(listeners))
		omapi_lib_destroy();

	UNLOCK(&listeners_lock);

	isc_event_free(&event);
}

void
ns_omapi_shutdown(isc_boolean_t exiting) {
	ns_omapilistener_t *listener;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	if (exiting) {
		/*
		 * When not exiting, this function is called from
		 * ns_omapi_configure(), which already holds the lock.
		 */
		LOCK(&listeners_lock);

		if (ISC_LIST_EMPTY(listeners))
			omapi_lib_destroy();
		else
			server_exiting = exiting;
	}

	for (listener = ISC_LIST_HEAD(listeners);
	     listener != NULL;
	     listener = ISC_LIST_NEXT(listener, link))
		/*
		 * This is asynchronous.  As listeners shut down, they will
		 * call listen_done().
		 */
		omapi_listener_shutdown(listener->manager);

	if (exiting)
		UNLOCK(&listeners_lock);
}

static isc_boolean_t
verify_connection(isc_sockaddr_t *sockaddr, void *arg) {
	ns_omapilistener_t *listener;
	isc_netaddr_t netaddr;
	isc_result_t result;
	int match;

	isc_netaddr_fromsockaddr(&netaddr, sockaddr);
	listener = arg;

	result = dns_acl_match(&netaddr, NULL, listener->acl,
			       &ns_g_server->aclenv, &match, NULL);

	if (result != ISC_R_SUCCESS || match <= 0)
		return (ISC_FALSE);
	else
		return (ISC_TRUE);
}

static isc_boolean_t
verify_key(const char *name, unsigned int algorithm, void *arg) {
	ns_omapilistener_t *listener;
	dns_c_kid_t *keyid = NULL;

	/*
	 * XXXDCL Ideally algorithm would be checked, too, but the current
	 * config API makes this moderately hard, and omapi will check it
	 * anyway.
	 */
	UNUSED(algorithm);

	listener = arg;

	(void)dns_c_kidlist_find(listener->keyids, name, &keyid);
	if (keyid != NULL)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

static isc_result_t
ns_omapi_listen(ns_omapilistener_t *listener) {
	isc_result_t result;

	REQUIRE(listener->manager == NULL);

	/*
	 * Create a generic object to be the manager for handling
	 * incoming server connections.
	 */
	result = omapi_object_create(&listener->manager, NULL, 0);

	if (result == ISC_R_SUCCESS)
		/*
		 * Start listening for connections.
		 */
		result = omapi_protocol_listen(listener->manager,
					       &listener->address,
					       verify_connection, verify_key,
					       listen_done, listener);

	if (result != ISC_R_SUCCESS && listener->manager != NULL)
		omapi_object_dereference(&listener->manager);

	return (result);
}

static void
register_keys(dns_c_ctrl_t *control, dns_c_kdeflist_t *keydeflist,
	      char *socktext)
{
	dns_c_kid_t *keyid;
	dns_c_kdef_t *keydef;
	char secret[1024];
	isc_buffer_t b;
	isc_result_t result;

	/*
	 * Register the keys used by this listener.  omapi_auth_deregister()
	 * is used to delete any existing key in case its secret or algorithm
	 * changed.
	 *
	 * XXXDCL but this means a little extra work overall when nothing
	 * changed.  In fact, the same key will be register/deregistered/
	 * reregistered if it appears more than once in the controls statement.
	 *
	 * XXXDCL a separate problem is that keys that have been removed
	 * from the controls statement in a reconfiguration are not deleted
	 * until the server shuts down.
	 */
	for (keyid = ISC_LIST_HEAD(control->keyidlist->keyids);
	     keyid != NULL;
	     keyid = ISC_LIST_NEXT(keyid, next)) {
		     omapi_auth_deregister(keyid->keyid);

		     /*
		      * XXXDCL confparser.y apparently allows any keyid
		      * in the list even if it has not been defined with
		      * the keys statement.
		      */
		     keydef = NULL;
		     result = dns_c_kdeflist_find(keydeflist, keyid->keyid,
						  &keydef);
		     if (result != ISC_R_SUCCESS)
			     isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
					   NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
					   "couldn't find key %s for "
					   "use with command channel %s",
					   keyid->keyid, socktext);
		     else if (strcasecmp(keydef->algorithm, "hmac-md5") != 0) {
			     isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
					   NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
					   "unsupported algorithm %s in "
					   "key %s for use with "
					   "command channel %s",
					   keydef->algorithm, keydef->keyid,
					   socktext);
			     result = DST_R_UNSUPPORTEDALG;
			     keydef = NULL; /* Prevent more error messages. */
		     }

		     if (result == ISC_R_SUCCESS) {
			     isc_buffer_init(&b, secret, sizeof(secret));
			     result = isc_base64_decodestring(ns_g_mctx,
							      keydef->secret,
							      &b);
		     }

		     if (keydef != NULL && result != ISC_R_SUCCESS) {
			     isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
					   NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
					   "can't use secret for key %s on "
					   "command channel %s: %s",
					   keydef->keyid, socktext,
					   isc_result_totext(result));
			     keydef = NULL; /* Prevent more error messages. */

		     } else if (result == ISC_R_SUCCESS)
			     result = omapi_auth_register(keydef->keyid,
						    OMAPI_AUTH_HMACMD5,
						    isc_buffer_base(&b),
						    isc_buffer_usedlength(&b));

		     if (keydef != NULL && result != ISC_R_SUCCESS)
			     isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
					   NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
					   "couldn't register key %s for"
					   "use with command channel %s: %s",
					   keydef->keyid, socktext,
					   isc_result_totext(result));
	}
}		     			 

static void
update_listener(ns_omapilistener_t **listenerp, dns_c_ctrl_t *control,
		dns_c_ctx_t *cctx, dns_aclconfctx_t *aclconfctx,
		char *socktext)
{
	ns_omapilistener_t *listener;
	dns_acl_t *new_acl = NULL;
	isc_result_t result;

	for (listener = ISC_LIST_HEAD(listeners); listener != NULL;
	     listener = ISC_LIST_NEXT(listener, link)) {

		if (isc_sockaddr_equal(&control->u.inet_v.addr,
				       &listener->address)) {
			/*
			 * There is already a listener for this sockaddr.
			 * Update the access list and key information.
			 *
			 * First, keep the old access list unless
			 * a new one can be made.
			 */
			result = dns_acl_fromconfig(control->
						    u.inet_v.matchlist,
						    cctx, aclconfctx,
						    listener->mctx, &new_acl);
			if (result == ISC_R_SUCCESS) {
				dns_acl_detach(&listener->acl);
				dns_acl_attach(new_acl,
					       &listener->acl);
				dns_acl_detach(&new_acl);
			} else
				/* XXXDCL say the old acl is still used? */
				isc_log_write(ns_g_lctx,
					      ISC_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_OMAPI,
					      ISC_LOG_WARNING,
					      "couldn't install new acl for "
					      "command channel %s: %s",
					      socktext,
					      isc_result_totext(result));

			/*
			 * Now update the key id list.
			 * XXXDCL the API for this seems incomplete.  For now,
			 * I just reassign the pointer and set the control
			 * keyidlist to NULL so dns_c_ctrl_delete will not
			 * free it.
			 */
			if (listener->keyids != NULL)
				dns_c_kidlist_delete(&listener->keyids);
			listener->keyids = control->keyidlist;
			control->keyidlist = NULL;

			break;
		}

	}

	*listenerp = listener;
}

static void
add_listener(isc_mem_t *mctx, ns_omapilistener_t **listenerp,
	     dns_c_ctrl_t *control, dns_c_ctx_t *cctx,
	     dns_aclconfctx_t *aclconfctx, char *socktext)
{
	ns_omapilistener_t *listener;
	dns_acl_t *new_acl = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	listener = isc_mem_get(mctx, sizeof(ns_omapilistener_t));
	if (listener == NULL)
		result = ISC_R_NOMEMORY;

	if (result == ISC_R_SUCCESS) {
		listener->mctx = mctx;
		listener->manager = NULL;
		listener->address = control->u.inet_v.addr;

		/*
		 * Make the acl.
		 */
		result = dns_acl_fromconfig(control->u.inet_v.matchlist,
					    cctx, aclconfctx, mctx, &new_acl);
	}

	if (result == ISC_R_SUCCESS) {
		dns_acl_attach(new_acl, &listener->acl);
		dns_acl_detach(&new_acl);

		/*
		 * Now update the key id list.
		 * XXXDCL the API for this seems incomplete.  For now,
		 * I just reassign the pointer and set it to NULL so
		 * dns_c_ctrl_delete will not free it.
		 */
		listener->keyids = control->keyidlist;
		control->keyidlist = NULL;

		result = ns_omapi_listen(listener);
	}

	if (result == ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_OMAPI, ISC_LOG_NOTICE,
			      "command channel listening on %s", socktext);
		*listenerp = listener;

	} else {
		if (listener != NULL)
			free_listener(listener);

		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
			      "couldn't add command channel %s: %s",
			      socktext, isc_result_totext(result));

		*listenerp = NULL;
	}

	/* XXXDCL return error results? fail hard? */
}

isc_result_t
ns_omapi_configure(isc_mem_t *mctx, dns_c_ctx_t *cctx,
		   dns_aclconfctx_t *aclconfctx)
{
	ns_omapilistener_t *listener;
	ns_omapilistenerlist_t new_listeners;
	dns_c_ctrllist_t *controls = NULL;
	dns_c_ctrl_t *control;
	dns_c_kdeflist_t *keydeflist = NULL;
	char socktext[ISC_SOCKADDR_FORMATSIZE];
	isc_result_t result;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	ISC_LIST_INIT(new_listeners);

	/*
	 * Get a pointer to the named.conf ``controls'' statement information.
	 */
	result = dns_c_ctx_getcontrols(cctx, &controls);

	LOCK(&listeners_lock);
	/*
	 * Run through the new control channel list, noting sockets that
	 * are already being listened on and moving them to the new list.
	 *			
	 * Identifying duplicates addr/port combinations is left to either
	 * the underlying config code, or to the bind attempt getting an
	 * address-in-use error.
	 */
	if (result == ISC_R_SUCCESS) {
		(void)dns_c_ctx_getkdeflist(cctx, &keydeflist);
		if (keydeflist == NULL)
			isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_OMAPI, ISC_LOG_WARNING,
				      "no key statements for use by "
				      "control channels");

		for (control = dns_c_ctrllist_head(controls);
		     control != NULL;
		     control = dns_c_ctrl_next(control)) {
			/*
			 * The parser handles BIND 8 configuration file syntax,
			 * so it allows a control_type of dns_c_unix_control,
			 * as well as an inet phrase with no keys{} clause.
			 * However, it already warned that those were
			 * unsupported, so there is no need to do so again.
			 * The keydeflist == NULL case was already warned
			 * about a few lines above.
			 */
			if (control->control_type != dns_c_inet_control ||
			    keydeflist == NULL || control->keyidlist == NULL)
				continue;

			isc_sockaddr_format(&control->u.inet_v.addr,
					    socktext, sizeof(socktext));

			isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_OMAPI, ISC_LOG_DEBUG(9),
				      "processing control channel %s",
				      socktext);

			register_keys(control, keydeflist, socktext);

			update_listener(&listener, control, cctx, aclconfctx,
					socktext);

			if (listener != NULL)
				/*
				 * Remove the listener from the old list,
				 * so it won't be shut down.
				 */
				ISC_LIST_UNLINK(listeners, listener, link);
			else
				/*
				 * This is a new listener.
				 */
				add_listener(mctx, &listener, control, cctx,
					     aclconfctx, socktext);
				
			if (listener != NULL)
				ISC_LIST_APPEND(new_listeners, listener, link);

		}
	}

	/*
	 * ns_omapi_shutdown() will stop whatever is on the global listeners
	 * list, which currently only has whatever sockaddr was in the previous
	 * configuration (if any) that does not remain in the current
	 * configuration.
	 */
	ns_omapi_shutdown(ISC_FALSE);

	/*
	 * Put all of the valid listeners on the listeners list.
	 * Anything already on listeners in the process of shutting down
	 * will be taken care of by listen_done().
	 */
	ISC_LIST_APPENDLIST(listeners, new_listeners, link);

	UNLOCK(&listeners_lock);

	return (ISC_R_SUCCESS);
}
