/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: omapiconf.c,v 1.17 2001/03/22 00:06:51 bwelling Exp $ */

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

#include <isccfg/cfg.h>

#include <dns/result.h>

#include <named/log.h>
#include <named/omapi.h>
#include <named/server.h>

typedef struct ns_omapikey ns_omapikey_t;

typedef ISC_LIST(ns_omapikey_t) ns_omapikeylist_t;

struct ns_omapikey {
	char *keyname;
	ISC_LINK(ns_omapikey_t)		link;
};

typedef struct ns_omapilistener ns_omapilistener_t;

typedef ISC_LIST(ns_omapilistener_t) ns_omapilistenerlist_t;

struct ns_omapilistener {
	/* XXXDCL magic */
	isc_mem_t *			mctx;
	omapi_object_t *		manager;
	isc_sockaddr_t			address;
	dns_acl_t *			acl;
	ns_omapikeylist_t		keyids;
	ISC_LINK(ns_omapilistener_t)	link;
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
free_omapikeylist(ns_omapikeylist_t *keylist, isc_mem_t *mctx) {
	while (!ISC_LIST_EMPTY(*keylist)) {
		ns_omapikey_t *key = ISC_LIST_HEAD(*keylist);
		ISC_LIST_UNLINK(*keylist, key, link);
		isc_mem_free(mctx, key->keyname);
		isc_mem_put(mctx, key, sizeof(*key));
	}
}

static void
free_listener(ns_omapilistener_t *listener) {
	free_omapikeylist(&listener->keyids, listener->mctx);

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
omapikeylist_find(ns_omapikeylist_t *keylist, const char *keyname) {
	ns_omapikey_t *key;

	for (key = ISC_LIST_HEAD(*keylist);
	     key != NULL;
	     key = ISC_LIST_NEXT(key, link))
	{
		if (strcasecmp(keyname, key->keyname) == 0)
			return (ISC_TRUE);
	}
	return (ISC_FALSE);
}

static isc_result_t
cfgkeylist_find(cfg_obj_t *keylist, const char *keyname, cfg_obj_t **objp) {
	cfg_listelt_t *element;
	const char *str;
	cfg_obj_t *obj;

	for (element = cfg_list_first(keylist);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		obj = cfg_listelt_value(element);
		str = cfg_obj_asstring(cfg_map_getname(obj));
		if (strcasecmp(str, keyname) == 0)
			break;
	}
	if (element == NULL)
		return (ISC_R_NOTFOUND);
	obj = cfg_listelt_value(element);
	*objp = obj;
	return (ISC_R_SUCCESS);
}

static isc_result_t
omapikeylist_fromcfg(cfg_obj_t *keylist, isc_mem_t *mctx,
		     ns_omapikeylist_t *keyids)
{
	cfg_listelt_t *element;
	char *newstr = NULL;
	const char *str;
	cfg_obj_t *obj;
	ns_omapikey_t *key = NULL;

	for (element = cfg_list_first(keylist);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		obj = cfg_listelt_value(element);
		str = cfg_obj_asstring(obj);
		newstr = isc_mem_strdup(mctx, str);
		if (newstr == NULL)
			goto cleanup;
		key = isc_mem_get(mctx, sizeof(*key));
		if (key == NULL)
			goto cleanup;
		key->keyname = newstr;
		ISC_LINK_INIT(key, link);
		ISC_LIST_APPEND(*keyids, key, link);
		key = NULL;
		newstr = NULL;
	}
	return (ISC_R_SUCCESS);

 cleanup:
	if (newstr != NULL)
		isc_mem_free(mctx, newstr);
	if (key != NULL)
		isc_mem_put(mctx, key, sizeof(*key));
	free_omapikeylist(keyids, mctx);
	return (ISC_R_NOMEMORY);
}

static isc_boolean_t
verify_key(const char *name, unsigned int algorithm, void *arg) {
	ns_omapilistener_t *listener;

	/*
	 * XXXDCL Ideally algorithm would be checked, too, but the current
	 * config API makes this moderately hard, and omapi will check it
	 * anyway.
	 */
	UNUSED(algorithm);

	listener = arg;

	return (omapikeylist_find(&listener->keyids, name));
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
register_keys(cfg_obj_t *control, cfg_obj_t *keylist, char *socktext) {
	char *keyid;
	cfg_obj_t *key;
	cfg_obj_t *keydef;
	cfg_listelt_t *element;
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
	for (element = cfg_list_first(keylist);
	     element != NULL;
	     element = cfg_list_next(element))
	{
		key = cfg_listelt_value(element);
		keyid = cfg_obj_asstring(cfg_map_getname(key));

		omapi_auth_deregister(keyid);

		/*
		 * XXXDCL confparser.y apparently allows any keyid
		 * in the list even if it has not been defined with
		 * the keys statement.
		 */
		keydef = NULL;
		result = cfgkeylist_find(keylist, keyid, &keydef);
		if (result != ISC_R_SUCCESS)
			cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
				    "couldn't find key %s for use with "
				    "command channel %s", keyid, socktext);
		else {
			cfg_obj_t *algobj = NULL;
			cfg_obj_t *secretobj = NULL;
			char *algstr = NULL;
			char *secretstr = NULL;

			(void)cfg_map_get(keydef, "algorithm", &algobj);
			(void)cfg_map_get(keydef, "secret", &secretobj);
			INSIST(algobj != NULL && secretobj != NULL);

			algstr = cfg_obj_asstring(algobj);
			secretstr = cfg_obj_asstring(secretobj);

			if (strcasecmp(algstr, "hmac-md5") != 0) {
				cfg_obj_log(control, ns_g_lctx,
					    ISC_LOG_WARNING,
					    "unsupported algorithm '%s' in "
					    "key '%s' for use with command "
					    "channel %s",
					    algstr, keyid, socktext);
				continue;
			}

			isc_buffer_init(&b, secret, sizeof(secret));
			result = isc_base64_decodestring(secretstr, &b);

			if (result != ISC_R_SUCCESS) {
				cfg_obj_log(keydef, ns_g_lctx, ISC_LOG_WARNING,
					    "secret for key '%s' on "
					    "command channel %s: %s",
					    keyid, socktext,
					    isc_result_totext(result));
				continue;
			}

			result = omapi_auth_register(keyid,
						    OMAPI_AUTH_HMACMD5,
						    isc_buffer_base(&b),
						    isc_buffer_usedlength(&b));

			if (result != ISC_R_SUCCESS)
				cfg_obj_log(keydef, ns_g_lctx, ISC_LOG_WARNING,
					   "couldn't register key '%s' for"
					   "use with command channel %s: %s",
					   keyid, socktext,
					   isc_result_totext(result));
		}
	}
}

static void
update_listener(ns_omapilistener_t **listenerp, cfg_obj_t *control,
		cfg_obj_t *config, isc_sockaddr_t *addr,
		ns_aclconfctx_t *aclconfctx, char *socktext)
{
	ns_omapilistener_t *listener;
	cfg_obj_t *allow;
	cfg_obj_t *keys;
	dns_acl_t *new_acl = NULL;
	ns_omapikeylist_t keyids;
	isc_result_t result;

	for (listener = ISC_LIST_HEAD(listeners);
	     listener != NULL;
	     listener = ISC_LIST_NEXT(listener, link))
		if (isc_sockaddr_equal(addr, &listener->address))
			break;

	if (listener == NULL) {
		*listenerp = NULL;
		return;
	}
		
	/*
	 * There is already a listener for this sockaddr.
	 * Update the access list and key information.
	 *
	 * First, keep the old access list unless a new one can be made.
	 */
	allow = cfg_tuple_get(control, "allow");
	result = ns_acl_fromconfig(allow, config, aclconfctx,
				   listener->mctx, &new_acl);
	if (result == ISC_R_SUCCESS) {
		dns_acl_detach(&listener->acl);
		dns_acl_attach(new_acl, &listener->acl);
		dns_acl_detach(&new_acl);
	} else
		/* XXXDCL say the old acl is still used? */
		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't install new acl for "
			    "command channel %s: %s",
			    socktext, isc_result_totext(result));

	keys = cfg_tuple_get(control, "keys");
	ISC_LIST_INIT(keyids);
	result = omapikeylist_fromcfg(keys, listener->mctx, &keyids);
	if (result != ISC_R_SUCCESS)
		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't install new keys for "
			    "command channel %s: %s",
			    socktext, isc_result_totext(result));
	else {
		free_omapikeylist(&listener->keyids, listener->mctx);
		listener->keyids = keyids;
	}

	*listenerp = listener;
}

static void
add_listener(isc_mem_t *mctx, ns_omapilistener_t **listenerp,
	     cfg_obj_t *control, cfg_obj_t *config, isc_sockaddr_t *addr,
	     ns_aclconfctx_t *aclconfctx, char *socktext)
{
	ns_omapilistener_t *listener;
	cfg_obj_t *allow;
	cfg_obj_t *keys;
	dns_acl_t *new_acl = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	listener = isc_mem_get(mctx, sizeof(ns_omapilistener_t));
	if (listener == NULL)
		result = ISC_R_NOMEMORY;

	if (result == ISC_R_SUCCESS) {
		listener->mctx = mctx;
		listener->manager = NULL;
		listener->address = *addr;
		ISC_LINK_INIT(listener, link);
		ISC_LIST_INIT(listener->keyids);

		/*
		 * Make the acl.
		 */
		allow = cfg_tuple_get(control, "allow");
		result = ns_acl_fromconfig(allow, config, aclconfctx, mctx,
					   &new_acl);
	}

	if (result == ISC_R_SUCCESS) {
		dns_acl_attach(new_acl, &listener->acl);
		dns_acl_detach(&new_acl);

		keys = cfg_tuple_get(control, "keys");
		result = omapikeylist_fromcfg(keys, listener->mctx,
					      &listener->keyids);
		if (result != ISC_R_SUCCESS)
			cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
				    "couldn't install new keys for "
				    "command channel %s: %s",
				    socktext, isc_result_totext(result));
	}

	if (result == ISC_R_SUCCESS)
		result = ns_omapi_listen(listener);

	if (result == ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_OMAPI, ISC_LOG_NOTICE,
			      "command channel listening on %s", socktext);
		*listenerp = listener;

	} else {
		if (listener != NULL)
			free_listener(listener);

		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't add command channel %s: %s",
			    socktext, isc_result_totext(result));

		*listenerp = NULL;
	}

	/* XXXDCL return error results? fail hard? */
}

isc_result_t
ns_omapi_configure(isc_mem_t *mctx, cfg_obj_t *config,
		   ns_aclconfctx_t *aclconfctx)
{
	ns_omapilistener_t *listener;
	ns_omapilistenerlist_t new_listeners;
	cfg_obj_t *controlslist = NULL;
	cfg_obj_t *keylist = NULL;
	cfg_listelt_t *element, *element2;
	char socktext[ISC_SOCKADDR_FORMATSIZE];

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	ISC_LIST_INIT(new_listeners);

	/*
	 * Get te list of named.conf 'controls' statements.
	 */
	(void)cfg_map_get(config, "controls", &controlslist);

	LOCK(&listeners_lock);
	/*
	 * Run through the new control channel list, noting sockets that
	 * are already being listened on and moving them to the new list.
	 *
	 * Identifying duplicates addr/port combinations is left to either
	 * the underlying config code, or to the bind attempt getting an
	 * address-in-use error.
	 */
	if (controlslist != NULL) {
		(void)cfg_map_get(config, "key", &keylist);
		if (keylist == NULL)
			cfg_obj_log(controlslist, ns_g_lctx, ISC_LOG_WARNING,
				    "no key statements for use by "
				    "control channels");

		for (element = cfg_list_first(controlslist);
		     element != NULL;
		     element = cfg_list_next(element))
		{
			cfg_obj_t *controls;
			cfg_obj_t *inetcontrols = NULL;

			controls = cfg_listelt_value(element);
			(void)cfg_map_get(controls, "inet", &inetcontrols);
			if (inetcontrols == NULL)
				continue;

			for (element2 = cfg_list_first(inetcontrols);
			     element2 != NULL;
			     element2 = cfg_list_next(element2))
			{
				cfg_obj_t *control;
				cfg_obj_t *obj;
				isc_sockaddr_t *addr;

				/*
				 * The parser handles BIND 8 configuration file
				 * syntax, so it allows unix phrases as well
				 * inet phrases with no keys{} clause.
				 *
				 * "unix" phrases have been reported as
				 * unsupported by the parser.
				 *
				 * The keylist == NULL case was already warned
				 * about a few lines above.
				 */
				control = cfg_listelt_value(element2);

				obj = cfg_tuple_get(control, "address");
				addr = cfg_obj_assockaddr(obj);
				if (isc_sockaddr_getport(addr) == 0)
					isc_sockaddr_setport(addr,
							     NS_OMAPI_PORT);

				isc_sockaddr_format(addr, socktext,
						    sizeof(socktext));

				obj = cfg_tuple_get(control, "keys");

				if (cfg_obj_isvoid(obj)) {
					cfg_obj_log(obj, ns_g_lctx,
						    ISC_LOG_ERROR,
						    "no keys clause in "
						    "control channel %s",
						    socktext);
					continue;
				}

				if (cfg_list_first(obj) == NULL) {
					cfg_obj_log(obj, ns_g_lctx,
						    ISC_LOG_ERROR,
						    "no keys specified in "
						    "control channel %s",
						    socktext);
					continue;
				}

				if (keylist == NULL)
					continue;

				isc_log_write(ns_g_lctx,
					      ISC_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_OMAPI,
					      ISC_LOG_DEBUG(9),
					      "processing control channel %s",
					      socktext);

				register_keys(control, keylist, socktext);

				update_listener(&listener, control, config,
						addr, aclconfctx, socktext);

				if (listener != NULL)
					/*
					 * Remove the listener from the old
					 * list, so it won't be shut down.
					 */
					ISC_LIST_UNLINK(listeners, listener,
							link);
				else
					/*
					 * This is a new listener.
					 */
					add_listener(mctx, &listener, control,
						     config, addr, aclconfctx,
						     socktext);
	
				if (listener != NULL)
					ISC_LIST_APPEND(new_listeners,
							listener, link);
			}
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
