/*
 * Copyright (C) 2001  Internet Software Consortium.
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

/* $Id: controlconf.c,v 1.3 2001/04/10 21:50:41 bwelling Exp $ */

#include <config.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/event.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/stdtime.h>
#include <isc/string.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <isccfg/cfg.h>

#include <isccc/alist.h>
#include <isccc/cc.h>
#include <isccc/ccmsg.h>
#include <isccc/events.h>
#include <isccc/result.h>
#include <isccc/sexpr.h>
#include <isccc/util.h>

#include <dns/result.h>

#include <named/control.h>
#include <named/log.h>
#include <named/server.h>

/*
 * Note: Listeners and connections are not locked.  All event handlers are
 * executed by the server task, and all callers of exported routines must
 * be running under the server task.
 */

typedef struct controlkey controlkey_t;
typedef ISC_LIST(controlkey_t) controlkeylist_t;

typedef struct controlconnection controlconnection_t;
typedef ISC_LIST(controlconnection_t) controlconnectionlist_t;

typedef struct controllistener controllistener_t;
typedef ISC_LIST(controllistener_t) controllistenerlist_t;

struct controlkey {
	char *				keyname;
	isc_region_t			secret;
	ISC_LINK(controlkey_t)		link;
};

struct controlconnection {
	isc_socket_t *			sock;
	isccc_ccmsg_t			ccmsg;
	isc_boolean_t			ccmsg_valid;
	isc_boolean_t			sending;
	isc_timer_t *			timer;
	unsigned char			buffer[2048];
	controllistener_t *		listener;
	ISC_LINK(controlconnection_t)	link;
};

struct controllistener {
	isc_mem_t *			mctx;
	isc_task_t *			task;
	isc_sockaddr_t			address;
	isc_socket_t *			sock;
	dns_acl_t *			acl;
	isc_boolean_t			listening;
	isc_boolean_t			exiting;
	controlkeylist_t		keys;
	controlconnectionlist_t		connections;
	ISC_LINK(controllistener_t)	link;
};

static controllistenerlist_t listeners;
static isc_mutex_t listeners_lock;
static isc_once_t once = ISC_ONCE_INIT;

static void control_newconn(isc_task_t *task, isc_event_t *event);
static void control_recvmessage(isc_task_t *task, isc_event_t *event);

static void
initialize_mutex(void) {
	RUNTIME_CHECK(isc_mutex_init(&listeners_lock) == ISC_R_SUCCESS);
}

static void
free_controlkey(controlkey_t *key, isc_mem_t *mctx) {
	if (key->keyname != NULL)
		isc_mem_free(mctx, key->keyname);
	if (key->secret.base != NULL)
		isc_mem_put(mctx, key->secret.base, key->secret.length);
	isc_mem_put(mctx, key, sizeof(*key));
}

static void
free_controlkeylist(controlkeylist_t *keylist, isc_mem_t *mctx) {
	while (!ISC_LIST_EMPTY(*keylist)) {
		controlkey_t *key = ISC_LIST_HEAD(*keylist);
		ISC_LIST_UNLINK(*keylist, key, link);
		free_controlkey(key, mctx);
	}
}

static void
free_listener(controllistener_t *listener) {
	INSIST(listener->exiting);
	INSIST(!listener->listening);
	INSIST(ISC_LIST_EMPTY(listener->connections));

	if (listener->sock != NULL)
		isc_socket_detach(&listener->sock);

	free_controlkeylist(&listener->keys, listener->mctx);

	if (listener->acl != NULL)
		dns_acl_detach(&listener->acl);

	isc_mem_put(listener->mctx, listener, sizeof(*listener));
}

static void
maybe_free_listener(controllistener_t *listener) {
	if (listener->exiting &&
	    !listener->listening &&
	    ISC_LIST_EMPTY(listener->connections))
		free_listener(listener);
}

static void
maybe_free_connection(controlconnection_t *conn) {
	controllistener_t *listener = conn->listener;

	if (conn->timer != NULL)
		isc_timer_detach(&conn->timer);

	if (conn->ccmsg_valid) {
		isccc_ccmsg_cancelread(&conn->ccmsg);
		return;
	}

	if (conn->sending) {
		isc_socket_cancel(conn->sock, listener->task,
				  ISC_SOCKCANCEL_SEND);
		return;
	}

	ISC_LIST_UNLINK(listener->connections, conn, link);
	isc_mem_put(listener->mctx, conn, sizeof(*conn));
}

static void
shutdown_listener(controllistener_t *listener) {
	isc_boolean_t destroy = ISC_TRUE;

	listener->exiting = ISC_TRUE;

	if (!ISC_LIST_EMPTY(listener->connections)) {
		controlconnection_t *conn;
		for (conn = ISC_LIST_HEAD(listener->connections);
		     conn != NULL;
		     conn = ISC_LIST_NEXT(conn, link))
			maybe_free_connection(conn);
		destroy = ISC_FALSE;
	}

	if (listener->sock != NULL) {
		isc_socket_cancel(listener->sock, listener->task,
				  ISC_SOCKCANCEL_ACCEPT);
		destroy = ISC_FALSE;
	}

	if (destroy)
		free_listener(listener);
}

static isc_boolean_t
address_ok(isc_sockaddr_t *sockaddr, dns_acl_t *acl) {
	isc_netaddr_t netaddr;
	isc_result_t result;
	int match;

	isc_netaddr_fromsockaddr(&netaddr, sockaddr);

	result = dns_acl_match(&netaddr, NULL, acl,
			       &ns_g_server->aclenv, &match, NULL);

	if (result != ISC_R_SUCCESS || match <= 0)
		return (ISC_FALSE);
	else
		return (ISC_TRUE);
}

static isc_result_t
control_accept(controllistener_t *listener) {
	isc_result_t result;
	result = isc_socket_accept(listener->sock,
				   listener->task,
				   control_newconn, listener);
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_socket_accept() failed: %s",
				 isc_result_totext(result));
	else
		listener->listening = ISC_TRUE;
	return (result);
}

static isc_result_t
control_listen(controllistener_t *listener) {
	isc_result_t result;

	result = isc_socket_listen(listener->sock, 0);
	if (result != ISC_R_SUCCESS)
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_socket_listen() failed: %s",
				 isc_result_totext(result));
	return (result);
}

static void
control_next(controllistener_t *listener) {
	(void)control_accept(listener);
}

static void
control_senddone(isc_task_t *task, isc_event_t *event) {
	isc_socketevent_t *sevent = (isc_socketevent_t *) event;
	controlconnection_t *conn = event->ev_arg;
	controllistener_t *listener = conn->listener;
	isc_socket_t *sock = (isc_socket_t *)sevent->ev_sender;
	isc_result_t result;

	REQUIRE(conn->sending);

	UNUSED(task);

	conn->sending = ISC_FALSE;

	if (sevent->result != ISC_R_SUCCESS &&
	    sevent->result != ISC_R_CANCELED)
	{
		char socktext[ISC_SOCKADDR_FORMATSIZE];
		isc_sockaddr_t peeraddr;

		(void)isc_socket_getpeername(sock, &peeraddr);
		isc_sockaddr_format(&peeraddr, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "error sending command response to %s: %s",
			      socktext, isc_result_totext(sevent->result));
	}
	isc_event_free(&event);

	result = isccc_ccmsg_readmessage(&conn->ccmsg, listener->task,
					 control_recvmessage, conn);
	if (result != ISC_R_SUCCESS) {
		isc_socket_detach(&conn->sock);
		maybe_free_connection(conn);
		maybe_free_listener(listener);
	}
}

static inline void
log_invalid(isccc_ccmsg_t *ccmsg, isc_result_t result) {
	char socktext[ISC_SOCKADDR_FORMATSIZE];
	isc_sockaddr_t peeraddr;

	(void)isc_socket_getpeername(ccmsg->sock, &peeraddr);
	isc_sockaddr_format(&peeraddr, socktext, sizeof(socktext));
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_CONTROL, ISC_LOG_ERROR,
		      "invalid command from %s: %s",
		      socktext, isc_result_totext(result));
}

static void
control_recvmessage(isc_task_t *task, isc_event_t *event) {
	controlconnection_t *conn;
	controllistener_t *listener;
	controlkey_t *key;
	isccc_sexpr_t *request = NULL;
	isccc_sexpr_t *response = NULL;
	isccc_region_t ccregion;
	isccc_region_t secret;
	isc_stdtime_t now;
	isc_buffer_t b;
	isc_region_t r;
	isc_uint32_t len;
	isc_result_t result;
	isc_result_t eresult;

	REQUIRE(event->ev_type == ISCCC_EVENT_CCMSG);

	conn = event->ev_arg;
	listener = conn->listener;
	key = ISC_LIST_HEAD(listener->keys);

	if (conn->ccmsg.result != ISC_R_SUCCESS) {
		if (conn->ccmsg.result != ISC_R_CANCELED &&
		    conn->ccmsg.result != ISC_R_EOF)
			log_invalid(&conn->ccmsg, conn->ccmsg.result);
		goto cleanup;
	}

	ccregion.rstart = isc_buffer_base(&conn->ccmsg.buffer);
	ccregion.rend = isc_buffer_used(&conn->ccmsg.buffer);
	request = NULL;
	secret.rstart = key->secret.base;
	secret.rend = key->secret.base + key->secret.length;
	result = isccc_cc_fromwire(&ccregion, &request, &secret);
	if (result != ISC_R_SUCCESS) {
		log_invalid(&conn->ccmsg, result);
		goto cleanup;
	}

	/* We shouldn't be getting a reply. */
	if (isccc_cc_isreply(request)) {
		log_invalid(&conn->ccmsg, ISC_R_FAILURE);
		goto cleanup;
	}

	eresult = ns_control_docommand(request);

	isc_stdtime_get(&now);
	result = isccc_cc_createresponse(request, now, now + 60, &response);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	if (eresult != ISC_R_SUCCESS) {
		isccc_sexpr_t *data;

		data = isccc_alist_lookup(response, "_data");
		if (data != NULL) {
			const char *estr = isc_result_totext(eresult);
			if (isccc_cc_definestring(data, "err", estr) == NULL)
				goto cleanup;
		}
	}

	ccregion.rstart = conn->buffer + 4;
	ccregion.rend = conn->buffer + sizeof(conn->buffer);
	result = isccc_cc_towire(response, &ccregion, &secret);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	isc_buffer_init(&b, conn->buffer, 4);
	len = sizeof(conn->buffer) - REGION_SIZE(ccregion);
	isc_buffer_putuint32(&b, len - 4);
	r.base = conn->buffer;
	r.length = len;

	result = isc_socket_send(conn->sock, &r, task, control_senddone, conn);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	conn->sending = ISC_TRUE;

	if (request != NULL)
		isccc_sexpr_free(&request);
	if (request != NULL)
		isccc_sexpr_free(&response);
	return;

 cleanup:
	isc_socket_detach(&conn->sock);
	isccc_ccmsg_invalidate(&conn->ccmsg);
	conn->ccmsg_valid = ISC_FALSE;
	maybe_free_connection(conn);
	maybe_free_listener(listener);
	if (request != NULL)
		isccc_sexpr_free(&request);
	if (request != NULL)
		isccc_sexpr_free(&response);
}

static void
control_timeout(isc_task_t *task, isc_event_t *event) {
	controlconnection_t *conn = event->ev_arg;

	UNUSED(task);

	isc_timer_detach(&conn->timer);
	maybe_free_connection(conn);

	isc_event_free(&event);
}

static isc_result_t
newconnection(controllistener_t *listener, isc_socket_t *sock) {
	controlconnection_t *conn;
	isc_interval_t interval;
	isc_result_t result;

	conn = isc_mem_get(listener->mctx, sizeof(*conn));
	if (conn == NULL)
		return (ISC_R_NOMEMORY);
	
	conn->sock = sock;
	isccc_ccmsg_init(listener->mctx, sock, &conn->ccmsg);
	conn->ccmsg_valid = ISC_TRUE;
	conn->sending = ISC_FALSE;
	conn->timer = NULL;
	isc_interval_set(&interval, 60, 0);
	result = isc_timer_create(ns_g_timermgr, isc_timertype_once,
				  NULL, &interval, listener->task,
				  control_timeout, conn, &conn->timer);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	conn->listener = listener;
	ISC_LINK_INIT(conn, link);

	result = isccc_ccmsg_readmessage(&conn->ccmsg, listener->task,
					 control_recvmessage, conn);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	isccc_ccmsg_setmaxsize(&conn->ccmsg, 2048);

	ISC_LIST_APPEND(listener->connections, conn, link);
	return (ISC_R_SUCCESS);

 cleanup:
	isccc_ccmsg_invalidate(&conn->ccmsg);
	if (conn->timer != NULL)
		isc_timer_detach(&conn->timer);
	isc_mem_put(listener->mctx, conn, sizeof(*conn));
	return (result);
}

static void
control_newconn(isc_task_t *task, isc_event_t *event) {
	isc_socket_newconnev_t *nevent = (isc_socket_newconnev_t *)event;
	controllistener_t *listener = event->ev_arg;
	isc_socket_t *sock;
	isc_sockaddr_t peeraddr;
	isc_result_t result;

	UNUSED(task);

	if (nevent->result != ISC_R_SUCCESS) {
		if (nevent->result == ISC_R_CANCELED) {
			isc_socket_detach(&listener->sock);
			listener->listening = ISC_FALSE;
			shutdown_listener(listener);
			goto cleanup;
		}
		goto restart;
	}

	sock = nevent->newsocket;
	(void)isc_socket_getpeername(sock, &peeraddr);
	if (!address_ok(&peeraddr, listener->acl)) {
		char socktext[ISC_SOCKADDR_FORMATSIZE];
		isc_sockaddr_format(&peeraddr, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "rejected command channel message from %s",
			      socktext);
		goto restart;
	}

	result = newconnection(listener, sock);
	if (result != ISC_R_SUCCESS) {
		char socktext[ISC_SOCKADDR_FORMATSIZE];
		isc_sockaddr_format(&peeraddr, socktext, sizeof(socktext));
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "dropped command channel from %s: %s",
			      socktext, isc_result_totext(result));
		goto restart;
	}

 restart:
	control_next(listener);
 cleanup:
	isc_event_free(&event);
}

void
ns_control_shutdown(isc_boolean_t exiting) {
	controllistener_t *listener;
	controllistener_t *next;

	RUNTIME_CHECK(isc_once_do(&once, initialize_mutex) == ISC_R_SUCCESS);

	if (exiting) {
		/*
		 * When not exiting, this function is called from
		 * ns_control_configure(), which already holds the lock.
		 */
		LOCK(&listeners_lock);
	}


	for (listener = ISC_LIST_HEAD(listeners);
	     listener != NULL;
	     listener = next)
	{
		/*
		 * This is asynchronous.  As listeners shut down, they will
		 * call their callbacks.
		 */
		next = ISC_LIST_NEXT(listener, link);
		ISC_LIST_UNLINK(listeners, listener, link);
		shutdown_listener(listener);
	}

	if (exiting)
		UNLOCK(&listeners_lock);
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
controlkeylist_fromcfg(cfg_obj_t *keylist, isc_mem_t *mctx,
		     controlkeylist_t *keyids)
{
	cfg_listelt_t *element;
	char *newstr = NULL;
	const char *str;
	cfg_obj_t *obj;
	controlkey_t *key = NULL;

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
		key->secret.base = NULL;
		key->secret.length = 0;
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
	free_controlkeylist(keyids, mctx);
	return (ISC_R_NOMEMORY);
}

static void
register_keys(cfg_obj_t *control, cfg_obj_t *keylist,
	      controlkeylist_t *keyids, isc_mem_t *mctx, char *socktext)
{
	controlkey_t *keyid, *next;
	cfg_obj_t *keydef;
	char secret[1024];
	isc_buffer_t b;
	isc_result_t result;

	/*
	 * Find the keys corresponding to the keyids used by this listener.
	 */
	for (keyid = ISC_LIST_HEAD(*keyids); keyid != NULL; keyid = next) {
		next = ISC_LIST_NEXT(keyid, link);

		result = cfgkeylist_find(keylist, keyid->keyname, &keydef);
		if (result != ISC_R_SUCCESS) {
			cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
				    "couldn't find key %s for use with "
				    "command channel %s",
				    keyid->keyname, socktext);
			ISC_LIST_UNLINK(*keyids, keyid, link);
			free_controlkey(keyid, mctx);
		} else {
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
					    algstr, keyid->keyname, socktext);
				ISC_LIST_UNLINK(*keyids, keyid, link);
				free_controlkey(keyid, mctx);
				continue;
			}

			isc_buffer_init(&b, secret, sizeof(secret));
			result = isc_base64_decodestring(secretstr, &b);

			if (result != ISC_R_SUCCESS) {
				cfg_obj_log(keydef, ns_g_lctx, ISC_LOG_WARNING,
					    "secret for key '%s' on "
					    "command channel %s: %s",
					    keyid->keyname, socktext,
					    isc_result_totext(result));
				ISC_LIST_UNLINK(*keyids, keyid, link);
				free_controlkey(keyid, mctx);
				continue;
			}

			keyid->secret.length = isc_buffer_usedlength(&b);
			keyid->secret.base = isc_mem_get(mctx,
							 keyid->secret.length);
			if (keyid->secret.base == NULL) {
				cfg_obj_log(keydef, ns_g_lctx, ISC_LOG_WARNING,
					   "couldn't register key '%s': "
					   "out of memory", keyid->keyname);
				ISC_LIST_UNLINK(*keyids, keyid, link);
				free_controlkey(keyid, mctx);
				break;
			}
			memcpy(keyid->secret.base, isc_buffer_base(&b),
			       keyid->secret.length);
		}
	}
}

static void
update_listener(controllistener_t **listenerp, cfg_obj_t *control,
		cfg_obj_t *config, isc_sockaddr_t *addr,
		ns_aclconfctx_t *aclconfctx, char *socktext)
{
	controllistener_t *listener;
	cfg_obj_t *allow;
	cfg_obj_t *keylist;
	dns_acl_t *new_acl = NULL;
	controlkeylist_t keys;
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

	keylist = cfg_tuple_get(control, "keys");
	ISC_LIST_INIT(keys);
	result = controlkeylist_fromcfg(keylist, listener->mctx, &keys);
	if (result != ISC_R_SUCCESS)
		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't install new keys for "
			    "command channel %s: %s",
			    socktext, isc_result_totext(result));
	else {
		free_controlkeylist(&listener->keys, listener->mctx);
		listener->keys = keys;
	}

	*listenerp = listener;
}

static void
add_listener(isc_mem_t *mctx, controllistener_t **listenerp,
	     cfg_obj_t *control, cfg_obj_t *config, isc_sockaddr_t *addr,
	     ns_aclconfctx_t *aclconfctx, char *socktext)
{
	controllistener_t *listener;
	cfg_obj_t *allow;
	cfg_obj_t *keys;
	dns_acl_t *new_acl = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	listener = isc_mem_get(mctx, sizeof(*listener));
	if (listener == NULL)
		result = ISC_R_NOMEMORY;

	if (result == ISC_R_SUCCESS) {
		listener->mctx = mctx;
		listener->task = ns_g_server->task;
		listener->address = *addr;
		listener->sock = NULL;
		listener->listening = ISC_FALSE;
		listener->exiting = ISC_FALSE;
		listener->acl = NULL;
		ISC_LINK_INIT(listener, link);
		ISC_LIST_INIT(listener->keys);
		ISC_LIST_INIT(listener->connections);

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
		result = controlkeylist_fromcfg(keys, listener->mctx,
					      &listener->keys);
		if (result != ISC_R_SUCCESS)
			cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
				    "couldn't install new keys for "
				    "command channel %s: %s",
				    socktext, isc_result_totext(result));
	}

	if (result == ISC_R_SUCCESS) {
		int pf = isc_sockaddr_pf(&listener->address);
		if ((pf == AF_INET && isc_net_probeipv4() != ISC_R_SUCCESS) ||
		    (pf == AF_INET6 && isc_net_probeipv6() != ISC_R_SUCCESS))
			result = ISC_R_FAMILYNOSUPPORT;
	}

	if (result == ISC_R_SUCCESS)
		result = isc_socket_create(ns_g_socketmgr,
					   isc_sockaddr_pf(&listener->address),
					   isc_sockettype_tcp,
					   &listener->sock);

	if (result == ISC_R_SUCCESS)
		result = isc_socket_bind(listener->sock,
					 &listener->address);

	if (result == ISC_R_SUCCESS)
		result = control_listen(listener);

	if (result == ISC_R_SUCCESS)
		result = control_accept(listener);

	if (result == ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, ISC_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_NOTICE,
			      "command channel listening on %s", socktext);
		*listenerp = listener;

	} else {
		if (listener != NULL) {
			listener->exiting = ISC_TRUE;
			free_listener(listener);
		}

		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't add command channel %s: %s",
			    socktext, isc_result_totext(result));

		*listenerp = NULL;
	}

	/* XXXDCL return error results? fail hard? */
}

isc_result_t
ns_control_configure(isc_mem_t *mctx, cfg_obj_t *config,
		     ns_aclconfctx_t *aclconfctx)
{
	controllistener_t *listener;
	controllistenerlist_t new_listeners;
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
							     NS_CONTROL_PORT);

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
					      NS_LOGMODULE_CONTROL,
					      ISC_LOG_DEBUG(9),
					      "processing control channel %s",
					      socktext);

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
	
				if (listener != NULL) {
					register_keys(control, keylist,
						      &listener->keys,
						      listener->mctx,
						      socktext);

					ISC_LIST_APPEND(new_listeners,
							listener, link);
				}
			}
		}
	}

	/*
	 * ns_control_shutdown() will stop whatever is on the global listeners
	 * list, which currently only has whatever sockaddr was in the previous
	 * configuration (if any) that does not remain in the current
	 * configuration.
	 */
	ns_control_shutdown(ISC_FALSE);

	/*
	 * Put all of the valid listeners on the listeners list.
	 * Anything already on listeners in the process of shutting down
	 * will be taken care of by listen_done().
	 */
	ISC_LIST_APPENDLIST(listeners, new_listeners, link);

	UNLOCK(&listeners_lock);

	return (ISC_R_SUCCESS);
}
