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

/* $Id: controlconf.c,v 1.16 2001/07/05 18:39:14 bwelling Exp $ */

#include <config.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/event.h>
#include <isc/file.h>
#include <isc/fsaccess.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/stdio.h>
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

#include <dns/keyvalues.h>
#include <dns/result.h>

#include <dst/dst.h>

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
	ns_controls_t *			controls;
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

static struct {
	char		name[64];
	char		secret[192];
	cfg_parser_t   *parser;
	cfg_obj_t      *config;
	isc_sockaddr_t  address; /* Last channel that needed automagic. */
} automagic_key;

#define NS_AUTOKEY_BITS 128
#define NS_AUTOKEY_NAME "control_autokey"

struct ns_controls {
	ns_server_t			*server;
	controllistenerlist_t 		listeners;
};

static void control_newconn(isc_task_t *task, isc_event_t *event);
static void control_recvmessage(isc_task_t *task, isc_event_t *event);

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

	if (!listener->exiting) {
		char socktext[ISC_SOCKADDR_FORMATSIZE];

		isc_sockaddr_format(&listener->address, socktext,
				    sizeof(socktext));
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_NOTICE,
			      "stopping command channel on %s", socktext);
		listener->exiting = ISC_TRUE;
	}

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
	isc_buffer_t text;
	char textarray[1024];
	isc_result_t result;
	isc_result_t eresult;

	REQUIRE(event->ev_type == ISCCC_EVENT_CCMSG);

	conn = event->ev_arg;
	listener = conn->listener;
	secret.rstart = NULL;

	if (conn->ccmsg.result != ISC_R_SUCCESS) {
		if (conn->ccmsg.result != ISC_R_CANCELED &&
		    conn->ccmsg.result != ISC_R_EOF)
			log_invalid(&conn->ccmsg, conn->ccmsg.result);
		goto cleanup;
	}

	request = NULL;
	INSIST(!ISC_LIST_EMPTY(listener->keys));

	for (key = ISC_LIST_HEAD(listener->keys);
	     key != NULL;
	     key = ISC_LIST_NEXT(key, link))
	{
		ccregion.rstart = isc_buffer_base(&conn->ccmsg.buffer);
		ccregion.rend = isc_buffer_used(&conn->ccmsg.buffer);
		secret.rstart = isc_mem_get(listener->mctx, key->secret.length);
		if (secret.rstart == NULL)
			goto cleanup;
		memcpy(secret.rstart, key->secret.base, key->secret.length);
		secret.rend = secret.rstart + key->secret.length;
		result = isccc_cc_fromwire(&ccregion, &request, &secret);
		if (result == ISC_R_SUCCESS)
			break;
		else if (result == ISCCC_R_BADAUTH) {
			/*
			 * For some reason, request is non-NULL when
			 * isccc_cc_fromwire returns ISCCC_R_BADAUTH.
			 */
			if (request != NULL)
				isccc_sexpr_free(&request);
			isc_mem_put(listener->mctx, secret.rstart,
				    REGION_SIZE(secret));
		} else {
			log_invalid(&conn->ccmsg, result);
			goto cleanup;
		}
	}

	if (key == NULL) {
		log_invalid(&conn->ccmsg, ISCCC_R_BADAUTH);
		goto cleanup;
	}

	/* We shouldn't be getting a reply. */
	if (isccc_cc_isreply(request)) {
		log_invalid(&conn->ccmsg, ISC_R_FAILURE);
		goto cleanup;
	}

	isc_buffer_init(&text, textarray, sizeof(textarray));
	eresult = ns_control_docommand(request, &text);

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

	if (isc_buffer_usedlength(&text) > 0) {
		isccc_sexpr_t *data;

		data = isccc_alist_lookup(response, "_data");
		if (data != NULL) {
			char *str = (char *)isc_buffer_base(&text);
			if (isccc_cc_definestring(data, "text", str) == NULL)
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

	if (secret.rstart != NULL)
		isc_mem_put(listener->mctx, secret.rstart,
			    REGION_SIZE(secret));
	if (request != NULL)
		isccc_sexpr_free(&request);
	if (response != NULL)
		isccc_sexpr_free(&response);
	return;

 cleanup:
	if (secret.rstart != NULL)
		isc_mem_put(listener->mctx, secret.rstart,
			    REGION_SIZE(secret));
	isc_socket_detach(&conn->sock);
	isccc_ccmsg_invalidate(&conn->ccmsg);
	conn->ccmsg_valid = ISC_FALSE;
	maybe_free_connection(conn);
	maybe_free_listener(listener);
	if (request != NULL)
		isccc_sexpr_free(&request);
	if (response != NULL)
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
ns_controls_shutdown(ns_controls_t *controls) {
	controllistener_t *listener;
	controllistener_t *next;

	for (listener = ISC_LIST_HEAD(controls->listeners);
	     listener != NULL;
	     listener = next)
	{
		/*
		 * This is asynchronous.  As listeners shut down, they will
		 * call their callbacks.
		 */
		next = ISC_LIST_NEXT(listener, link);
		ISC_LIST_UNLINK(controls->listeners, listener, link);
		shutdown_listener(listener);
	}
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
				    "couldn't find key '%s' for use with "
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

static isc_result_t
make_automagic_key(isc_mem_t *mctx) {
	unsigned char key_rawsecret[32];
	unsigned char key_txtsecret[32];
	isc_buffer_t key_rawbuffer;
	isc_buffer_t key_txtbuffer;
	isc_region_t key_rawregion;
	isc_uint32_t key_id;
	isc_result_t result;
	dst_key_t *key = NULL;

	/*
	 * First generate a secret.  The fourth parameter non-zero means
	 * that pseudorandom data is ok; good entropy is not required.
	 */
	result = dst_key_generate(dns_rootname, DST_ALG_HMACMD5,
				  NS_AUTOKEY_BITS, 1, 0, DNS_KEYPROTO_ANY,
				  dns_rdataclass_in, mctx, &key);

	if (result == ISC_R_SUCCESS) {
		isc_buffer_init(&key_rawbuffer, &key_rawsecret,
				sizeof(key_rawsecret));
		result = dst_key_tobuffer(key, &key_rawbuffer);
	}

	if (result == ISC_R_SUCCESS) {
		isc_buffer_init(&key_txtbuffer, &key_txtsecret,
				sizeof(key_txtsecret));
		isc_buffer_usedregion(&key_rawbuffer, &key_rawregion);
		result = isc_base64_totext(&key_rawregion, -1, "",
					   &key_txtbuffer);
	}

	if (result == ISC_R_SUCCESS) {
		unsigned int len = isc_buffer_usedlength(&key_txtbuffer);

		INSIST(len < sizeof(automagic_key.secret));

		memcpy(automagic_key.secret, isc_buffer_base(&key_txtbuffer),
		       len);
		automagic_key.secret[len] = '\0';

		/*
		 * Make a random name for the key and generate the config
		 * file statement for it.
		 */
		isc_random_get(&key_id);
		len = snprintf(automagic_key.name, sizeof(automagic_key.name),
			       NS_AUTOKEY_NAME ".%u", key_id);
		INSIST(len < sizeof(automagic_key.name));
	}

	if (key != NULL)
		dst_key_free(&key);

	if (result != ISC_R_SUCCESS)
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "could not generate control channel key: %s",
			      isc_result_totext(result));

	return (result);
}

static void
format_automagic_keycfg(isc_buffer_t *conf) {
	unsigned int len;

	len = snprintf(isc_buffer_base(conf), isc_buffer_length(conf),
		       "key \"%s\" {\n"
				"\talgorithm hmac-md5;\n"
				"\tsecret \"%s\";\n"
		       "};\n",
		       automagic_key.name, automagic_key.secret);

	INSIST(len < isc_buffer_length(conf));

	isc_buffer_add(conf, len);
}

static isc_result_t
parse_automagic_key(isc_mem_t *mctx) {
	unsigned int len;
	char cfg_data[512];
	isc_buffer_t cfg_buffer;
	isc_result_t result = ISC_R_SUCCESS;
	cfg_obj_t *cfg = NULL;
	cfg_parser_t *parser = NULL;

	if (automagic_key.name[0] == '\0')
		result = make_automagic_key(mctx);

	if (result == ISC_R_SUCCESS) {
		/*
		 * Fake up a configuration with a dummy inet control
		 * to grab the keylist tuple.
		 */
		isc_buffer_init(&cfg_buffer, cfg_data, sizeof(cfg_data));
		format_automagic_keycfg(&cfg_buffer);
		len = snprintf(isc_buffer_used(&cfg_buffer),
			       isc_buffer_availablelength(&cfg_buffer),
			       "controls { inet 127.0.0.1 allow { localhost; }"
			       "			  keys { %s; }; };",
			       automagic_key.name);
		INSIST(len < isc_buffer_availablelength(&cfg_buffer));
		isc_buffer_add(&cfg_buffer, len);

		result = cfg_parser_create(mctx, ns_g_lctx, &parser);
	}

	if (result == ISC_R_SUCCESS)
		result = cfg_parse_buffer(parser, &cfg_buffer,
					  &cfg_type_namedconf, &cfg);

	if (result == ISC_R_SUCCESS) {
		automagic_key.parser = parser;
		automagic_key.config = cfg;
	} else {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_CONTROL, ISC_LOG_WARNING,
			      "could not parse autogenerated "
			      "control channel key: %s",
			      isc_result_totext(result));

		if (parser != NULL)
			cfg_parser_destroy(&parser);
	}

	return (result);
}

static void
finalize_automagic_key(void) {
	unsigned int fsaccess;
	int i;
	FILE *fp;
	isc_result_t result;

	(void)isc_file_remove(ns_g_autorndckeyfile);

	if (automagic_key.parser != NULL) {
		/*
		 * An automagic key was parsed, so some channel needed it.
		 * Try to write the rndc.conf file.
		 */
		char cfg_data[512];
		char nettext[ISC_NETADDR_FORMATSIZE];
		isc_buffer_t cfg_buffer;
		isc_netaddr_t netaddr;


		result = isc_stdio_open(ns_g_autorndckeyfile, "w", &fp);

		if (result == ISC_R_SUCCESS) {
			fsaccess = 0;
			isc_fsaccess_add(ISC_FSACCESS_OWNER, ISC_FSACCESS_READ,
					 &fsaccess);
			result = isc_fsaccess_set(ns_g_autorndckeyfile,
						  fsaccess);

			if (result != ISC_R_SUCCESS) {
				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_CONTROL,
					      ISC_LOG_WARNING,
					      "could not set owner-only "
					      "access on %s: %s: "
					      "server control key might be "
					      "exposed to local users",
					      ns_g_autorndckeyfile,
					      isc_result_totext(result));
			}

			isc_buffer_init(&cfg_buffer, cfg_data,
					sizeof(cfg_data));
			format_automagic_keycfg(&cfg_buffer);

			isc_netaddr_fromsockaddr(&netaddr,
						 &automagic_key.address);
			isc_netaddr_format(&netaddr, nettext, sizeof(nettext));

			i = fputs(isc_buffer_base(&cfg_buffer), fp);

			if (i != EOF)
				i = fprintf(fp, "options {\n"
					    "\tdefault-server %s;\n"
					    "\tdefault-port %hu;\n"
					    "\tdefault-key \"%s\";\n"
					    "};\n",
					    nettext,
					    isc_sockaddr_getport(
						       &automagic_key.address),
					    automagic_key.name);

			if (i == EOF)
				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_CONTROL,
					      ISC_LOG_WARNING,
					      "could not write %s",
					      ns_g_autorndckeyfile);

			result = isc_stdio_close(fp);
			if (result != ISC_R_SUCCESS)
				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_CONTROL,
					      ISC_LOG_WARNING,
					      "error closing %s: %s",
					      ns_g_autorndckeyfile,
					      isc_result_totext(result));
		}

		cfg_obj_destroy(automagic_key.parser, &automagic_key.config);
		cfg_parser_destroy(&automagic_key.parser);
	}
}
			
static void
get_key_info(isc_mem_t *mctx, cfg_obj_t *config, cfg_obj_t *control,
	     cfg_obj_t **global_keylistp, cfg_obj_t **control_keylistp,
	     isc_boolean_t *explicit_key)
{
	cfg_obj_t *control_keylist = NULL;
	cfg_obj_t *global_keylist = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(global_keylistp != NULL && *global_keylistp == NULL);
	REQUIRE(control_keylistp != NULL && *control_keylistp == NULL);

	control_keylist = cfg_tuple_get(control, "keys");

	if (cfg_obj_isvoid(control_keylist) ||
	    cfg_list_first(control_keylist) == NULL) {
		cfg_obj_t *controls = NULL;
		cfg_obj_t *inet = NULL;

		if (automagic_key.parser == NULL)
			result = parse_automagic_key(mctx);

		if (result == ISC_R_SUCCESS) {
			config = automagic_key.config;

			/*
			 * All of these should succeed.
			 */
			(void)cfg_map_get(config, "key", &global_keylist);
			INSIST(global_keylist != NULL);

			(void)cfg_map_get(config, "controls", &controls);
			INSIST(controls != NULL);
			(void)cfg_map_get(cfg_listelt_value
					  (cfg_list_first(controls)),
					  "inet", &inet);
			INSIST(inet != NULL);
			control_keylist =
				cfg_tuple_get(cfg_listelt_value
					      (cfg_list_first(inet)), "keys");
			INSIST(control_keylist != NULL);
		}

		*explicit_key = ISC_FALSE;

	} else {
		result = cfg_map_get(config, "key", &global_keylist);
		*explicit_key = config != automagic_key.config
				       ? ISC_TRUE : ISC_FALSE;
	}

	if (result == ISC_R_SUCCESS) {
		*global_keylistp = global_keylist;
		*control_keylistp = control_keylist;
	} else
		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "no key statements for use by control channel");
}

static void
update_listener(ns_controls_t *cp,
		controllistener_t **listenerp, cfg_obj_t *control,
		cfg_obj_t *config, isc_sockaddr_t *addr,
		ns_aclconfctx_t *aclconfctx, char *socktext)
{
	controllistener_t *listener;
	cfg_obj_t *allow;
	cfg_obj_t *global_keylist = NULL;
	cfg_obj_t *control_keylist = NULL;
	dns_acl_t *new_acl = NULL;
	controlkeylist_t keys;
	isc_boolean_t explicit_key;
	isc_result_t result = ISC_R_SUCCESS;

	for (listener = ISC_LIST_HEAD(cp->listeners);
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
	 * First try to deal with the key situation.  There are a few
	 * possibilities:
	 *  (a)	It had an explicit keylist and still has an explicit keylist.
	 *  (b)	It had an automagic key and now has an explicit keylist.
	 *  (c)	It had an explicit keylist and now needs an automagic key.
	 *  (d) It has an automagic key and still needs the automagic key.
	 *
	 * (c) and (d) are the annoying ones.  The caller needs to know
	 * that it should use the automagic configuration for key information
	 * in place of the named.conf configuration.
	 *
	 * XXXDCL There is one other hazard that has not been dealt with,
	 * the problem that if a key change is being caused by a control
	 * channel reload, then the response will be with the new key
	 * and not able to be decrypted by the client.  For this reason,
	 * the automagic key is not regenerated on each reload.
	 */
	get_key_info(listener->mctx, config, control,
		     &global_keylist, &control_keylist, &explicit_key);

	if (control_keylist != NULL) {
		INSIST(global_keylist != NULL);

		ISC_LIST_INIT(keys);
		result = controlkeylist_fromcfg(control_keylist,
						listener->mctx, &keys);
	}

	if (result == ISC_R_SUCCESS) {
		free_controlkeylist(&listener->keys, listener->mctx);
		listener->keys = keys;
		register_keys(control, global_keylist, &listener->keys,
			      listener->mctx, socktext);

		if (! explicit_key)
			automagic_key.address = listener->address;

	} else if (global_keylist != NULL)
		/*
		 * This message might be a little misleading since the
		 * "new keys" might in fact be identical to the old ones,
		 * but tracking whether they are identical just for the
		 * sake of avoiding this message would be too much trouble.
		 */
		cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't install new keys for "
			    "command channel %s: %s",
			    socktext, isc_result_totext(result));


	/*
	 * Now, keep the old access list unless a new one can be made.
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

	*listenerp = listener;
}

static void
add_listener(ns_controls_t *cp, controllistener_t **listenerp,
	     cfg_obj_t *control, cfg_obj_t *config, isc_sockaddr_t *addr,
	     ns_aclconfctx_t *aclconfctx, char *socktext)
{
	isc_mem_t *mctx = cp->server->mctx;
	controllistener_t *listener;
	cfg_obj_t *allow;
	cfg_obj_t *global_keylist = NULL;
	cfg_obj_t *control_keylist = NULL;
	dns_acl_t *new_acl = NULL;
	isc_boolean_t explicit_key;
	isc_result_t result = ISC_R_SUCCESS;

	listener = isc_mem_get(mctx, sizeof(*listener));
	if (listener == NULL)
		result = ISC_R_NOMEMORY;

	if (result == ISC_R_SUCCESS) {
		listener->controls = cp;
		listener->mctx = mctx;
		listener->task = cp->server->task;
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

		get_key_info(listener->mctx, config, control,
			     &global_keylist, &control_keylist, &explicit_key);

		if (control_keylist != NULL)
			result = controlkeylist_fromcfg(control_keylist,
							listener->mctx,
							&listener->keys);
		if (result == ISC_R_SUCCESS) {
			register_keys(control, global_keylist, &listener->keys,
				      listener->mctx, socktext);

			if (! explicit_key)
				automagic_key.address = listener->address;

		} else
			cfg_obj_log(control, ns_g_lctx, ISC_LOG_WARNING,
				    "couldn't install keys for "
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
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
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
ns_controls_configure(ns_controls_t *cp, cfg_obj_t *config,
		      ns_aclconfctx_t *aclconfctx)
{
	controllistener_t *listener;
	controllistenerlist_t new_listeners;
	cfg_obj_t *controlslist = NULL;
	cfg_listelt_t *element, *element2;
	char socktext[ISC_SOCKADDR_FORMATSIZE];

	ISC_LIST_INIT(new_listeners);

	/*
	 * Get the list of named.conf 'controls' statements.
	 */
	(void)cfg_map_get(config, "controls", &controlslist);

	/*
	 * Run through the new control channel list, noting sockets that
	 * are already being listened on and moving them to the new list.
	 *
	 * Identifying duplicate addr/port combinations is left to either
	 * the underlying config code, or to the bind attempt getting an
	 * address-in-use error.
	 */
	if (controlslist != NULL) {
		for (element = cfg_list_first(controlslist);
		     element != NULL;
		     element = cfg_list_next(element)) {
			cfg_obj_t *controls;
			cfg_obj_t *inetcontrols = NULL;

			controls = cfg_listelt_value(element);
			(void)cfg_map_get(controls, "inet", &inetcontrols);
			if (inetcontrols == NULL)
				continue;

			for (element2 = cfg_list_first(inetcontrols);
			     element2 != NULL;
			     element2 = cfg_list_next(element2)) {
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
				 */
				control = cfg_listelt_value(element2);

				obj = cfg_tuple_get(control, "address");
				addr = cfg_obj_assockaddr(obj);
				if (isc_sockaddr_getport(addr) == 0)
					isc_sockaddr_setport(addr,
							     NS_CONTROL_PORT);

				isc_sockaddr_format(addr, socktext,
						    sizeof(socktext));

				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_CONTROL,
					      ISC_LOG_DEBUG(9),
					      "processing control channel %s",
					      socktext);

				update_listener(cp, &listener, control, config,
						addr, aclconfctx, socktext);

				if (listener != NULL)
					/*
					 * Remove the listener from the old
					 * list, so it won't be shut down.
					 */
					ISC_LIST_UNLINK(cp->listeners,
							listener, link);
				else
					/*
					 * This is a new listener.
					 */
					add_listener(cp, &listener, control,
						     config, addr, aclconfctx,
						     socktext);

				if (listener != NULL)
					ISC_LIST_APPEND(new_listeners,
							listener, link);
			}
		}

		finalize_automagic_key();

		/*
		 * ns_control_shutdown() will stop whatever is on the global
		 * listeners list, which currently only has whatever sockaddrs
		 * were in the previous configuration (if any) that do not
		 * remain in the current configuration.
		 */
		ns_controls_shutdown(cp);

		/*
		 * Put all of the valid listeners on the listeners list.
		 * Anything already on listeners in the process of shutting
		 * down will be taken care of by listen_done().
		 */
		ISC_LIST_APPENDLIST(cp->listeners, new_listeners, link);

	} else {
		isc_result_t result;

		result = parse_automagic_key(cp->server->mctx);

		if (result == ISC_R_SUCCESS)
			ns_controls_configure(cp, automagic_key.config,
					     aclconfctx);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
ns_controls_create(ns_server_t *server, ns_controls_t **ctrlsp) {
	isc_mem_t *mctx = server->mctx;
	ns_controls_t *controls = isc_mem_get(mctx, sizeof(*controls));
	if (controls == NULL)
		return (ISC_R_NOMEMORY);
	controls->server = server;
	ISC_LIST_INIT(controls->listeners);
	*ctrlsp = controls;
	return (ISC_R_SUCCESS);
}

void
ns_controls_destroy(ns_controls_t **ctrlsp) {
	ns_controls_t *controls = *ctrlsp;

	REQUIRE(ISC_LIST_EMPTY(controls->listeners));

	isc_mem_put(controls->server->mctx, controls, sizeof(*controls));
	*ctrlsp = NULL;
}
