/*
 * Copyright (C) 2008  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: statschannel.c,v 1.2.2.4 2008/01/24 02:29:56 jinmei Exp $ */

/*! \file */

#include <config.h>

#include <isc/buffer.h>
#include <isc/httpd.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/socket.h>
#include <isc/task.h>

#include <dns/stats.h>
#include <dns/view.h>

#include <named/log.h>
#include <named/server.h>
#include <named/statschannel.h>

struct ns_statschannel {
	/* Unlocked */
	isc_httpdmgr_t				*httpdmgr;
	isc_sockaddr_t				address;
	isc_mem_t				*mctx;

	/*
	 * Locked by channel lock: can be refererenced and modified by both
	 * the server task and the channel task.
	 */
	isc_mutex_t				lock;
	dns_acl_t				*acl;

	/* Locked by server task */
	ISC_LINK(struct ns_statschannel)	link;
};

#ifdef HAVE_LIBXML2

/* XXXMLG below here sucks. */

#define TRY(a) do { result = (a); INSIST(result == ISC_R_SUCCESS); } while(0);
#define TRY0(a) do { xmlrc = (a); INSIST(xmlrc >= 0); } while(0);

#define NODES 8
#define SPACES 3

static void
generatexml(ns_server_t *server, int *buflen, xmlChar **buf) {
	char boottime[sizeof "yyyy-mm-ddThh:mm:ssZ"];
	char nowstr[sizeof "yyyy-mm-ddThh:mm:ssZ"];
	isc_time_t now;
	xmlTextWriterPtr writer;
	xmlDocPtr doc;
	int xmlrc;
	dns_view_t *view;
	int i;
	isc_uint64_t counters[DNS_STATS_NCOUNTERS];

	isc_time_now(&now);
	isc_time_formatISO8601(&ns_g_boottime, boottime, sizeof boottime);
	isc_time_formatISO8601(&now, nowstr, sizeof nowstr);

	writer = xmlNewTextWriterDoc(&doc, 0);
	TRY0(xmlTextWriterStartDocument(writer, NULL, "UTF-8", NULL));
	TRY0(xmlTextWriterWritePI(writer, ISC_XMLCHAR "xml-stylesheet",
			ISC_XMLCHAR "type=\"text/xsl\" href=\"/bind9.xsl\""));
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "isc"));
	TRY0(xmlTextWriterWriteAttribute(writer, ISC_XMLCHAR "version",
					 ISC_XMLCHAR "1.0"));

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "bind"));
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "statistics"));
	TRY0(xmlTextWriterWriteAttribute(writer, ISC_XMLCHAR "version",
					 ISC_XMLCHAR "1.0"));

	/*
	 * Start by rendering the views we know of here.  For each view we
	 * know of, call its rendering function.
	 */
	view = ISC_LIST_HEAD(server->viewlist);
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "views"));
	while (view != NULL) {
		dns_view_xmlrender(view, writer, ISC_XML_RENDERALL);
		view = ISC_LIST_NEXT(view, link);
	}
	TRY0(xmlTextWriterEndElement(writer)); /* views */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "socketmgr"));
	isc_socketmgr_renderxml(ns_g_socketmgr, writer);
	TRY0(xmlTextWriterEndElement(writer)); /* socketmgr */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "taskmgr"));
	isc_taskmgr_renderxml(ns_g_taskmgr, writer);
	TRY0(xmlTextWriterEndElement(writer)); /* taskmgr */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "server"));
	xmlTextWriterStartElement(writer, ISC_XMLCHAR "boot-time");
	xmlTextWriterWriteString(writer, ISC_XMLCHAR boottime);
	xmlTextWriterEndElement(writer);
	xmlTextWriterStartElement(writer, ISC_XMLCHAR "current-time");
	xmlTextWriterWriteString(writer, ISC_XMLCHAR nowstr);
	xmlTextWriterEndElement(writer);
	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "counters"));
	dns_stats_copy(server->querystats, counters);
	for (i = 0; i < DNS_STATS_NCOUNTERS; i++) {
		xmlTextWriterStartElement(writer,
					ISC_XMLCHAR dns_statscounter_names[i]);
		xmlTextWriterWriteFormatString(writer,
					       "%" ISC_PRINT_QUADFORMAT "u",
					       counters[i]);
		xmlTextWriterEndElement(writer);
	}
	xmlTextWriterEndElement(writer); /* counters */
	xmlTextWriterEndElement(writer); /* server */

	TRY0(xmlTextWriterStartElement(writer, ISC_XMLCHAR "memory"));
	isc_mem_renderxml(server->mctx, writer);
	TRY0(xmlTextWriterEndElement(writer)); /* memory */

	TRY0(xmlTextWriterEndElement(writer)); /* statistics */
	TRY0(xmlTextWriterEndElement(writer)); /* bind */
	TRY0(xmlTextWriterEndElement(writer)); /* isc */

	TRY0(xmlTextWriterEndDocument(writer));

	xmlFreeTextWriter(writer);

	xmlDocDumpFormatMemoryEnc(doc, buf, buflen, "UTF-8", 1);
	xmlFreeDoc(doc);
}

static void
wrap_xmlfree(isc_buffer_t *buffer, void *arg) {
	UNUSED(arg);

	xmlFree(isc_buffer_base(buffer));
}

static isc_result_t
render_index(const char *url, const char *querystring, void *arg,
	     unsigned int *retcode, const char **retmsg, const char **mimetype,
	     isc_buffer_t *b, isc_httpdfree_t **freecb,
	     void **freecb_args)
{
	unsigned char *msg;
	int msglen;
	ns_server_t *server = arg;

	UNUSED(url);
	UNUSED(querystring);

	generatexml(server, &msglen, &msg);

	*retcode = 200;
	*retmsg = "OK";
	*mimetype = "text/xml";
	isc_buffer_reinit(b, msg, msglen);
	isc_buffer_add(b, msglen);
	*freecb = wrap_xmlfree;
	*freecb_args = NULL;

	return (ISC_R_SUCCESS);
}

#endif	/* HAVE_LIBXML2 */

static isc_result_t
render_xsl(const char *url, const char *querystring, void *args,
	   unsigned int *retcode, const char **retmsg, const char **mimetype,
	   isc_buffer_t *b, isc_httpdfree_t **freecb,
	   void **freecb_args)
{
#include "bind9.xsl.h"

	UNUSED(url);
	UNUSED(querystring);
	UNUSED(args);

	*retcode = 200;
	*retmsg = "OK";
	*mimetype = "text/xslt+xml";
	isc_buffer_reinit(b, msg, strlen(msg));
	isc_buffer_add(b, strlen(msg));
	*freecb = NULL;
	*freecb_args = NULL;

	return (ISC_R_SUCCESS);
}

static void
shutdown_listener(ns_statschannel_t *listener) {
	char socktext[ISC_SOCKADDR_FORMATSIZE];
	isc_sockaddr_format(&listener->address, socktext, sizeof(socktext));
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,NS_LOGMODULE_SERVER,
		      ISC_LOG_NOTICE, "stopping statistics channel on %s",
		      socktext);

	isc_httpdmgr_shutdown(&listener->httpdmgr);
}

static isc_boolean_t
client_ok(const isc_sockaddr_t *fromaddr, void *arg) {
	ns_statschannel_t *listener = arg;
	isc_netaddr_t netaddr;
	char socktext[ISC_SOCKADDR_FORMATSIZE];
	int match;

	REQUIRE(listener != NULL);

	isc_netaddr_fromsockaddr(&netaddr, fromaddr);

	LOCK(&listener->lock);
	if (dns_acl_match(&netaddr, NULL, listener->acl, &ns_g_server->aclenv,
			  &match, NULL) == ISC_R_SUCCESS && match > 0) {
		UNLOCK(&listener->lock);
		return (ISC_TRUE);
	}
	UNLOCK(&listener->lock);

	isc_sockaddr_format(fromaddr, socktext, sizeof(socktext));
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_SERVER, ISC_LOG_WARNING,
		      "rejected statistics connection from %s", socktext);

	return (ISC_FALSE);
}

static void
destroy_listener(void *arg) {
	ns_statschannel_t *listener = arg;

	REQUIRE(listener != NULL);
	REQUIRE(!ISC_LINK_LINKED(listener, link));

	/* We don't to have acquire the lock here since it's already unlinked */
	dns_acl_detach(&listener->acl);

	DESTROYLOCK(&listener->lock);
	isc_mem_putanddetach(&listener->mctx, listener, sizeof(*listener));
}

static isc_result_t
add_listener(ns_server_t *server, ns_statschannel_t **listenerp,
	     const cfg_obj_t *listen_params, const cfg_obj_t *config,
	     isc_sockaddr_t *addr, cfg_aclconfctx_t *aclconfctx,
	     const char *socktext)
{
	isc_result_t result;
	ns_statschannel_t *listener;
	isc_task_t *task = NULL;
	isc_socket_t *sock = NULL;
	const cfg_obj_t *allow;
	dns_acl_t *new_acl = NULL;

	listener = isc_mem_get(server->mctx, sizeof(*listener));
	if (listener == NULL)
		return (ISC_R_NOMEMORY);

	listener->httpdmgr = NULL;
	listener->address = *addr;
	listener->acl = NULL;
	listener->mctx = NULL;
	ISC_LINK_INIT(listener, link);

	result = isc_mutex_init(&listener->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(server->mctx, listener, sizeof(*listener));
		return (ISC_R_FAILURE);
	}

	isc_mem_attach(server->mctx, &listener->mctx);

	allow = cfg_tuple_get(listen_params, "allow");
	if (allow != NULL && cfg_obj_islist(allow)) {
		result = cfg_acl_fromconfig(allow, config, ns_g_lctx,
					    aclconfctx, listener->mctx, 0,
					    &new_acl);
	} else
		result = dns_acl_any(listener->mctx, &new_acl);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	dns_acl_attach(new_acl, &listener->acl);
	dns_acl_detach(&new_acl);

	result = isc_task_create(ns_g_taskmgr, 0, &task);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	isc_task_setname(task, "statchannel", NULL);

	result = isc_socket_create(ns_g_socketmgr, isc_sockaddr_pf(addr),
				   isc_sockettype_tcp, &sock);
	if (result != ISC_R_SUCCESS)
		goto cleanup;
	isc_socket_setname(sock, "statchannel", NULL);

#ifndef ISC_ALLOW_MAPPED
	isc_socket_ipv6only(sock, ISC_TRUE);
#endif

	result = isc_socket_bind(sock, addr);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = isc_httpdmgr_create(server->mctx, sock, task, client_ok,
				     destroy_listener, listener, ns_g_timermgr,
				     &listener->httpdmgr);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

#ifdef HAVE_LIBXML2
	isc_httpdmgr_addurl(listener->httpdmgr, "/", render_index, server);
#endif
	isc_httpdmgr_addurl(listener->httpdmgr, "/bind9.xsl", render_xsl,
			    server);

	*listenerp = listener;
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_SERVER, ISC_LOG_NOTICE,
		      "statistics channel listening on %s", socktext);

cleanup:
	if (result != ISC_R_SUCCESS) {
		if (listener->acl != NULL)
			dns_acl_detach(&listener->acl);
		DESTROYLOCK(&listener->lock);
		isc_mem_putanddetach(&listener->mctx, listener,
				     sizeof(*listener));
	}
	if (task != NULL)
		isc_task_detach(&task);
	if (sock != NULL)
		isc_socket_detach(&sock);

	return (result);
}

static void
update_listener(ns_server_t *server, ns_statschannel_t **listenerp,
		const cfg_obj_t *listen_params, const cfg_obj_t *config,
		isc_sockaddr_t *addr, cfg_aclconfctx_t *aclconfctx,
		const char *socktext)
{
	ns_statschannel_t *listener;
	const cfg_obj_t *allow = NULL;
	dns_acl_t *new_acl = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	for (listener = ISC_LIST_HEAD(server->statschannels);
	     listener != NULL;
	     listener = ISC_LIST_NEXT(listener, link))
		if (isc_sockaddr_equal(addr, &listener->address))
			break;

	if (listener == NULL) {
		*listenerp = NULL;
		return;
	}

	/*
	 * Now, keep the old access list unless a new one can be made.
	 */
	allow = cfg_tuple_get(listen_params, "allow");
	if (allow != NULL && cfg_obj_islist(allow)) {
		result = cfg_acl_fromconfig(allow, config, ns_g_lctx,
					    aclconfctx, listener->mctx, 0,
					    &new_acl);
	} else
		result = dns_acl_any(listener->mctx, &new_acl);

	if (result == ISC_R_SUCCESS) {
		LOCK(&listener->lock);

		dns_acl_detach(&listener->acl);
		dns_acl_attach(new_acl, &listener->acl);
		dns_acl_detach(&new_acl);

		UNLOCK(&listener->lock);
	} else {
		cfg_obj_log(listen_params, ns_g_lctx, ISC_LOG_WARNING,
			    "couldn't install new acl for "
			    "statistics channel %s: %s",
			    socktext, isc_result_totext(result));
	}

	*listenerp = listener;
}

isc_result_t
ns_statschannels_configure(ns_server_t *server, const cfg_obj_t *config,
			 cfg_aclconfctx_t *aclconfctx)
{
	ns_statschannel_t *listener, *listener_next;
	ns_statschannellist_t new_listeners;
	const cfg_obj_t *statschannellist = NULL;
	const cfg_listelt_t *element, *element2;
	char socktext[ISC_SOCKADDR_FORMATSIZE];

	ISC_LIST_INIT(new_listeners);

	/*
	 * Get the list of named.conf 'statistics-channels' statements.
	 */
	(void)cfg_map_get(config, "statistics-channels", &statschannellist);

	/*
	 * Run through the new address/port list, noting sockets that are
	 * already being listened on and moving them to the new list.
	 *
	 * Identifying duplicate addr/port combinations is left to either
	 * the underlying config code, or to the bind attempt getting an
	 * address-in-use error.
	 */
	if (statschannellist != NULL) {
#ifndef HAVE_LIBXML2
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_WARNING,
			      "statistics-channels specified but not effective "
			      "due to missing XML library");
#endif

		for (element = cfg_list_first(statschannellist);
		     element != NULL;
		     element = cfg_list_next(element)) {
			const cfg_obj_t *statschannel;
			const cfg_obj_t *listenercfg = NULL;

			statschannel = cfg_listelt_value(element);
			(void)cfg_map_get(statschannel, "inet",
					  &listenercfg);
			if (listenercfg == NULL)
				continue;

			for (element2 = cfg_list_first(listenercfg);
			     element2 != NULL;
			     element2 = cfg_list_next(element2)) {
				const cfg_obj_t *listen_params;
				const cfg_obj_t *obj;
				isc_sockaddr_t addr;

				listen_params = cfg_listelt_value(element2);

				obj = cfg_tuple_get(listen_params, "address");
				addr = *cfg_obj_assockaddr(obj);
				if (isc_sockaddr_getport(&addr) == 0)
					isc_sockaddr_setport(&addr, NS_STATSCHANNEL_HTTPPORT);

				isc_sockaddr_format(&addr, socktext,
						    sizeof(socktext));

				isc_log_write(ns_g_lctx,
					      NS_LOGCATEGORY_GENERAL,
					      NS_LOGMODULE_SERVER,
					      ISC_LOG_DEBUG(9),
					      "processing statistics "
					      "channel %s",
					      socktext);

				update_listener(server, &listener,
						listen_params, config, &addr,
						aclconfctx, socktext);

				if (listener != NULL) {
					/*
					 * Remove the listener from the old
					 * list, so it won't be shut down.
					 */
					ISC_LIST_UNLINK(server->statschannels,
							listener, link);
				} else {
					/*
					 * This is a new listener.
					 */
					isc_result_t r;

					r = add_listener(server, &listener,
							 listen_params, config,
							 &addr, aclconfctx,
							 socktext);
					if (r != ISC_R_SUCCESS) {
						cfg_obj_log(listen_params,
							    ns_g_lctx,
							    ISC_LOG_WARNING,
							    "couldn't allocate "
							    "statistics channel"
							    " %s: %s",
							    socktext,
							    isc_result_totext(r));
					}
				}

				if (listener != NULL)
					ISC_LIST_APPEND(new_listeners, listener,
							link);
			}
		}
	}

	for (listener = ISC_LIST_HEAD(server->statschannels);
	     listener != NULL;
	     listener = listener_next) {
		listener_next = ISC_LIST_NEXT(listener, link);
		ISC_LIST_UNLINK(server->statschannels, listener, link);
		shutdown_listener(listener);
	}

	ISC_LIST_APPENDLIST(server->statschannels, new_listeners, link);
	return (ISC_R_SUCCESS);
}

void
ns_statschannels_shutdown(ns_server_t *server) {
	ns_statschannel_t *listener;

	while ((listener = ISC_LIST_HEAD(server->statschannels)) != NULL) {
		ISC_LIST_UNLINK(server->statschannels, listener, link);
		shutdown_listener(listener);
	}
}
