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

#include <config.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <isc/app.h>
#include <isc/assertions.h>
#include <isc/dir.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/aclconf.h>
#include <dns/cache.h>
#include <dns/confacl.h>
#include <dns/confctx.h>
#include <dns/confip.h>
#include <dns/confparser.h>
#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/fixedname.h>
#include <dns/journal.h>
#include <dns/master.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/rootns.h>
#include <dns/tkeyconf.h>
#include <dns/tsigconf.h>
#include <dns/types.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zoneconf.h>

#include <named/client.h>
#include <named/globals.h>
#include <named/interfacemgr.h>
#include <named/listenlist.h>
#include <named/log.h>
#include <named/os.h>
#include <named/server.h>
#include <named/types.h>

/*
 * Check an operation for failure.  Assumes that the function
 * using it has a 'result' variable and a 'cleanup' label.
 */
#define CHECK(op) \
	do { result = (op); 				  	 \
	       if (result != ISC_R_SUCCESS) goto cleanup; 	 \
	} while (0)

#define CHECKM(op, msg) \
	do { result = (op); 				  	  \
	       if (result != ISC_R_SUCCESS) {			  \
			isc_log_write(ns_g_lctx,		  \
				      NS_LOGCATEGORY_GENERAL,	  \
				      NS_LOGMODULE_SERVER,	  \
				      ISC_LOG_ERROR,		  \
				      "%s: %s", msg,		  \
				      isc_result_totext(result)); \
			goto cleanup;				  \
		}						  \
	} while (0)						  \

#define CHECKFATAL(op, msg) \
	do { result = (op); 				  	  \
	       if (result != ISC_R_SUCCESS)			  \
			fatal(msg, result);			  \
	} while (0)						  \

typedef struct {
	isc_mem_t *		mctx;
	dns_viewlist_t		viewlist;
	dns_aclconfctx_t	*aclconf;
} ns_load_t;

static void fatal(char *msg, isc_result_t result);
static void ns_server_reload(isc_task_t *task, isc_event_t *event);

static isc_result_t
ns_listenelt_fromconfig(dns_c_lstnon_t *celt, dns_c_ctx_t *cctx,
			dns_aclconfctx_t *actx,
			isc_mem_t *mctx, ns_listenelt_t **target);
static isc_result_t
ns_listenlist_fromconfig(dns_c_lstnlist_t *clist, dns_c_ctx_t *cctx,
			 dns_aclconfctx_t *actx,
			 isc_mem_t *mctx, ns_listenlist_t **target);

/*
 * Configure 'view' according to 'cctx'.
 *
 * XXX reconfiguration should preserve cache contents.
 */
static isc_result_t
configure_view(dns_view_t *view, dns_c_ctx_t *cctx, isc_mem_t *mctx,
	       dns_dispatch_t *dispatch)
{
	dns_cache_t *cache;
	isc_result_t result;
	isc_int32_t cleaning_interval;
	dns_tsig_keyring_t *ring;
	dns_c_forw_t forward;
	dns_c_iplist_t *forwarders;
	dns_fwdpolicy_t fwdpolicy;
	isc_sockaddrlist_t addresses;
	isc_sockaddr_t *sa, *next_sa;
	unsigned int i;

	REQUIRE(DNS_VIEW_VALID(view));

	ISC_LIST_INIT(addresses);

	RWLOCK(&view->conflock, isc_rwlocktype_write);
	
	/*
	 * Cache.
	 */
	cache = NULL;
	CHECK(dns_cache_create(mctx, ns_g_taskmgr, ns_g_timermgr,
			       view->rdclass, "rbt", 0, NULL, &cache));
	dns_view_setcache(view, cache);
	cleaning_interval = 3600; /* Default is 1 hour. */
	(void) dns_c_ctx_getcleaninterval(cctx, &cleaning_interval);
	dns_cache_setcleaninginterval(cache, cleaning_interval);
	dns_cache_detach(&cache);

	/*
	 * XXXRTH  Temporary support for loading cache contents.
	 */
	if (ns_g_cachefile != NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER,
			      ISC_LOG_DEBUG(1), "loading cache '%s'",
			      ns_g_cachefile);
		CHECK(dns_db_load(view->cachedb, ns_g_cachefile));
	}

	/*
	 * Resolver.
	 *
	 * XXXRTH  Hardwired number of tasks.
	 */
	CHECK(dns_view_createresolver(view, ns_g_taskmgr, 31,
				      ns_g_socketmgr, ns_g_timermgr,
				      0, dispatch, NULL));

	/*
	 * Set resolver forwarding policy.
	 */
	if (dns_c_ctx_getforwarders(cctx, &forwarders) == ISC_R_SUCCESS) {
		fwdpolicy = dns_fwdpolicy_first;
		/*
		 * Ugh.  Convert between list formats.
		 */
		for (i = 0; i < forwarders->nextidx; i++) {
			sa = isc_mem_get(view->mctx, sizeof *sa);
			if (sa == NULL) {
				result = ISC_R_NOMEMORY;
				goto cleanup;
			}
			*sa = forwarders->ips[i];
			isc_sockaddr_setport(sa, 53);
			ISC_LINK_INIT(sa, link);
			ISC_LIST_APPEND(addresses, sa, link);
		}
		INSIST(!ISC_LIST_EMPTY(addresses));
		CHECK(dns_resolver_setforwarders(view->resolver, &addresses));
		/*
		 * XXXRTH  The configuration type 'dns_c_forw_t' should be
		 *         elminated.
		 */
		if (dns_c_ctx_getforward(cctx, &forward) == ISC_R_SUCCESS) {
			INSIST(forward == dns_c_forw_first ||
			       forward == dns_c_forw_only);
			if (forward == dns_c_forw_only)
				fwdpolicy = dns_fwdpolicy_only;
		}
		CHECK(dns_resolver_setfwdpolicy(view->resolver, fwdpolicy));
	}

	/*
	 * We have default hints for class IN if we need them.
	 */
	if (view->rdclass == dns_rdataclass_in && view->hints == NULL)
		dns_view_sethints(view, ns_g_server->roothints);

	/*
	 * Configure the view's TSIG keys.
	 */
	ring = NULL;
	CHECK(dns_tsigkeyring_fromconfig(cctx, view->mctx, &ring));
	dns_view_setkeyring(view, ring);

 cleanup:
	RWUNLOCK(&view->conflock, isc_rwlocktype_write);

	for (sa = ISC_LIST_HEAD(addresses);
	     sa != NULL;
	     sa = next_sa) {
		next_sa = ISC_LIST_NEXT(sa, link);
		isc_mem_put(view->mctx, sa, sizeof *sa);
	}

	return (result);
}

/*
 * Create the special view that handles queries for
 * "version.bind. CH".   The version string returned is that
 * configured in 'configctx', or a compiled-in default if
 * there is no "version" configuration option.
 */
static isc_result_t
create_version_view(dns_c_ctx_t *configctx, dns_view_t **viewp) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_zone_t *zone = NULL;
	dns_dbversion_t *dbver = NULL;
	dns_difftuple_t *tuple = NULL;
	dns_diff_t diff;
	dns_view_t *view = NULL;
	char *versiontext;
	unsigned char buf[256];
	isc_region_t r;
	size_t len;
	dns_rdata_t rdata;
	static unsigned char origindata[] = "\007version\004bind";
	dns_name_t origin;

	REQUIRE(viewp != NULL && *viewp == NULL);

	dns_diff_init(ns_g_mctx, &diff);

	dns_name_init(&origin, NULL);
	r.base = origindata;
	r.length = sizeof(origindata);
	dns_name_fromregion(&origin, &r);

	(void) dns_c_ctx_getversion(configctx, &versiontext);
	if (versiontext == NULL)
		versiontext = ns_g_version;
	len = strlen(versiontext);
	if (len > 255)
		len = 255; /* Silently truncate. */
	buf[0] = len;
	memcpy(buf + 1, versiontext, len);

	r.base = buf;
	r.length = 1 + len;
	dns_rdata_fromregion(&rdata, dns_rdataclass_ch, dns_rdatatype_txt, &r);

	CHECK(dns_zone_create(&zone, ns_g_mctx));
	CHECK(dns_zone_setorigin(zone, &origin));

	CHECK(dns_db_create(ns_g_mctx, "rbt", &origin, ISC_FALSE,
			    dns_rdataclass_ch, 0, NULL, &db));
	
	CHECK(dns_db_newversion(db, &dbver));

	CHECK(dns_difftuple_create(ns_g_mctx, DNS_DIFFOP_ADD, &origin,
				   0, &rdata, &tuple));
	dns_diff_append(&diff, &tuple);
	CHECK(dns_diff_apply(&diff, db, dbver));

	dns_db_closeversion(db, &dbver, ISC_TRUE);

	CHECK(dns_view_create(ns_g_mctx, dns_rdataclass_ch, "_version",
			      &view));

	CHECK(dns_zone_replacedb(zone, db, ISC_FALSE));

	CHECK(dns_view_addzone(view, zone));

	dns_view_freeze(view);

	/* Transfer ownership. */
	*viewp = view;
	view = NULL;

	result = ISC_R_SUCCESS;

 cleanup:
	if (view != NULL)
		dns_view_detach(&view);
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (dbver != NULL)
		dns_db_closeversion(db, &dbver, ISC_FALSE);
	if (db != NULL)
		dns_db_detach(&db);
	dns_diff_clear(&diff);

	return (result);
}

static isc_result_t
configure_hints(dns_view_t *view, const char *filename) {
	isc_result_t result;
	dns_db_t *db;

	db = NULL;
	result = dns_rootns_create(view->mctx, view->rdclass, filename, &db);
	if (result == ISC_R_SUCCESS) {
		dns_view_sethints(view, db);
		dns_db_detach(&db);
	}

	return (result);
}

/*
 * Configure or reconfigure a zone.  This callback function
 * is called after parsing each "zone" statement in named.conf.
 */
static isc_result_t
configure_zone(dns_c_ctx_t *cctx, dns_c_zone_t *czone, dns_c_view_t *cview,
	  void *uap)
{
	ns_load_t *lctx = (ns_load_t *) uap;
	dns_view_t *view = NULL;	/* New view */
	dns_view_t *pview = NULL;	/* Production view */
	dns_zone_t *zone = NULL;	/* New or reused zone */
	dns_zone_t *tzone = NULL;	/* Temporary zone */
	char *viewname;
	
	isc_result_t result;

	char *corigin;	
	isc_buffer_t buffer;
	dns_fixedname_t fixorigin;
	dns_name_t *origin;

	/*
	 * Get the zone origin as a dns_name_t.
	 */
	corigin = NULL;
	/* XXX casting away const */
	CHECK(dns_c_zone_getname(czone, (const char **) &corigin));
	isc_buffer_init(&buffer, corigin, strlen(corigin),
			ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&buffer, strlen(corigin));
	dns_fixedname_init(&fixorigin);
	CHECK(dns_name_fromtext(dns_fixedname_name(&fixorigin),
				&buffer, dns_rootname, ISC_FALSE, NULL));
	origin = dns_fixedname_name(&fixorigin);
	
	/*
	 * Find or create the view in the new view list.
	 */
	view = NULL;
	if (cview != NULL)
		viewname = cview->name;
	else
		viewname = "_default";
	result = dns_viewlist_find(&lctx->viewlist, viewname,
				   czone->zclass, &view);
	if (result != ISC_R_NOTFOUND && result != ISC_R_SUCCESS)
		goto cleanup;
	if (view == NULL) {
		dns_view_t *tview = NULL;
		CHECK(dns_view_create(ns_g_mctx, czone->zclass,
				      viewname, &view));
		dns_view_attach(view, &tview);
		ISC_LIST_APPEND(lctx->viewlist, tview, link);
	}

	/*
	 * Master zones must have 'file' set.
	 */
	if (czone->ztype == dns_c_zone_master &&
	    czone->u.mzone.file == NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			      "zone '%s': 'file' not specified",
			      corigin);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	/*
	 * "hints zones" aren't zones.  If we've got one,
	 * configure it and return.
	 */
	if (czone->ztype == dns_c_zone_hint) {
		if (czone->u.hzone.file == NULL) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "zone '%s': 'file' not specified",
				      corigin);
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		if (dns_name_equal(origin, dns_rootname)) {
			result = configure_hints(view, czone->u.hzone.file);
		} else {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER, ISC_LOG_WARNING,
				      "ignoring non-root hint zone '%s'",
				      corigin);
			result = ISC_R_SUCCESS;
		}
		goto cleanup;
	}

	/*
	 * "stub zones" aren't zones either.  Eventually we'll
	 * create a "cache freshener" to keep the stub data in the
	 * cache.
	 */
	if (czone->ztype == dns_c_zone_stub) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_WARNING,
	      "stub zone '%s': stub zones are not supported in this release",
			      corigin);
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	/*
	 * "forward zones" aren't zones either.  Eventually we'll
	 * translate this syntax into the appropriate selective forwarding
	 * configuration.
	 */
	if (czone->ztype == dns_c_zone_forward) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_WARNING,
      "forward zone '%s': forward zones are not supported in this release",
			      corigin);
		result = ISC_R_SUCCESS;
		goto cleanup;
	}

	/*
	 * Check for duplicates in the new zone table.
	 */
	result = dns_view_findzone(view, origin, &tzone);
	if (result == ISC_R_SUCCESS) {
		/*
		 * We already have this zone!
		 */
		result = ISC_R_EXISTS;
		goto cleanup;
	}

	/*
	 * See if we can reuse an existing zone.  This is
	 * only possible if all of these are true:
	 *   - The zone's view exists
	 *   - A zone with the right name exists in the view
	 *   - The zone is compatible with the config
	 *     options (e.g., an existing master zone cannot 
	 *     be reused if the options specify a slave zone)
	 */
	result = dns_viewlist_find(&ns_g_server->viewlist,
				   view->name, view->rdclass,
				   &pview);
	if (result != ISC_R_NOTFOUND && result != ISC_R_SUCCESS)
		goto cleanup;
	if (pview != NULL)
		result = dns_view_findzone(pview, origin, &zone);
	if (result != ISC_R_NOTFOUND && result != ISC_R_SUCCESS)
		goto cleanup;
	if (zone != NULL) {
		if (! dns_zone_reusable(zone, czone))
			dns_zone_detach(&zone);
	}

	/*
	 * If we cannot reuse an existing zone, we will have to
	 * create a new one.
	 */
	if (zone == NULL) {
		CHECK(dns_zone_create(&zone, lctx->mctx));
		CHECK(dns_zone_setorigin(zone, origin));
		CHECK(dns_zonemgr_managezone(ns_g_server->zonemgr,
					     zone));
	}

	/*
	 * Configure the zone.
	 */
	CHECK(dns_zone_configure(cctx, lctx->aclconf, czone, zone));

	/*
	 * XXX Why was this here?
	 *
	 * if (dns_zone_gettype(zone) == dns_zone_hint)
	 *      INSIST(0);
	 */

	/*
	 * Add the zone to its view in the new view list.
	 */
	CHECK(dns_view_addzone(view, zone));

 cleanup:
	if (tzone != NULL)
		dns_zone_detach(&tzone);
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (pview != NULL)
		dns_view_detach(&pview);
	if (view != NULL)
		dns_view_detach(&view);

	return (result);
}

/*
 * Configure a single server ACL at '*aclp'.  Get its configuration by
 * calling 'getacl'.
 */
static isc_result_t
configure_server_acl(dns_c_ctx_t *cctx, dns_aclconfctx_t *actx, isc_mem_t *mctx,
		     isc_result_t (*getcacl)(dns_c_ctx_t *, dns_c_ipmatchlist_t **),
		     dns_acl_t **aclp)
{
	isc_result_t result = ISC_R_SUCCESS;
	dns_c_ipmatchlist_t *cacl = NULL;
	if (*aclp != NULL)
		dns_acl_detach(aclp);
	(void) (*getcacl)(cctx, &cacl);
	if (cacl != NULL) {
		result = dns_acl_fromconfig(cacl, cctx, actx, mctx, aclp);
		dns_c_ipmatchlist_detach(&cacl);
	}
	return (result);
}

/*
 * Configure a single server quota.
 */
static void
configure_server_quota(dns_c_ctx_t *cctx,
		       isc_result_t (*getquota)(dns_c_ctx_t *, isc_int32_t *),
		       isc_quota_t *quota, int defaultvalue)
{
	isc_int32_t val = defaultvalue;
	(void)(*getquota)(cctx, &val);
	quota->max = val;
}

static isc_result_t
configure_server_querysource(dns_c_ctx_t *cctx, ns_server_t *server,
			     dns_dispatch_t **dispatchp) {
	isc_result_t result;
	struct in_addr ina;
	isc_sockaddr_t sa, any;
	in_port_t port;
	isc_socket_t *socket;

	ina.s_addr = htonl(INADDR_ANY);
	isc_sockaddr_fromin(&any, &ina, 0);

	*dispatchp = NULL;

	if (dns_c_ctx_getquerysourceaddr(cctx, &sa) != ISC_R_SUCCESS)
		sa = any;
	if (dns_c_ctx_getquerysourceport(cctx, &port) != ISC_R_SUCCESS)
		port = 0;
	isc_sockaddr_setport(&sa, port);

	/*
	 * XXX  We need to have separate query source options for v4 and v6,
	 *      but right now we only have one option, and the parser allows
	 *      v6 addresses for it.  Until we have a separate v6 option,
	 *      make sure that the query source is v4.
	 */
	if (isc_sockaddr_pf(&sa) != PF_INET)
		return (DNS_R_NOTIMPLEMENTED);

	/*
	 * If we don't support IPv4, we're done!
	 */
	if (isc_net_probeipv4() != ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);

	if (isc_sockaddr_equal(&sa, &any)) {
		/*
		 * The query source is fully wild.  No special dispatcher
		 * work needs to be done.
		 */
		return (ISC_R_SUCCESS);
	}

	/*
	 * If the interface manager has a dispatcher for this address,
	 * use it.
	 */
	if (ns_interfacemgr_findudpdispatcher(server->interfacemgr, &sa,
					      dispatchp) !=
	    ISC_R_SUCCESS) {
		/*
		 * The interface manager doesn't have a matching dispatcher.
		 */
		if (server->querysrc_dispatch != NULL) {
			/*
			 * We've already got a custom dispatcher.  If it is
			 * compatible with the new configuration, use it.
			 */
			if (isc_sockaddr_equal(&server->querysrc_address,
					       &sa)) {
				dns_dispatch_attach(server->querysrc_dispatch,
						    dispatchp);
				return (ISC_R_SUCCESS);
			}
			/*
			 * The existing custom dispatcher is not compatible.
			 * We don't need it anymore.
			 */
			dns_dispatch_detach(&server->querysrc_dispatch);
		}
		/*
		 * Create a custom dispatcher.
		 */
		INSIST(server->querysrc_dispatch == NULL);
		server->querysrc_address = sa;
		socket = NULL;
		result = isc_socket_create(ns_g_socketmgr, AF_INET,
					   isc_sockettype_udp,
					   &socket);
		if (result != ISC_R_SUCCESS)
			return (result);
		result = isc_socket_bind(socket, &sa);
		if (result != ISC_R_SUCCESS) {
			isc_socket_detach(&socket);	
			return (result);
		}
		result = dns_dispatch_create(ns_g_mctx, socket,
					     server->task, 4096,
					     1000, 32768, 16411, 16433, NULL,
					     &server->querysrc_dispatch);
		/*
		 * Regardless of whether dns_dispatch_create() succeeded or
		 * failed, we don't need to keep the reference to the socket.
		 */
		isc_socket_detach(&socket);
		if (result != ISC_R_SUCCESS)
			return (result);
		dns_dispatch_attach(server->querysrc_dispatch, dispatchp);
	} else {
		/*
		 * We're sharing a UDP dispatcher with the interface manager
		 * now.  Any prior custom dispatcher can be discarded.
		 */
		if (server->querysrc_dispatch != NULL)
			dns_dispatch_detach(&server->querysrc_dispatch);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
load_configuration(const char *filename, ns_server_t *server,
		   isc_boolean_t first_time)
{
	isc_result_t result;
	ns_load_t lctx;
	dns_c_cbks_t callbacks;
	dns_c_ctx_t *configctx;
	dns_view_t *view, *view_next;
	dns_viewlist_t tmpviewlist;
	dns_aclconfctx_t aclconfctx;
	dns_dispatch_t *dispatch;
	char *pidfilename;

	dns_aclconfctx_init(&aclconfctx);

	RWLOCK(&server->conflock, isc_rwlocktype_write);
	dns_zonemgr_lockconf(server->zonemgr, isc_rwlocktype_write);
	
	lctx.mctx = ns_g_mctx;
	lctx.aclconf = &aclconfctx;
	ISC_LIST_INIT(lctx.viewlist);

	callbacks.zonecbk = configure_zone;
	callbacks.zonecbkuap = &lctx;
	callbacks.optscbk = NULL;
	callbacks.optscbkuap = NULL;

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "loading configuration from '%s'",
		      filename);

	/*
	 * Parse the configuration file creating a parse tree.  Any
	 * 'zone' statements are handled immediately by calling
	 * configure_zone() through 'callbacks'.
	 */
	configctx = NULL;
	CHECK(dns_c_parse_namedconf(filename, ns_g_mctx, &configctx,
				    &callbacks));
	
	/*
	 * Configure various server options.
	 */
	(void) dns_c_ctx_getrecursion(configctx, &server->recursion);	
	(void) dns_c_ctx_getauthnxdomain(configctx, &server->auth_nxdomain);
	(void) dns_c_ctx_gettransferformat(configctx,
					   &server->transfer_format);
	
	CHECK(configure_server_acl(configctx, &aclconfctx, ns_g_mctx,
				   dns_c_ctx_getqueryacl, &server->queryacl));
	
	CHECK(configure_server_acl(configctx, &aclconfctx, ns_g_mctx,
				   dns_c_ctx_getrecursionacl,
				   &server->recursionacl));
	
	CHECK(configure_server_acl(configctx, &aclconfctx, ns_g_mctx,
				   dns_c_ctx_gettransferacl,
				   &server->transferacl));
	
	configure_server_quota(configctx, dns_c_ctx_gettransfersout,
				     &server->xfroutquota, 10);
	configure_server_quota(configctx, dns_c_ctx_gettcpclients,
				     &server->tcpquota, 100);
	configure_server_quota(configctx, dns_c_ctx_getrecursiveclients,
				     &server->recursionquota, 100);

	/*
	 * Configure the interface manager according to the "listen-on"
	 * statement.
	 */
	{
		dns_c_lstnlist_t *clistenon = NULL;
		ns_listenlist_t *listenon = NULL;

		(void) dns_c_ctx_getlistenlist(configctx, &clistenon);
		if (clistenon != NULL) {
			result = ns_listenlist_fromconfig(clistenon,
							  configctx,
							  &aclconfctx,
							  ns_g_mctx,
							  &listenon);
		} else {
			/* Not specified, use default. */
			CHECK(ns_listenlist_default(ns_g_mctx, ns_g_port,
						    &listenon));
		}
		ns_interfacemgr_setlistenon(server->interfacemgr, listenon);
		ns_listenlist_detach(&listenon);
	}

	/*
	 * Rescan the interface list to pick up changes in the
	 * listen-on option.  It's important that we do this before we try
	 * to configure the query source, since the dispatcher we use might
	 * be shared with an interface.
	 */
	ns_interfacemgr_scan(server->interfacemgr);

	dispatch = NULL;
	CHECK(configure_server_querysource(configctx, server, &dispatch));

	/*
	 * If we haven't created any views, create a default view for class
	 * IN.  (We're a caching-only server.)
	 */
	if (ISC_LIST_EMPTY(lctx.viewlist)) {
		view = NULL;
		CHECKM(dns_view_create(ns_g_mctx, dns_rdataclass_in, 
				       "_default", &view),
		       "creating default view");
		ISC_LIST_APPEND(lctx.viewlist, view, link);
	}

	/*
	 * Configure and freeze the views.  Their zone tables have
	 * already been filled in at parsing time, but other stuff
	 * like the resolvers are still unconfigured.
	 */
	for (view = ISC_LIST_HEAD(lctx.viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link))
	{
		CHECK(configure_view(view, configctx, ns_g_mctx, dispatch));
		dns_view_freeze(view);
	}

	/*
	 * We don't need dispatch anymore.
	 */
	if (dispatch != NULL)
		dns_dispatch_detach(&dispatch);
	
	/*
	 * Create (or recreate) the version view.
	 */
	view = NULL;
	CHECK(create_version_view(configctx, &view));
	ISC_LIST_APPEND(lctx.viewlist, view, link);
	view = NULL;

	/*
	 * Change directory.
	 */
	if (configctx->options != NULL &&
	    configctx->options->directory != NULL) {
		result = isc_dir_chdir(configctx->options->directory);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER,
				      ISC_LOG_ERROR, "change directory "
				      "to '%s' failed: %s",
				      configctx->options->directory,
				      isc_result_totext(result));
			CHECK(result);
		}
	}


	/*
	 * Swap our new view list with the production one.
	 */
	tmpviewlist = server->viewlist;
	server->viewlist = lctx.viewlist;
	lctx.viewlist = tmpviewlist;

	/*
	 * Load the TKEY information from the configuration.
	 */
	{
		dns_tkey_ctx_t *t = NULL;
		CHECKM(dns_tkeyctx_fromconfig(configctx, ns_g_mctx, &t),
		       "configuring TKEY");
		if (server->tkeyctx != NULL)
			dns_tkeyctx_destroy(&server->tkeyctx);
		server->tkeyctx = t;
	}

	if (first_time)
		ns_os_changeuser(ns_g_username);

	if (dns_c_ctx_getpidfilename(configctx, &pidfilename) ==
	    ISC_R_NOTFOUND)
		pidfilename = "/var/run/named.pid";
	ns_os_writepidfile(pidfilename);
	
	dns_aclconfctx_destroy(&aclconfctx);	

	dns_c_ctx_delete(&configctx);
	
 cleanup:
	/*
	 * This cleans up either the old production view list
	 * or our temporary list depending on whether they
	 * were swapped above or not.
	 */
	for (view = ISC_LIST_HEAD(lctx.viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(lctx.viewlist, view, link);
		dns_view_detach(&view);

	}

	dns_zonemgr_unlockconf(server->zonemgr, isc_rwlocktype_write);
	RWUNLOCK(&server->conflock, isc_rwlocktype_write);	
	return (result);
}

static isc_result_t
load_zones(ns_server_t *server, isc_boolean_t stop) {
	isc_result_t result;
	dns_view_t *view;

	dns_zonemgr_lockconf(server->zonemgr, isc_rwlocktype_read);
	
	/*
	 * Load zone data from disk.
	 */
	for (view = ISC_LIST_HEAD(server->viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link))
	{
		CHECK(dns_view_load(view, stop));
	}

	/*
	 * Force zone maintenance.  Do this after loading
	 * so that we know when we need to force AXFR of
	 * slave zones whose master files are missing.
	 */
	CHECK(dns_zonemgr_forcemaint(server->zonemgr));
 cleanup:
	dns_zonemgr_unlockconf(server->zonemgr, isc_rwlocktype_read);	
	return (result);
}

static void
run_server(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	ns_server_t *server = (ns_server_t *) event->arg;

	(void)task;

	isc_event_free(&event);

	CHECKFATAL(ns_clientmgr_create(ns_g_mctx, ns_g_taskmgr, ns_g_timermgr,
				       &server->clientmgr),
		   "creating client manager");
	
	CHECKFATAL(ns_interfacemgr_create(ns_g_mctx, ns_g_taskmgr,
					  ns_g_socketmgr, server->clientmgr,
					  &server->interfacemgr),
		   "creating interface manager");

	CHECKFATAL(load_configuration(ns_g_conffile, server, ISC_TRUE),
		   "loading configuration");

	CHECKFATAL(load_zones(server, ISC_TRUE),
		   "loading zones");

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "running");
}

static void
shutdown_server(isc_task_t *task, isc_event_t *event) {
	dns_view_t *view, *view_next;
	ns_server_t *server = (ns_server_t *) event->arg;
		
	UNUSED(task);

	RWLOCK(&server->conflock, isc_rwlocktype_write);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "shutting down");

	for (view = ISC_LIST_HEAD(server->viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(server->viewlist, view, link);
		dns_view_detach(&view);
	}

	if (server->querysrc_dispatch != NULL)
		dns_dispatch_detach(&server->querysrc_dispatch);
	ns_clientmgr_destroy(&server->clientmgr);
	ns_interfacemgr_shutdown(server->interfacemgr);
	ns_interfacemgr_detach(&server->interfacemgr);	
	dns_zonemgr_shutdown(server->zonemgr);
	
	isc_task_detach(&server->task);

	isc_event_free(&event);

	RWUNLOCK(&server->conflock, isc_rwlocktype_write);
}

void
ns_server_create(isc_mem_t *mctx, ns_server_t **serverp) {
	isc_result_t result;
	
	ns_server_t *server = isc_mem_get(mctx, sizeof(*server));
	if (server == NULL)
		fatal("allocating server object", ISC_R_NOMEMORY);

	server->mctx = mctx;
	server->task = NULL;
	
	CHECKFATAL(isc_rwlock_init(&server->conflock, 1, 1),
		   "initializing server configuration lock");

	/* Initialize configuration data with default values. */
	server->recursion = ISC_TRUE;
	server->auth_nxdomain = ISC_FALSE; /* Was true in BIND 8 */
	server->transfer_format = dns_one_answer;

	server->queryacl = NULL;
	server->recursionacl = NULL;
	server->transferacl = NULL;

	result = isc_quota_init(&server->xfroutquota, 10);
	RUNTIME_CHECK(result == ISC_R_SUCCESS); 
	result = isc_quota_init(&server->tcpquota, 10);
	RUNTIME_CHECK(result == ISC_R_SUCCESS); 
	result = isc_quota_init(&server->recursionquota, 100);
	RUNTIME_CHECK(result == ISC_R_SUCCESS); 
	
	/* Initialize server data structures. */
	server->zonemgr = NULL;
	server->clientmgr = NULL;
	server->interfacemgr = NULL;
	ISC_LIST_INIT(server->viewlist);
	server->roothints = NULL;
		
	CHECKFATAL(dns_rootns_create(mctx, dns_rdataclass_in, NULL,
				     &server->roothints),
		   "setting up root hints");

	CHECKFATAL(isc_mutex_init(&server->reload_event_lock),
		   "initializing reload event lock");
	server->reload_event =
		isc_event_allocate(ns_g_mctx, server,
				   NS_EVENT_RELOAD,
				   ns_server_reload,
				   server,
				   sizeof(isc_event_t));
	CHECKFATAL(server->reload_event == NULL ?
		   ISC_R_NOMEMORY : ISC_R_SUCCESS,
		   "allocating reload event");

	server->tkeyctx = NULL;
	CHECKFATAL(dns_tkeyctx_create(ns_g_mctx, &server->tkeyctx),
		   "creating TKEY context");
	server->querysrc_dispatch = NULL;

	/*
	 * Setup the server task, which is responsible for coordinating
	 * startup and shutdown of the server.
	 */
	CHECKFATAL(isc_task_create(ns_g_taskmgr, ns_g_mctx, 0, &server->task),
		   "creating server task");
	isc_task_setname(server->task, "server", server);
	CHECKFATAL(isc_task_onshutdown(server->task, shutdown_server, server),
		   "isc_task_onshutdown");
	CHECKFATAL(isc_app_onrun(ns_g_mctx, server->task, run_server, server),
		   "isc_app_onrun");

	CHECKFATAL(dns_zonemgr_create(ns_g_mctx, ns_g_taskmgr, ns_g_timermgr,
				      ns_g_socketmgr, &server->zonemgr),
		   "dns_zonemgr_create");

	server->magic = NS_SERVER_MAGIC;
	*serverp = server;
}
	
void
ns_server_destroy(ns_server_t **serverp) {
	ns_server_t *server = *serverp;
	REQUIRE(NS_SERVER_VALID(server));

	REQUIRE(server->querysrc_dispatch == NULL);
	if (server->tkeyctx != NULL)
		dns_tkeyctx_destroy(&server->tkeyctx);

	isc_event_free(&server->reload_event);
	
	INSIST(ISC_LIST_EMPTY(server->viewlist));

	dns_zonemgr_destroy(&server->zonemgr);
	server->zonemgr = NULL;
	
	dns_db_detach(&server->roothints);
	
	if (server->queryacl != NULL)
		dns_acl_detach(&server->queryacl);
	if (server->recursionacl != NULL)
		dns_acl_detach(&server->recursionacl);
	if (server->transferacl != NULL)
		dns_acl_detach(&server->transferacl);

	isc_quota_destroy(&server->recursionquota);
	isc_quota_destroy(&server->tcpquota);
	isc_quota_destroy(&server->xfroutquota);
	isc_rwlock_destroy(&server->conflock);

	server->magic = 0;
	isc_mem_put(server->mctx, server, sizeof(*server));
}

static void
fatal(char *msg, isc_result_t result)
{
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_CRITICAL, "%s: %s", msg, isc_result_totext(result));
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_CRITICAL, "exiting (due to fatal error)");
	exit(1);
}

static void
ns_server_reload(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	ns_server_t *server = (ns_server_t *) event->arg;
	UNUSED(task);
	
	result = load_configuration(ns_g_conffile, server, ISC_FALSE);
	if (result != DNS_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			      "reloading configuration failed: %s",
			      isc_result_totext(result));
	}
	result = load_zones(server, ISC_FALSE);
	if (result != DNS_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			      "reloading zones failed: %s",
			      isc_result_totext(result));
	}
	LOCK(&server->reload_event_lock);
	INSIST(server->reload_event == NULL);
	server->reload_event = event;
	UNLOCK(&server->reload_event_lock);
}

void
ns_server_reloadwanted(ns_server_t *server) {
	LOCK(&server->reload_event_lock);
	if (server->reload_event != NULL)
		isc_task_send(server->task, &server->reload_event);
	UNLOCK(&server->reload_event_lock);
}

static isc_result_t
ns_listenlist_fromconfig(dns_c_lstnlist_t *clist, dns_c_ctx_t *cctx,
			  dns_aclconfctx_t *actx,
			  isc_mem_t *mctx, ns_listenlist_t **target)
{
	dns_c_lstnon_t *ce;
	isc_result_t result;
	ns_listenlist_t *dlist = NULL;
		
	REQUIRE(target != NULL && *target == NULL);

	result = ns_listenlist_create(mctx, &dlist);
	if (result != ISC_R_SUCCESS)
		return (result);
	
	for (ce = ISC_LIST_HEAD(clist->elements);
	     ce != NULL;
	     ce = ISC_LIST_NEXT(ce, next))
	{
		ns_listenelt_t *delt = NULL;
		result = ns_listenelt_fromconfig(ce, cctx, actx, mctx, &delt);
		if (result != DNS_R_SUCCESS)
			goto cleanup;
		ISC_LIST_APPEND(dlist->elts, delt, link);
	}
	*target = dlist;
	return (ISC_R_SUCCESS);

 cleanup:
	ns_listenlist_detach(&dlist);
	return (result);
}

/*
 * Create a listen list from the corresponding configuration
 * data structure.
 */
static isc_result_t
ns_listenelt_fromconfig(dns_c_lstnon_t *celt, dns_c_ctx_t *cctx,
			 dns_aclconfctx_t *actx,
			 isc_mem_t *mctx, ns_listenelt_t **target)
{
	isc_result_t result;
	ns_listenelt_t *delt = NULL;
	REQUIRE(target != NULL && *target == NULL);
	result = ns_listenelt_create(mctx, celt->port, NULL, &delt);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_acl_fromconfig(celt->iml, cctx, actx, mctx, &delt->acl);
	if (result != DNS_R_SUCCESS) {
		ns_listenelt_destroy(delt);
		return (result);
	}
	*target = delt;
	return (ISC_R_SUCCESS);
}

