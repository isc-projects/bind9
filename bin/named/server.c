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

/* $Id: server.c,v 1.276.2.3.6.2 2003/09/19 07:06:43 marka Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/app.h>
#include <isc/base64.h>
#include <isc/dir.h>
#include <isc/entropy.h>
#include <isc/file.h>
#include <isc/lex.h>
#include <isc/print.h>
#include <isc/resource.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/cache.h>
#include <dns/confparser.h>
#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/forward.h>
#include <dns/journal.h>
#include <dns/keytable.h>
#include <dns/master.h>
#include <dns/peer.h>
#include <dns/rdataclass.h>
#include <dns/rdatastruct.h>
#include <dns/resolver.h>
#include <dns/rootns.h>
#include <dns/stats.h>
#include <dns/tkey.h>
#include <dns/view.h>
#include <dns/zone.h>
#include <dns/zt.h>

#include <dst/dst.h>

#include <named/client.h>
#include <named/interfacemgr.h>
#include <named/log.h>
#include <named/logconf.h>
#include <named/lwresd.h>
#include <named/omapi.h>
#include <named/os.h>
#include <named/server.h>
#include <named/tkeyconf.h>
#include <named/tsigconf.h>
#include <named/zoneconf.h>

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
	ns_aclconfctx_t	*aclconf;
} ns_load_t;

static void
fatal(const char *msg, isc_result_t result);

static void
ns_server_reload(isc_task_t *task, isc_event_t *event);

static isc_result_t
ns_listenelt_fromconfig(dns_c_lstnon_t *celt, dns_c_ctx_t *cctx,
			ns_aclconfctx_t *actx,
			isc_mem_t *mctx, ns_listenelt_t **target);
static isc_result_t
ns_listenlist_fromconfig(dns_c_lstnlist_t *clist, dns_c_ctx_t *cctx,
			 ns_aclconfctx_t *actx,
			 isc_mem_t *mctx, ns_listenlist_t **target);

static isc_result_t
configure_forward(dns_c_ctx_t *cctx, dns_view_t *view, dns_name_t *origin,
		  dns_c_iplist_t *forwarders, dns_c_forw_t forward);

/*
 * Configure a single view ACL at '*aclp'.  Get its configuration by
 * calling 'getvcacl' (for per-view configuration) and maybe 'getscacl'
 * (for a global default).
 */
static isc_result_t
configure_view_acl(dns_c_view_t *cview,
		   dns_c_ctx_t *cctx,
		   ns_aclconfctx_t *actx, isc_mem_t *mctx,
		   isc_result_t (*getvcacl)
		       (dns_c_view_t *, dns_c_ipmatchlist_t **),
		   isc_result_t (*getscacl)
		       (dns_c_ctx_t *, dns_c_ipmatchlist_t **),
		   dns_acl_t **aclp)
{
	isc_result_t result;

	dns_c_ipmatchlist_t *cacl = NULL;
	if (*aclp != NULL)
		dns_acl_detach(aclp);
	if (getvcacl != NULL && cview != NULL)
		(void)(*getvcacl)(cview, &cacl);
	if (cacl == NULL && getscacl != NULL)
		(void)(*getscacl)(cctx, &cacl);
	if (cacl == NULL) {
		/*
		 * No value available.  *aclp == NULL.
		 */
		return (ISC_R_SUCCESS);
	}

	result = ns_acl_fromconfig(cacl, cctx, actx, mctx, aclp);

	dns_c_ipmatchlist_detach(&cacl);

	return (result);
}

static isc_result_t
configure_view_dnsseckey(dns_c_view_t *cview, dns_c_tkey_t *ckey,
			 dns_keytable_t *keytable, isc_mem_t *mctx)
{
	dns_rdataclass_t viewclass;
	dns_rdata_key_t keystruct;
	isc_int32_t flags, proto, alg;
	unsigned char keydata[4096];
	isc_buffer_t keydatabuf;
	unsigned char rrdata[4096];
	isc_buffer_t rrdatabuf;
	isc_region_t r;
	dns_fixedname_t fkeyname;
	dns_name_t *keyname;
	isc_buffer_t namebuf;
	isc_result_t result;
	dst_key_t *dstkey = NULL;

	if (cview == NULL)
		viewclass = dns_rdataclass_in;
	else
		CHECK(dns_c_view_getviewclass(cview,
					      &viewclass));
	keystruct.common.rdclass = viewclass;
	keystruct.common.rdtype = dns_rdatatype_key;
	/*
	 * The key data in keystruct is not
	 * dynamically allocated.
	 */
	keystruct.mctx = NULL;

	ISC_LINK_INIT(&keystruct.common, link);

	flags = ckey->pubkey->flags;
	proto = ckey->pubkey->protocol;
	alg = ckey->pubkey->algorithm;
	if (flags < 0 || flags > 0xffff)
		CHECKM(ISC_R_RANGE, "key flags");
	if (proto < 0 || proto > 0xff)
		CHECKM(ISC_R_RANGE, "key protocol");
	if (alg < 0 || alg > 0xff)
		CHECKM(ISC_R_RANGE, "key algorithm");
	keystruct.flags = flags;
	keystruct.protocol = proto;
	keystruct.algorithm = alg;

	isc_buffer_init(&keydatabuf, keydata, sizeof(keydata));
	isc_buffer_init(&rrdatabuf, rrdata, sizeof(rrdata));

	CHECK(isc_base64_decodestring(mctx, ckey->pubkey->key,
				      &keydatabuf));
	isc_buffer_usedregion(&keydatabuf, &r);
	keystruct.datalen = r.length;
	keystruct.data = r.base;

	CHECK(dns_rdata_fromstruct(NULL,
				   keystruct.common.rdclass,
				   keystruct.common.rdtype,
				   &keystruct, &rrdatabuf));
	dns_fixedname_init(&fkeyname);
	keyname = dns_fixedname_name(&fkeyname);
	isc_buffer_init(&namebuf, ckey->domain,
			strlen(ckey->domain));
	isc_buffer_add(&namebuf, strlen(ckey->domain));
	CHECK(dns_name_fromtext(keyname, &namebuf,
				dns_rootname, ISC_FALSE,
				NULL));
	CHECK(dst_key_fromdns(keyname, viewclass, &rrdatabuf,
			      mctx, &dstkey));

	CHECK(dns_keytable_add(keytable, &dstkey));
	INSIST(dstkey == NULL);
	return (ISC_R_SUCCESS);

 cleanup:
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
		      "configuring trusted key for '%s': "
		      "%s", ckey->domain,
		      isc_result_totext(result));
	result = ISC_R_FAILURE;

	if (dstkey != NULL)
		dst_key_free(&dstkey);

	return (result);
}

/*
 * Configure DNSSEC keys for a view.  Currently used only for
 * the security roots.
 *
 * The per-view configuration values and their server-global
 * defaults are are read from 'cview' and 'cctx' using
 * the function 'cgetv' and 'cgets', respectively.
 * The variable to be configured is '*target'.
 */
static isc_result_t
configure_view_dnsseckeys(dns_c_view_t *cview,
			  dns_c_ctx_t *cctx,
			  isc_mem_t *mctx,
			  isc_result_t (*cgetv)
			      (dns_c_view_t *, dns_c_tkeylist_t **),
			  isc_result_t (*cgets)
			      (dns_c_ctx_t *, dns_c_tkeylist_t **),
			  dns_keytable_t **target)
{
	isc_result_t result;
	dns_c_tkeylist_t *ckeys = NULL;
	dns_c_tkey_t *ckey;
	dns_keytable_t *keytable = NULL;

	CHECK(dns_keytable_create(mctx, &keytable));

	result = ISC_R_FAILURE;
	if (cgetv != NULL && cview != NULL)
		result = (*cgetv)(cview, &ckeys);
	if (result != ISC_R_SUCCESS)
		result = (*cgets)(cctx, &ckeys);

	if (result == ISC_R_SUCCESS) {
		for (ckey = ISC_LIST_HEAD(ckeys->tkeylist);
		     ckey != NULL;
		     ckey = ISC_LIST_NEXT(ckey, next)) {
			CHECK(configure_view_dnsseckey(cview, ckey,
						       keytable, mctx));
		}
	} else if (result != ISC_R_NOTFOUND)
		goto cleanup;

	dns_keytable_detach(target);
	*target = keytable; /* Transfer ownership. */
	keytable = NULL;
	result = ISC_R_SUCCESS;
	
 cleanup:
	return (result);
}


/*
 * Get a dispatch appropriate for the resolver of a given view.
 */
static isc_result_t
get_view_querysource_dispatch(dns_c_ctx_t *cctx, dns_c_view_t *cview,
			      int af, dns_dispatch_t **dispatchp)
{
	isc_result_t result;
	dns_dispatch_t *disp;
	isc_sockaddr_t sa;
	unsigned int attrs, attrmask;

	/*
	 * Make compiler happy.
	 */
	result = ISC_R_FAILURE;

	switch (af) {
	case AF_INET:
		result = ISC_R_NOTFOUND;
		if (cview != NULL)
			result = dns_c_view_getquerysource(cview, &sa);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getquerysource(cctx, &sa);
		if (result != ISC_R_SUCCESS)
			isc_sockaddr_any(&sa);
		break;
	case AF_INET6:
		result = ISC_R_NOTFOUND;
		if (cview != NULL)
			result = dns_c_view_getquerysourcev6(cview, &sa);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getquerysourcev6(cctx, &sa);
		if (result != ISC_R_SUCCESS)
			isc_sockaddr_any6(&sa);
		break;
	default:
		INSIST(0);
	}

	INSIST(isc_sockaddr_pf(&sa) == af);

	/*
	 * If we don't support this address family, we're done!
	 */
	switch (af) {
	case AF_INET:
		result = isc_net_probeipv4();
		break;
	case AF_INET6:
		result = isc_net_probeipv6();
		break;
	default:
		INSIST(0);
	}
	if (result != ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);

	/*
	 * Try to find a dispatcher that we can share.
	 */
	attrs = 0;
	attrs |= DNS_DISPATCHATTR_UDP;
	switch (af) {
	case AF_INET:
		attrs |= DNS_DISPATCHATTR_IPV4;
		break;
	case AF_INET6:
		attrs |= DNS_DISPATCHATTR_IPV6;
		break;
	}
	attrmask = 0;
	attrmask |= DNS_DISPATCHATTR_UDP;
	attrmask |= DNS_DISPATCHATTR_TCP;
	attrmask |= DNS_DISPATCHATTR_IPV4;
	attrmask |= DNS_DISPATCHATTR_IPV6;

	disp = NULL;
	result = dns_dispatch_getudp(ns_g_dispatchmgr, ns_g_socketmgr,
				     ns_g_taskmgr, &sa, 4096,
				     1000, 32768, 16411, 16433,
				     attrs, attrmask, &disp);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			      "could not get query source dispatcher");
		return (result);
	}

	*dispatchp = disp;

	return (ISC_R_SUCCESS);
}

/*
 * Configure 'view' according to 'cview', taking defaults from 'cctx'
 * where values are missing in cview.
 *
 * When configuring the default view, cview will be NULL and the
 * global defaults in cctx used exclusively.
 */
static isc_result_t
configure_view(dns_view_t *view, dns_c_ctx_t *cctx, dns_c_view_t *cview,
	       isc_mem_t *mctx, ns_aclconfctx_t *actx)
{
	dns_cache_t *cache = NULL;
	isc_result_t result;
	isc_uint32_t cleaning_interval;
	isc_uint32_t max_cache_size;
	isc_uint32_t lame_ttl;
	dns_tsig_keyring_t *ring;
	dns_c_iplist_t *forwarders;
	dns_view_t *pview = NULL;	/* Production view */
	isc_mem_t *cmctx;
	dns_dispatch_t *dispatch4 = NULL;
	dns_dispatch_t *dispatch6 = NULL;
	in_port_t port;

	REQUIRE(DNS_VIEW_VALID(view));

	cmctx = NULL;

	RWLOCK(&view->conflock, isc_rwlocktype_write);

	/*
	 * Set the view's port number for outgoing queries.
	 */
	result = dns_c_ctx_getport(cctx, &port);
	if (result != ISC_R_SUCCESS)
		port = 53;
	dns_view_setdstport(view, port);

	/*
	 * Attach load manager to view.
	 */
	dns_view_setloadmgr(view, ns_g_server->loadmgr);

	/*
	 * Configure the view's cache.  Try to reuse an existing
	 * cache if possible, otherwise create a new cache.
	 * Note that the ADB is not preserved in either case.
	 *
	 * XXX Determining when it is safe to reuse a cache is
	 * tricky.  When the view's configuration changes, the cached
	 * data may become invalid because it reflects our old
	 * view of the world.  As more view attributes become
	 * configurable, we will have to add code here to check
	 * whether they have changed in ways that could
	 * invalidate the cache.
	 */
	result = dns_viewlist_find(&ns_g_server->viewlist,
				   view->name, view->rdclass,
				   &pview);
	if (result != ISC_R_NOTFOUND && result != ISC_R_SUCCESS)
		goto cleanup;
	if (pview != NULL) {
		INSIST(pview->cache != NULL);
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_DEBUG(3),
			      "reusing existing cache");
		dns_cache_attach(pview->cache, &cache);
		dns_view_detach(&pview);
	} else {
		CHECK(isc_mem_create(0, 0, &cmctx));
		CHECK(dns_cache_create(cmctx, ns_g_taskmgr, ns_g_timermgr,
				       view->rdclass, "rbt", 0, NULL, &cache));
	}
	dns_view_setcache(view, cache);

	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_getcleaninterval(cview,
						     &cleaning_interval);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getcleaninterval(cctx, &cleaning_interval);
	if (result != ISC_R_SUCCESS)
		cleaning_interval = 3600; /* Default is 1 hour. */
	dns_cache_setcleaninginterval(cache, cleaning_interval);

	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_getmaxcachesize(cview, &max_cache_size);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getmaxcachesize(cctx, &max_cache_size);
	if (result != ISC_R_SUCCESS)
		max_cache_size = 0;
	/*
	 * XXX remove once rbt if fixed
	 */
	max_cache_size = 0;
	dns_cache_setcachesize(cache, max_cache_size);

	dns_cache_detach(&cache);

	/*
	 * Resolver.
	 *
	 * XXXRTH  Hardwired number of tasks.
	 */
	CHECK(get_view_querysource_dispatch(cctx, cview, AF_INET,
					    &dispatch4));
	CHECK(get_view_querysource_dispatch(cctx, cview, AF_INET6,
					    &dispatch6));
	CHECK(dns_view_createresolver(view, ns_g_taskmgr, 31,
				      ns_g_socketmgr, ns_g_timermgr,
				      0, ns_g_dispatchmgr,
				      dispatch4, dispatch6));
	if (dispatch4 != NULL)
		dns_dispatch_detach(&dispatch4);
	if (dispatch6 != NULL)
		dns_dispatch_detach(&dispatch6);

	/*
	 * Set resolver's lame-ttl.
	 */
	if (cview != NULL)
		result = dns_c_view_getlamettl(cview, &lame_ttl);
	else
		result = ISC_R_NOTFOUND;
	if (result == ISC_R_NOTFOUND)
		result = dns_c_ctx_getlamettl(cctx, &lame_ttl);
	if (result == ISC_R_NOTFOUND)
		lame_ttl = 600;
	if (lame_ttl > 18000)
		lame_ttl = 18000;
	dns_resolver_setlamettl(view->resolver, lame_ttl);
	
	/*
	 * Set resolver forwarding policy.
	 */
	if ((cview != NULL &&
	     dns_c_view_getforwarders(cview, &forwarders) == ISC_R_SUCCESS) ||
	    (dns_c_ctx_getforwarders(cctx, &forwarders) == ISC_R_SUCCESS))
	{
		dns_c_forw_t fwd;
		if (!((cview != NULL &&
		       dns_c_view_getforward(cview, &fwd) == ISC_R_SUCCESS) ||
		      (dns_c_ctx_getforward(cctx, &fwd) == ISC_R_SUCCESS)))
			fwd = dns_c_forw_first;
		result = configure_forward(cctx, view,
					   dns_rootname, forwarders, fwd);
		dns_c_iplist_detach(&forwarders);
	}

	/*
	 * We have default hints for class IN if we need them.
	 */
	if (view->rdclass == dns_rdataclass_in && view->hints == NULL)
		dns_view_sethints(view, ns_g_server->in_roothints);

	/*
	 * If we still have no hints, this is a non-IN view with no
	 * "hints zone" configured.  That's an error.
	 */
	if (view->hints == NULL) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			      "no root hints for view '%s'",
			      cview == NULL ? "<default>" : cview->name);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	/*
	 * Configure the view's TSIG keys.
	 */
	ring = NULL;
	CHECK(ns_tsigkeyring_fromconfig(cview, cctx, view->mctx, &ring));
	dns_view_setkeyring(view, ring);

	/*
	 * Configure the view's peer list.
	 */
	{
		dns_peerlist_t *newpeers = NULL;

		result = ISC_R_NOTFOUND;
		if (cview != NULL)
			result = dns_c_view_getpeerlist(cview, &newpeers);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getpeerlist(cctx, &newpeers);
		if (result != ISC_R_SUCCESS)
			result = dns_peerlist_new(mctx, &newpeers);
		CHECK(result);

		dns_peerlist_detach(&view->peers);
		view->peers = newpeers; /* Transfer ownership. */
	}

	/*
	 * Configure the "match-clients" ACL.
	 */
	CHECK(configure_view_acl(cview, cctx, actx, ns_g_mctx,
				 dns_c_view_getmatchclients, NULL,
				 &view->matchclients));

	/*
	 * Configure other configurable data.
	 */
	view->recursion = ISC_TRUE;
	(void)dns_c_ctx_getrecursion(cctx, &view->recursion);
	if (cview != NULL)
		(void)dns_c_view_getrecursion(cview, &view->recursion);

	view->auth_nxdomain = ISC_FALSE; /* Was true in BIND 8 */
	(void)dns_c_ctx_getauthnxdomain(cctx, &view->auth_nxdomain);
	if (cview != NULL)
		(void)dns_c_view_getauthnxdomain(cview, &view->auth_nxdomain);

	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_gettransferformat(cview,
						      &view->transfer_format);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_gettransferformat(cctx,
						     &view->transfer_format);
	if (result != ISC_R_SUCCESS)
		view->transfer_format = dns_many_answers;

	/*
	 * Set sources where additional data, CNAMEs, and DNAMEs may be found.
	 */
	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_getadditionalfromauth(cview,
					&view->additionalfromauth);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getadditionalfromauth(cctx,
					&view->additionalfromauth);
	if (result != ISC_R_SUCCESS)
		view->additionalfromauth = ISC_TRUE;

	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_getadditionalfromcache(cview,
					&view->additionalfromcache);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getadditionalfromcache(cctx,
					&view->additionalfromcache);
	if (result != ISC_R_SUCCESS)
		view->additionalfromcache = ISC_TRUE;

	CHECK(configure_view_acl(cview, cctx, actx, ns_g_mctx,
				 dns_c_view_getallowquery,
				 dns_c_ctx_getallowquery,
				 &view->queryacl));

	CHECK(configure_view_acl(cview, cctx, actx, ns_g_mctx,
				 dns_c_view_getrecursionacl,
				 dns_c_ctx_getallowrecursion,
				 &view->recursionacl));

	CHECK(configure_view_acl(cview, cctx, actx, ns_g_mctx,
				 dns_c_view_getsortlist,
				 dns_c_ctx_getsortlist,
				 &view->sortlist));

	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_getrequestixfr(cview, &view->requestixfr);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getrequestixfr(cctx, &view->requestixfr);
	if (result != ISC_R_SUCCESS)
		view->requestixfr = ISC_TRUE;

	result = ISC_R_NOTFOUND;
	if (cview != NULL)
		result = dns_c_view_getprovideixfr(cview, &view->provideixfr);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getprovideixfr(cctx, &view->provideixfr);
	if (result != ISC_R_SUCCESS)
		view->provideixfr = ISC_TRUE;

	/*
	 * For now, there is only one kind of trusted keys, the
	 * "security roots".
	 */
	CHECK(configure_view_dnsseckeys(cview, cctx, mctx,
				  dns_c_view_gettrustedkeys,
				  dns_c_ctx_gettrustedkeys,
				  &view->secroots));

	{
		isc_uint32_t val;
		result = ISC_R_NOTFOUND;
		if (cview != NULL)
			result = dns_c_view_getmaxcachettl(cview, &val);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getmaxcachettl(cctx, &val);
		if (result != ISC_R_SUCCESS)
			val = 7 * 24 * 3600;
		view->maxcachettl = val;
	}
	{
		isc_uint32_t val;
		result = ISC_R_NOTFOUND;
		if (cview != NULL)
			result = dns_c_view_getmaxncachettl(cview, &val);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getmaxncachettl(cctx, &val);
		if (result != ISC_R_SUCCESS)
			val = 3 * 3600;
		if (val > 7 * 24 * 3600)
			val = 7 * 24 * 3600;
		view->maxncachettl = val;
	}
	{
		char *cachefile = NULL, *p = NULL;
		if (cview != NULL)
			result = dns_c_view_getcachefile(cview, &cachefile);
		else
			result = dns_c_ctx_getcachefile(cctx, &cachefile);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
			goto cleanup;
		if (cachefile != NULL) {
			p = isc_mem_strdup(view->mctx, cachefile);
			if (p == NULL) {
				result = ISC_R_NOMEMORY;
				goto cleanup;
			}
		}
		if (view->cachefile != NULL)
			isc_mem_free(view->mctx, view->cachefile);
		view->cachefile = p;
		if (view->cachefile != NULL) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER, ISC_LOG_DEBUG(1),
				      "loading cache '%s'", view->cachefile);
			/* DNS_R_SEENINCLUDE should be impossible here. */
			CHECK(dns_db_load(view->cachedb, view->cachefile));
		}
	}

	result = ISC_R_SUCCESS;

 cleanup:
	RWUNLOCK(&view->conflock, isc_rwlocktype_write);

	if (cmctx != NULL)
		isc_mem_detach(&cmctx);

	return (result);
}

/*
 * Create the special view that handles queries under "bind. CH".
 */
static isc_result_t
create_bind_view(dns_view_t **viewp)
{
	isc_result_t result;
	dns_view_t *view = NULL;

	REQUIRE(viewp != NULL && *viewp == NULL);

	CHECK(dns_view_create(ns_g_mctx, dns_rdataclass_ch, "_bind", &view));

	/* Transfer ownership. */
	*viewp = view;
	view = NULL;

	result = ISC_R_SUCCESS;

 cleanup:
	if (view != NULL)
		dns_view_detach(&view);

	return (result);
}



/*
 * Create the zone that handles queries for
 * "version.bind. CH".   The version string returned is that
 * configured in 'cctx', or a compiled-in default if
 * there is no "version" configuration option.
 */
static isc_result_t
create_version_zone(dns_c_ctx_t *cctx, dns_zonemgr_t *zmgr, dns_view_t *view)
{
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_zone_t *zone = NULL;
	dns_dbversion_t *dbver = NULL;
	dns_difftuple_t *tuple = NULL;
	dns_diff_t diff;
	char *versiontext;
	unsigned char buf[256];
	isc_region_t r;
	size_t len;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	static unsigned char origindata[] = "\007version\004bind";
	dns_name_t origin;

	dns_diff_init(ns_g_mctx, &diff);

	dns_name_init(&origin, NULL);
	r.base = origindata;
	r.length = sizeof(origindata);
	dns_name_fromregion(&origin, &r);

	result = dns_c_ctx_getversion(cctx, &versiontext);
	if (result != ISC_R_SUCCESS)
		/*
		 * Removing the const qualifier from ns_g_version is ok
		 * because the resulting string is not modified, only
		 * copied into a new buffer.
		 */
		DE_CONST(ns_g_version, versiontext);

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
	dns_zone_settype(zone, dns_zone_master);
	dns_zone_setclass(zone, dns_rdataclass_ch);
	dns_zone_setview(zone, view);

	CHECK(dns_zonemgr_managezone(zmgr, zone));

	CHECK(dns_db_create(ns_g_mctx, "rbt", &origin, dns_dbtype_zone,
			    dns_rdataclass_ch, 0, NULL, &db));

	CHECK(dns_db_newversion(db, &dbver));

	CHECK(dns_difftuple_create(ns_g_mctx, DNS_DIFFOP_ADD, &origin,
				   0, &rdata, &tuple));
	dns_diff_append(&diff, &tuple);
	CHECK(dns_diff_apply(&diff, db, dbver));

	dns_db_closeversion(db, &dbver, ISC_TRUE);

	CHECK(dns_zone_replacedb(zone, db, ISC_FALSE));

	CHECK(dns_view_addzone(view, zone));

	result = ISC_R_SUCCESS;

 cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (dbver != NULL)
		dns_db_closeversion(db, &dbver, ISC_FALSE);
	if (db != NULL)
		dns_db_detach(&db);
	dns_diff_clear(&diff);

	return (result);
}

/*
 * Create the special view that handles queries for
 * "authors.bind. CH".   The strings returned list
 * the BIND 9 authors.
 */
static isc_result_t
create_authors_zone(dns_zonemgr_t *zmgr, dns_view_t *view) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_zone_t *zone = NULL;
	dns_dbversion_t *dbver = NULL;
	dns_difftuple_t *tuple;
	dns_diff_t diff;
	isc_constregion_t r;
	isc_constregion_t cr;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	static const char origindata[] = "\007authors\004bind";
	dns_name_t origin;
	int i;
	static const char *authors[] = {
		"\014Mark Andrews",
		"\015James Brister",
		"\015Michael Graff",
		"\022Andreas Gustafsson",
		"\012Bob Halley",
		"\016David Lawrence",
		"\016Michael Sawyer",
		"\020Brian Wellington",
		NULL,
	};

	dns_diff_init(ns_g_mctx, &diff);

	dns_name_init(&origin, NULL);
	r.base = origindata;
	r.length = sizeof(origindata);
	dns_name_fromregion(&origin, (isc_region_t *)&r);

	CHECK(dns_zone_create(&zone, ns_g_mctx));
	CHECK(dns_zone_setorigin(zone, &origin));
	dns_zone_settype(zone, dns_zone_master);
	dns_zone_setclass(zone, dns_rdataclass_ch);
	dns_zone_setview(zone, view);

	CHECK(dns_zonemgr_managezone(zmgr, zone));

	CHECK(dns_db_create(ns_g_mctx, "rbt", &origin, dns_dbtype_zone,
			    dns_rdataclass_ch, 0, NULL, &db));

	CHECK(dns_db_newversion(db, &dbver));

	for (i = 0; authors[i] != NULL; i++) {
		cr.base = authors[i];
		cr.length = strlen(authors[i]);
		INSIST(cr.length == ((const unsigned char *)cr.base)[0] + 1U);
		dns_rdata_fromregion(&rdata, dns_rdataclass_ch,
				     dns_rdatatype_txt, (isc_region_t *)&cr);
		tuple = NULL;
		CHECK(dns_difftuple_create(ns_g_mctx, DNS_DIFFOP_ADD, &origin,
					   0, &rdata, &tuple));
		dns_diff_append(&diff, &tuple);
		dns_rdata_reset(&rdata);
	}

	CHECK(dns_diff_apply(&diff, db, dbver));

	dns_db_closeversion(db, &dbver, ISC_TRUE);

	CHECK(dns_zone_replacedb(zone, db, ISC_FALSE));

	CHECK(dns_view_addzone(view, zone));

	result = ISC_R_SUCCESS;

 cleanup:
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

static isc_result_t
configure_forward(dns_c_ctx_t *cctx, dns_view_t *view, dns_name_t *origin,
		  dns_c_iplist_t *forwarders, dns_c_forw_t forward)
{
	dns_fwdpolicy_t fwdpolicy;
	isc_sockaddrlist_t addresses;
	isc_sockaddr_t *sa;
	isc_result_t result;
	in_port_t port;
	unsigned int i;

	/*
	 * Determine which port to send forwarded requests to.
	 */
	if (ns_g_port != 0) {
		port = ns_g_port;
	} else {
		result = dns_c_ctx_getport(cctx, &port);
		if (result != ISC_R_SUCCESS)
			port = 53;
	}

	ISC_LIST_INIT(addresses);

	if (forwarders != NULL) {
		for (i = 0; i < forwarders->nextidx; i++) {
			sa = isc_mem_get(view->mctx, sizeof(isc_sockaddr_t));
			if (sa == NULL) {
				result = ISC_R_NOMEMORY;
				goto cleanup;
			}
			*sa = forwarders->ips[i];
			isc_sockaddr_setport(sa, port);
			ISC_LINK_INIT(sa, link);
			ISC_LIST_APPEND(addresses, sa, link);
		}
	}

	if (ISC_LIST_EMPTY(addresses))
		fwdpolicy = dns_fwdpolicy_none;
	else {
		INSIST(forward == dns_c_forw_first ||
		       forward == dns_c_forw_only);
		if (forward == dns_c_forw_only)
			fwdpolicy = dns_fwdpolicy_only;
		else
			fwdpolicy = dns_fwdpolicy_first;
	}

	result = dns_fwdtable_add(view->fwdtable, origin, &addresses,
				  fwdpolicy);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = ISC_R_SUCCESS;

 cleanup:

	while (!ISC_LIST_EMPTY(addresses)) {
		sa = ISC_LIST_HEAD(addresses);
		ISC_LIST_UNLINK(addresses, sa, link);
		isc_mem_put(view->mctx, sa, sizeof(isc_sockaddr_t));
	}

	return (result);
}

/*
 * Find an existing view matching the name and class of 'cview'
 * in 'viewlist', or create a new one and add it to the list.
 *
 * If 'cview' is NULL, find or create the default view.
 *
 * The view found or created is attached to '*viewp'.
 */
static isc_result_t
find_or_create_view(dns_c_view_t *cview, dns_viewlist_t *viewlist,
		    dns_view_t **viewp)
{
	isc_result_t result;
	const char *viewname;
	dns_rdataclass_t viewclass;
	dns_view_t *view = NULL;

	if (cview != NULL) {
		viewname = cview->name;
		result = dns_c_view_getviewclass(cview, &viewclass);
		if (result != ISC_R_SUCCESS)
			return (result);
	} else {
		viewname = "_default";
		viewclass = dns_rdataclass_in;
	}
	result = dns_viewlist_find(viewlist, viewname,
				   viewclass, &view);
	if (result == ISC_R_SUCCESS) {
		*viewp = view;
		return (ISC_R_SUCCESS);
	}
	if (result != ISC_R_NOTFOUND)
		return (result);
	INSIST(view == NULL);

	result = dns_view_create(ns_g_mctx, viewclass, viewname, &view);
	if (result != ISC_R_SUCCESS)
		return (result);

	ISC_LIST_APPEND(*viewlist, view, link);
	dns_view_attach(view, viewp);
	return (ISC_R_SUCCESS);
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
	dns_zone_t *dupzone = NULL;
	dns_c_iplist_t *forwarders = NULL;
	dns_c_forw_t forward;
	isc_result_t result;
	char *corigin;
	isc_buffer_t buffer;
	dns_fixedname_t fixorigin;
	dns_name_t *origin;
	isc_boolean_t only;

	/*
	 * Get the zone origin as a dns_name_t.
	 */
	corigin = NULL;
	/* XXX casting away const */
	CHECK(dns_c_zone_getname(czone, (const char **) &corigin));
	isc_buffer_init(&buffer, corigin, strlen(corigin));
	isc_buffer_add(&buffer, strlen(corigin));
	dns_fixedname_init(&fixorigin);
	CHECK(dns_name_fromtext(dns_fixedname_name(&fixorigin),
				&buffer, dns_rootname, ISC_FALSE, NULL));
	origin = dns_fixedname_name(&fixorigin);

	/*
	 * Find or create the view in the new view list.
	 */
	view = NULL;
	CHECK(find_or_create_view(cview, &lctx->viewlist, &view));

	if (czone->zclass != view->rdclass) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
		      "zone '%s': wrong class for view '%s'",
			      corigin, cview ? cview->name : "<default view>");
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
		if (!dns_name_equal(origin, dns_rootname)) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER, ISC_LOG_WARNING,
				      "ignoring non-root hint zone '%s'",
				      corigin);
			result = ISC_R_SUCCESS;
			goto cleanup;
		}
		if (view->hints != NULL) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "'%s' hint zone already defined",
				      corigin);
			result = ISC_R_EXISTS;
			goto cleanup;
		}
		result = configure_hints(view, czone->u.hzone.file);
		/*
		 * Hint zones may also refer to delegation only points.
		 */
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		only = ISC_FALSE;
		if (dns_c_zone_getdelegationonly(czone, &only) ==
		    ISC_R_SUCCESS && only)
			result = dns_view_adddelegationonly(view, origin);
		goto cleanup;
	}

	/*
	 * "forward zones" aren't zones either.  Translate this syntax into
	 * the appropriate selective forwarding configuration and return.
	 */
	if (czone->ztype == dns_c_zone_forward) {
		if (dns_c_zone_getforward(czone, &forward) != ISC_R_SUCCESS)
			forward = dns_c_forw_first;
		result = configure_forward(cctx, view, origin,
					   czone->u.fzone.forwarders,
					   forward);
		goto cleanup;
	}

	/*
	 * "delegation-only zones" aren't zones either.
	 */
	if (czone->ztype == dns_c_zone_delegationonly) {
		result = dns_view_adddelegationonly(view, origin);
		goto cleanup;
	}

	/*
	 * Check for duplicates in the new zone table.
	 */
	result = dns_view_findzone(view, origin, &dupzone);
	if (result == ISC_R_SUCCESS) {
		/*
		 * We already have this zone!
		 */
		dns_zone_detach(&dupzone);
		result = ISC_R_EXISTS;
		goto cleanup;
	}
	INSIST(dupzone == NULL);

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
		if (! ns_zone_reusable(zone, czone))
			dns_zone_detach(&zone);
	}

	if (zone != NULL) {
		/*
		 * We found a reusable zone.  Make it use the
		 * new view.
		 */
		dns_zone_setview(zone, view);
	} else {
		/*
		 * We cannot reuse an existing zone, we have
		 * to create a new one.
		 */
		CHECK(dns_zone_create(&zone, lctx->mctx));
		CHECK(dns_zone_setorigin(zone, origin));
		dns_zone_setview(zone, view);
		CHECK(dns_zonemgr_managezone(ns_g_server->zonemgr, zone));
	}

	/*
	 * If the zone contains 'forwarders' statements,
	 * configure selective forwarding.
	 */
	if (dns_c_zone_getforwarders(czone, &forwarders) == ISC_R_SUCCESS) {
		if (dns_c_zone_getforward(czone, &forward) != ISC_R_SUCCESS)
			forward = dns_c_forw_first;
		CHECK(configure_forward(cctx, view,
					origin, forwarders, forward));
	}

	/*
	 * Stub zones may also refer to delegation only points.
	 */
	only = ISC_FALSE;
	if (czone->ztype == dns_c_zone_stub &&
	    dns_c_zone_getdelegationonly(czone, &only) == ISC_R_SUCCESS) {
		if (only)
			CHECK(dns_view_adddelegationonly(view, origin));
	}

	/*
	 * Configure the zone.
	 */
	CHECK(ns_zone_configure(cctx, cview, czone, lctx->aclconf, zone));

	/*
	 * Add the zone to its view in the new view list.
	 */
	CHECK(dns_view_addzone(view, zone));

 cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);
	if (pview != NULL)
		dns_view_detach(&pview);
	if (view != NULL)
		dns_view_detach(&view);

	return (result);
}

/*
 * Configure a single server quota.
 */
static void
configure_server_quota(dns_c_ctx_t *cctx,
		       isc_result_t (*getquota)(dns_c_ctx_t *, isc_uint32_t *),
		       isc_quota_t *quota, int defaultvalue)
{
	isc_uint32_t val = defaultvalue;
	(void)(*getquota)(cctx, &val);
	quota->max = val;
}

/*
 * This function is called as soon as the 'options' statement has been
 * parsed.
 */
static isc_result_t
options_callback(dns_c_ctx_t *cctx, void *uap) {
	isc_result_t result;

	UNUSED(uap);

	/*
	 * Change directory.
	 */
	if (cctx->options != NULL &&
	    cctx->options->directory != NULL) {
		result = isc_dir_chdir(cctx->options->directory);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER,
				      ISC_LOG_ERROR, "change directory "
				      "to '%s' failed: %s",
				      cctx->options->directory,
				      isc_result_totext(result));
			return (result);
		}
	}

	return (ISC_R_SUCCESS);
}


static void
scan_interfaces(ns_server_t *server, isc_boolean_t verbose) {
	ns_interfacemgr_scan(server->interfacemgr, verbose);
	/*
	 * Update the "localhost" and "localnets" ACLs to match the
	 * current set of network interfaces.
	 */
	dns_aclenv_copy(&server->aclenv,
			ns_interfacemgr_getaclenv(server->interfacemgr));
}

/*
 * This event callback is invoked to do periodic network
 * interface scanning.
 */
static void
interface_timer_tick(isc_task_t *task, isc_event_t *event) {
	ns_server_t *server = (ns_server_t *) event->ev_arg;
	UNUSED(task);
	isc_event_free(&event);
	RWLOCK(&server->conflock, isc_rwlocktype_write);
	scan_interfaces(server, ISC_FALSE);
	RWUNLOCK(&server->conflock, isc_rwlocktype_write);
}

static void
heartbeat_timer_tick(isc_task_t *task, isc_event_t *event) {
	ns_server_t *server = (ns_server_t *) event->ev_arg;
	dns_view_t *view;

	UNUSED(task);
	isc_event_free(&event);
	RWLOCK(&server->conflock, isc_rwlocktype_read);
	view = ISC_LIST_HEAD(server->viewlist);
	while (view != NULL) {
		dns_view_dialup(view);
		view = ISC_LIST_NEXT(view, link);
	}
	RWUNLOCK(&server->conflock, isc_rwlocktype_read);
}

static isc_result_t
setstatsfile(ns_server_t *server, const char *name) {
	char *p;

	REQUIRE(name != NULL);

	p = isc_mem_strdup(server->mctx, name);
	if (p == NULL)
		return (ISC_R_NOMEMORY);
	if (server->statsfile != NULL)
		isc_mem_free(server->mctx, server->statsfile);
	server->statsfile = p;
	return (ISC_R_SUCCESS);
}

static isc_result_t
setdumpfile(ns_server_t *server, const char *name) {
	char *p;

	REQUIRE(name != NULL);

	p = isc_mem_strdup(server->mctx, name);
	if (p == NULL)
		return (ISC_R_NOMEMORY);
	if (server->dumpfile != NULL)
		isc_mem_free(server->mctx, server->dumpfile);
	server->dumpfile = p;
	return (ISC_R_SUCCESS);
}

#define SETLIMIT(cfgvar, resource, description) \
	if (dns_c_ctx_get ## cfgvar(cctx, &resource) == ISC_R_SUCCESS) {      \
		if (resource == DNS_C_SIZE_SPEC_DEFAULT)		      \
			value = ns_g_init ## resource;			      \
		else if (resource == DNS_C_SIZE_SPEC_UNLIM)		      \
			value = ISC_RESOURCE_UNLIMITED;			      \
		else							      \
			value = resource;				      \
		result = isc_resource_setlimit(isc_resource_ ## resource,     \
					       value);			      \
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,	      \
			      NS_LOGMODULE_SERVER,			      \
			      result == ISC_R_SUCCESS ?			      \
			      	ISC_LOG_DEBUG(1) : ISC_LOG_WARNING,	      \
			      "set maximum " description " to %"	      \
			      ISC_PRINT_QUADFORMAT "d: %s", value,	      \
			      isc_result_totext(result));		      \
	}

static void
set_limits(dns_c_ctx_t *cctx) {
	isc_uint32_t stacksize;
	isc_uint32_t datasize;
	isc_uint32_t coresize;
	isc_uint32_t openfiles;
	isc_resourcevalue_t value;
	isc_result_t result;

	SETLIMIT(stacksize, stacksize, "stack size");
	SETLIMIT(datasize, datasize, "data size");
	SETLIMIT(coresize, coresize, "core size");
	SETLIMIT(files, openfiles, "open files");
}

static isc_result_t
load_configuration(const char *filename, ns_server_t *server,
		   isc_boolean_t first_time)
{
	isc_result_t result;
	ns_load_t lctx;
	dns_c_cbks_t callbacks;
	dns_c_ctx_t *cctx;
	dns_view_t *view = NULL;
	dns_view_t *view_next;
	dns_viewlist_t tmpviewlist;
	ns_aclconfctx_t aclconfctx;
	dns_dispatch_t *dispatchv4 = NULL;
	dns_dispatch_t *dispatchv6 = NULL;
	char *pidfilename;
	char *statsfilename;
	char *dumpfilename;
	isc_uint32_t interface_interval;
	isc_uint32_t heartbeat_interval;
	in_port_t listen_port;

	ns_aclconfctx_init(&aclconfctx);

	RWLOCK(&server->conflock, isc_rwlocktype_write);
	dns_zonemgr_lockconf(server->zonemgr, isc_rwlocktype_write);

	lctx.mctx = ns_g_mctx;
	lctx.aclconf = &aclconfctx;
	ISC_LIST_INIT(lctx.viewlist);

	callbacks.zonecbk = configure_zone;
	callbacks.zonecbkuap = &lctx;
	callbacks.optscbk = options_callback;
	callbacks.optscbkuap = NULL;

	/*
	 * Parse the configuration file creating a parse tree.  Any
	 * 'zone' statements are handled immediately by calling
	 * configure_zone() through 'callbacks'.
	 */
	cctx = NULL;
	if (ns_g_lwresdonly && lwresd_g_useresolvconf)
		result = ISC_R_FILENOTFOUND;
	else {
		isc_log_write(ns_g_lctx,
			      NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
			      ISC_LOG_INFO, "loading configuration from '%s'",
			      filename);

		result = dns_c_parse_namedconf(filename, ns_g_mctx, &cctx,
					       &callbacks);
	}
	if (result == ISC_R_FILENOTFOUND &&
	    ns_g_lwresdonly && !ns_g_conffileset)
	{
		isc_log_write(ns_g_lctx,
			      NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
			      ISC_LOG_INFO, "loading configuration from '%s'",
			      lwresd_g_resolvconffile);

		result = ns_lwresd_parseresolvconf(ns_g_mctx, &cctx);
	}
	CHECK(result);

	/*
	 * Set process limits, which (usually) needs to be done as root.
	 */
	set_limits(cctx);

	/*
	 * Configure various server options.
	 */
	configure_server_quota(cctx, dns_c_ctx_gettransfersout,
				     &server->xfroutquota, 10);
	configure_server_quota(cctx, dns_c_ctx_gettcpclients,
				     &server->tcpquota, 100);
	configure_server_quota(cctx, dns_c_ctx_getrecursiveclients,
				     &server->recursionquota, 1000);

	CHECK(configure_view_acl(NULL, cctx, &aclconfctx, ns_g_mctx, NULL,
				 dns_c_ctx_getblackhole,
				 &server->blackholeacl));
	if (server->blackholeacl != NULL)
		dns_dispatchmgr_setblackhole(ns_g_dispatchmgr,
					     server->blackholeacl);

	/* dns_loadmgr_setlimit(server->loadmgr, 20); XXXMPA */

	/*
	 * Configure the zone manager.
	 */
	{
 		isc_uint32_t transfersin = 10;
		(void)dns_c_ctx_gettransfersin(cctx, &transfersin);
		dns_zonemgr_settransfersin(server->zonemgr, transfersin);
	}
	{
 		isc_uint32_t transfersperns = 2;
		(void)dns_c_ctx_gettransfersperns(cctx, &transfersperns);
		dns_zonemgr_settransfersperns(server->zonemgr, transfersperns);
	}

	/*
	 * Determine which port to use for listening for incoming connections.
	 */
	if (ns_g_port != 0) {
		listen_port = ns_g_port;
	} else {
		result = dns_c_ctx_getport(cctx, &listen_port);
		if (result != ISC_R_SUCCESS)
			listen_port = 53;
	}
	/*
	 * Configure the interface manager according to the "listen-on"
	 * statement.
	 */
	{
		dns_c_lstnlist_t *clistenon = NULL;
		ns_listenlist_t *listenon = NULL;

		(void)dns_c_ctx_getlistenlist(cctx, &clistenon);
		if (clistenon != NULL) {
			result = ns_listenlist_fromconfig(clistenon,
							  cctx,
							  &aclconfctx,
							  ns_g_mctx,
							  &listenon);
		} else if (!ns_g_lwresdonly) {
			/*
			 * Not specified, use default.
			 */
			CHECK(ns_listenlist_default(ns_g_mctx, listen_port,
						    ISC_TRUE, &listenon));
		}
		if (listenon != NULL) {
			ns_interfacemgr_setlistenon4(server->interfacemgr,
						     listenon);
			ns_listenlist_detach(&listenon);
		}
	}
	/*
	 * Ditto for IPv6.
	 */
	{
		dns_c_lstnlist_t *clistenon = NULL;
		ns_listenlist_t *listenon = NULL;

		(void)dns_c_ctx_getv6listenlist(cctx, &clistenon);
		if (clistenon != NULL) {
			result = ns_listenlist_fromconfig(clistenon,
							  cctx,
							  &aclconfctx,
							  ns_g_mctx,
							  &listenon);
		} else if (!ns_g_lwresdonly) {
			/*
			 * Not specified, use default.
			 */
			CHECK(ns_listenlist_default(ns_g_mctx, listen_port,
						    ISC_FALSE, &listenon));
		}
		if (listenon != NULL) {
			ns_interfacemgr_setlistenon6(server->interfacemgr,
						     listenon);
			ns_listenlist_detach(&listenon);
		}
	}

	/*
	 * Rescan the interface list to pick up changes in the
	 * listen-on option.  It's important that we do this before we try
	 * to configure the query source, since the dispatcher we use might
	 * be shared with an interface.
	 */
	scan_interfaces(server, ISC_TRUE);

	/*
	 * Arrange for further interface scanning to occur periodically
	 * as specified by the "interface-interval" option.
	 */
	interface_interval = 3600; /* Default is 1 hour. */
	(void)dns_c_ctx_getinterfaceinterval(cctx, &interface_interval);
	if (interface_interval == 0) {
		isc_timer_reset(server->interface_timer,
				isc_timertype_inactive,
				NULL, NULL, ISC_TRUE);
	} else {
		isc_interval_t interval;
		isc_interval_set(&interval, interface_interval, 0);
		isc_timer_reset(server->interface_timer, isc_timertype_ticker,
				NULL, &interval, ISC_FALSE);
	}

	/*
	 * Configure the dialup heartbeat timer.
	 */
	heartbeat_interval = 3600; /* Default is 1 hour. */
	(void)dns_c_ctx_getheartbeatinterval(cctx, &heartbeat_interval);

	if (heartbeat_interval == 0) {
		isc_timer_reset(server->heartbeat_timer,
				isc_timertype_inactive,
				NULL, NULL, ISC_TRUE);
	} else {
		isc_interval_t interval;
		isc_interval_set(&interval, heartbeat_interval, 0);
		isc_timer_reset(server->heartbeat_timer, isc_timertype_ticker,
				NULL, &interval, ISC_FALSE);
	}

	/*
	 * Configure and freeze all explicit views.  Explicit
	 * views that have zones were already created at parsing
	 * time, but views with no zones must be created here.
	 */
	if (cctx->views != NULL) {
		dns_c_view_t *cview;
		for (cview = ISC_LIST_HEAD(cctx->views->views);
		     cview != NULL;
		     cview = ISC_LIST_NEXT(cview, next))
		{
			view = NULL;
			CHECK(find_or_create_view(cview,
						  &lctx.viewlist, &view));
			INSIST(view != NULL);
			CHECK(configure_view(view, cctx, cview, ns_g_mctx,
					     &aclconfctx));
			dns_view_freeze(view);
			dns_view_detach(&view);
		}
	}
	INSIST(view == NULL);

	/*
	 * Make sure we have a default view if and only if there
	 * were no explicit views.
	 */
	if (cctx->views == NULL || ISC_LIST_EMPTY(cctx->views->views)) {
		/*
		 * No explicit views; there ought to be a default view.
		 * There may already be one created as a side effect
		 * of zone statements, or we may have to create one.
		 * In either case, we need to configure and freeze it.
		 */
		CHECK(find_or_create_view(NULL, &lctx.viewlist, &view));
		CHECK(configure_view(view, cctx, NULL,
				     ns_g_mctx, &aclconfctx));
		dns_view_freeze(view);
		dns_view_detach(&view);
	} else {
		/*
		 * There are explicit views.  There should not be
		 * a default view.  If there is one, complain.
		 */
		result = dns_viewlist_find(&lctx.viewlist, "_default",
					   dns_rdataclass_in, &view);
		if (result == ISC_R_SUCCESS) {
			dns_view_detach(&view);
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				      "when using 'view' statements, "
				      "all zones must be in views");
			result = ISC_R_FAILURE;
			goto cleanup;
		}
	}

	/*
	 * Create (or recreate) the internal _bind view.
	 */
	CHECK(create_bind_view(&view));
	ISC_LIST_APPEND(lctx.viewlist, view, link);
	CHECK(create_version_zone(cctx, server->zonemgr, view));
	CHECK(create_authors_zone(server->zonemgr, view));
	dns_view_freeze(view);
	view = NULL;

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
		dns_tkeyctx_t *t = NULL;
		CHECKM(ns_tkeyctx_fromconfig(cctx, ns_g_mctx, ns_g_entropy,
					      &t),
		       "configuring TKEY");
		if (server->tkeyctx != NULL)
			dns_tkeyctx_destroy(&server->tkeyctx);
		server->tkeyctx = t;
	}

	/*
	 * Bind the OMAPI port(s).
	 */
	CHECKM(ns_omapi_configure(ns_g_mctx, cctx, &aclconfctx),
	       "binding control channel(s)");

	/*
	 * Bind the lwresd port(s).
	 */
	CHECKM(ns_lwresd_configure(ns_g_mctx, cctx),
	       "binding lightweight resolver ports");

	/*
	 * Relinquish root privileges.
	 */
	if (first_time)
		ns_os_changeuser();

	/*
	 * Configure the logging system.
	 *
	 * Do this after changing UID to make sure that any log
	 * files specified in named.conf get created by the
	 * unprivileged user, not root.
	 */
	if (ns_g_logstderr) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			      "ignoring config file logging "
			      "statement due to -g option");
	} else {
		dns_c_logginglist_t *clog = NULL;
		isc_logconfig_t *logc = NULL;

		CHECKM(isc_logconfig_create(ns_g_lctx, &logc),
		       "creating new logging configuration");

		(void)dns_c_ctx_getlogging(cctx, &clog);
		if (clog != NULL) {
			CHECKM(ns_log_configure(logc, clog),
			       "configuring logging");
		} else {
			CHECKM(ns_log_setdefaultchannels(logc),
			       "setting up default logging channels");
			CHECKM(ns_log_setdefaultcategory(logc),
			       "setting up default 'category default'");
		}

		result = isc_logconfig_use(ns_g_lctx, logc);
		if (result != ISC_R_SUCCESS) {
			isc_logconfig_destroy(&logc);
			CHECKM(result, "installing logging configuration");
		}

		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_DEBUG(1),
			      "now using logging configuration from "
			      "config file");
	}

	/*
	 * Set the default value of the query logging flag depending
	 * whether a "queries" category has been defined.  This is
	 * a disgusting hack, but we need to do this for BIND 8
	 * compatibility.
	 */
	if (first_time) {
		dns_c_logginglist_t *clog = NULL;		
		dns_c_logcat_t *ccat;
		(void)dns_c_ctx_getlogging(cctx, &clog);
		for (ccat = ISC_LIST_HEAD(clog->categories);
		     ccat != NULL;
		     ccat = ISC_LIST_NEXT(ccat, next)) {
			if (strcmp(ccat->catname, "queries") == 0)
				server->log_queries = ISC_TRUE;
		}
	}

	if (dns_c_ctx_getpidfilename(cctx, &pidfilename) != ISC_R_NOTFOUND)
		ns_os_writepidfile(pidfilename);
	else if (ns_g_lwresdonly)
		ns_os_writepidfile(lwresd_g_defaultpidfile);
	else
		ns_os_writepidfile(ns_g_defaultpidfile);

	result = dns_c_ctx_getstatsfilename(cctx, &statsfilename);
	if (result == ISC_R_NOTFOUND) {
		CHECKM(setstatsfile(server, "named.stats"), "strdup");
	} else {
		CHECKM(setstatsfile(server, statsfilename), "strdup");		
	}

	result = dns_c_ctx_getdumpfilename(cctx, &dumpfilename);
	if (result == ISC_R_NOTFOUND) {
		CHECKM(setdumpfile(server, "named_dump.db"), "strdup");
	} else {
		CHECKM(setdumpfile(server, dumpfilename), "strdup");		
	}

 cleanup:
	ns_aclconfctx_destroy(&aclconfctx);

	if (cctx != NULL)
		dns_c_ctx_delete(&cctx);

	if (view != NULL)
		dns_view_detach(&view);

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

	if (dispatchv4 != NULL)
		dns_dispatch_detach(&dispatchv4);
	if (dispatchv6 != NULL)
		dns_dispatch_detach(&dispatchv6);

	dns_zonemgr_unlockconf(server->zonemgr, isc_rwlocktype_write);
	RWUNLOCK(&server->conflock, isc_rwlocktype_write);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_DEBUG(1), "load_configuration: %s",
		      isc_result_totext(result));

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
	ns_server_t *server = (ns_server_t *)event->ev_arg;

	UNUSED(task);

	isc_event_free(&event);

	CHECKFATAL(dns_dispatchmgr_create(ns_g_mctx, ns_g_entropy,
					  &ns_g_dispatchmgr),
		   "creating dispatch manager");

	CHECKFATAL(ns_interfacemgr_create(ns_g_mctx, ns_g_taskmgr,
					  ns_g_socketmgr, ns_g_dispatchmgr,
					  &server->interfacemgr),
		   "creating interface manager");

	CHECKFATAL(isc_timer_create(ns_g_timermgr, isc_timertype_inactive,
				    NULL, NULL, server->task,
				    interface_timer_tick,
				    server, &server->interface_timer),
		   "creating interface timer");

	CHECKFATAL(isc_timer_create(ns_g_timermgr, isc_timertype_inactive,
				    NULL, NULL, server->task,
				    heartbeat_timer_tick,
				    server, &server->heartbeat_timer),
		   "creating heartbeat timer");

	if (ns_g_lwresdonly)
		CHECKFATAL(load_configuration(lwresd_g_conffile, server,
					      ISC_TRUE),
			   "loading configuration");
	else
		CHECKFATAL(load_configuration(ns_g_conffile, server, ISC_TRUE),
			   "loading configuration");

	CHECKFATAL(load_zones(server, ISC_FALSE),
		   "loading zones");

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "running");
}

void 
ns_server_flushonshutdown(ns_server_t *server, isc_boolean_t flush) {

	REQUIRE(NS_SERVER_VALID(server));

	server->flushonshutdown = flush;
}

static void
shutdown_server(isc_task_t *task, isc_event_t *event) {
	dns_view_t *view, *view_next;
	ns_server_t *server = (ns_server_t *)event->ev_arg;
	isc_boolean_t flush = server->flushonshutdown;

	UNUSED(task);

	RWLOCK(&server->conflock, isc_rwlocktype_write);

	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_INFO, "shutting down%s",
		      flush ? ": flushing changes" : "");

	for (view = ISC_LIST_HEAD(server->viewlist);
	     view != NULL;
	     view = view_next) {
		view_next = ISC_LIST_NEXT(view, link);
		ISC_LIST_UNLINK(server->viewlist, view, link);
		if (flush)
			dns_view_flushanddetach(&view);
		else
			dns_view_detach(&view);
	}

	isc_timer_detach(&server->interface_timer);
	isc_timer_detach(&server->heartbeat_timer);

	ns_interfacemgr_shutdown(server->interfacemgr);
	ns_interfacemgr_detach(&server->interfacemgr);

	dns_dispatchmgr_destroy(&ns_g_dispatchmgr);

	dns_zonemgr_shutdown(server->zonemgr);

	if (server->blackholeacl != NULL)
		dns_acl_detach(&server->blackholeacl);

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

	result = isc_quota_init(&server->xfroutquota, 10);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	result = isc_quota_init(&server->tcpquota, 10);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	result = isc_quota_init(&server->recursionquota, 100);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	result = dns_aclenv_init(mctx, &server->aclenv);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	/* Initialize server data structures. */
	server->loadmgr = NULL;
	server->zonemgr = NULL;
	server->interfacemgr = NULL;
	ISC_LIST_INIT(server->viewlist);
	server->in_roothints = NULL;
	server->blackholeacl = NULL;

	CHECKFATAL(dns_rootns_create(mctx, dns_rdataclass_in, NULL,
				     &server->in_roothints),
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

	CHECKFATAL(dst_lib_init(ns_g_mctx, ns_g_entropy, ISC_ENTROPY_GOODONLY),
		   "initializing DST");

	server->tkeyctx = NULL;
	CHECKFATAL(dns_tkeyctx_create(ns_g_mctx, ns_g_entropy,
				      &server->tkeyctx),
		   "creating TKEY context");

	/*
	 * Setup the server task, which is responsible for coordinating
	 * startup and shutdown of the server.
	 */
	CHECKFATAL(isc_task_create(ns_g_taskmgr, 0, &server->task),
		   "creating server task");
	isc_task_setname(server->task, "server", server);
	CHECKFATAL(isc_task_onshutdown(server->task, shutdown_server, server),
		   "isc_task_onshutdown");
	CHECKFATAL(isc_app_onrun(ns_g_mctx, server->task, run_server, server),
		   "isc_app_onrun");

	server->interface_timer = NULL;
	server->heartbeat_timer = NULL;

	CHECKFATAL(dns_zonemgr_create(ns_g_mctx, ns_g_taskmgr, ns_g_timermgr,
				      ns_g_socketmgr, &server->zonemgr),
		   "dns_zonemgr_create");
	CHECKFATAL(dns_loadmgr_create(ns_g_mctx, &server->loadmgr),
		   "dns_loadmgr_create");

	server->statsfile = isc_mem_strdup(server->mctx, "named.stats");
	CHECKFATAL(server->statsfile == NULL ? ISC_R_NOMEMORY : ISC_R_SUCCESS,
		   "isc_mem_strdup");
	server->querystats = NULL;
	CHECKFATAL(dns_stats_alloccounters(ns_g_mctx, &server->querystats),
		   "dns_stats_alloccounters");

	server->dumpfile = isc_mem_strdup(server->mctx, "named.dump");
	CHECKFATAL(server->dumpfile == NULL ? ISC_R_NOMEMORY : ISC_R_SUCCESS,
		   "isc_mem_strdup");

	server->flushonshutdown = ISC_FALSE;
	server->log_queries = ISC_FALSE;

	server->magic = NS_SERVER_MAGIC;
	*serverp = server;
}

void
ns_server_destroy(ns_server_t **serverp) {
	ns_server_t *server = *serverp;
	REQUIRE(NS_SERVER_VALID(server));

	dns_stats_freecounters(server->mctx, &server->querystats);
	isc_mem_free(server->mctx, server->statsfile);

	isc_mem_free(server->mctx, server->dumpfile);

	dns_loadmgr_detach(&server->loadmgr);
	dns_zonemgr_detach(&server->zonemgr);

	if (server->tkeyctx != NULL)
		dns_tkeyctx_destroy(&server->tkeyctx);

	dst_lib_destroy();

	isc_event_free(&server->reload_event);

	INSIST(ISC_LIST_EMPTY(server->viewlist));

	dns_db_detach(&server->in_roothints);

	dns_aclenv_destroy(&server->aclenv);

	isc_quota_destroy(&server->recursionquota);
	isc_quota_destroy(&server->tcpquota);
	isc_quota_destroy(&server->xfroutquota);
	isc_rwlock_destroy(&server->conflock);

	server->magic = 0;
	isc_mem_put(server->mctx, server, sizeof(*server));
}

static void
fatal(const char *msg, isc_result_t result) {
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_CRITICAL, "%s: %s", msg,
		      isc_result_totext(result));
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
		      ISC_LOG_CRITICAL, "exiting (due to fatal error)");
	exit(1);
}

static void
ns_server_reload(isc_task_t *task, isc_event_t *event) {
	isc_result_t result;
	ns_server_t *server = (ns_server_t *)event->ev_arg;
	UNUSED(task);

	if (ns_g_lwresdonly)
		result = load_configuration(lwresd_g_conffile, server,
					    ISC_FALSE);
	else
		result = load_configuration(ns_g_conffile, server, ISC_FALSE);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			      NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
			      "reloading configuration failed: %s",
			      isc_result_totext(result));
	}
	result = load_zones(server, ISC_FALSE);
	if (result != ISC_R_SUCCESS) {
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

static char *
next_token(char **stringp, const char *delim) {
	char *res;

	do {
		res = strsep(stringp, delim);
		if (res == NULL)
			break;
	} while (*res == '\0');
	return (res);
}                       

/*
 * Find the zone specified in the control channel command 'args',
 * if any.  If a zone is specified, point '*zonep' at it, otherwise
 * set '*zonep' to NULL.
 */
static isc_result_t
zone_from_args(ns_server_t *server, char *args, dns_zone_t **zonep) {
	char *input, *ptr;
	const char *zonetxt;
	char *classtxt;
	const char *viewtxt = NULL;
	dns_fixedname_t name;
	isc_result_t result;
	isc_buffer_t buf;
	dns_view_t *view = NULL;
	dns_rdataclass_t rdclass;

	REQUIRE(zonep != NULL && *zonep == NULL);

	input = args;

	/* Skip the command name. */
	ptr = next_token(&input, " \t");
	if (ptr == NULL)
		return (ISC_R_UNEXPECTEDEND);

	/* Look for the zone name. */
	zonetxt = next_token(&input, " \t");
	if (zonetxt == NULL) {
		*zonep = NULL;
		return (ISC_R_SUCCESS);
	}

	/* Look for the optional class name. */
	classtxt = next_token(&input, " \t");
	if (classtxt != NULL) {
		/* Look for the optional view name. */
		viewtxt = next_token(&input, " \t");
	}

	isc_buffer_init(&buf, zonetxt, strlen(zonetxt));
	isc_buffer_add(&buf, strlen(zonetxt));
	dns_fixedname_init(&name);
	result = dns_name_fromtext(dns_fixedname_name(&name),
				   &buf, dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS)
		goto fail1;

	if (classtxt != NULL) {
		isc_textregion_t r;
		r.base = classtxt;
		r.length = strlen(classtxt);
		result = dns_rdataclass_fromtext(&rdclass, &r);
		if (result != ISC_R_SUCCESS)
			goto fail1;
	} else {
		rdclass = dns_rdataclass_in;
	}
	
	if (viewtxt == NULL)
		viewtxt = "_default";
	result = dns_viewlist_find(&server->viewlist, viewtxt,
				   rdclass, &view);
	if (result != ISC_R_SUCCESS)
		goto fail1;
	
	result = dns_zt_find(view->zonetable, dns_fixedname_name(&name),
			     0, NULL, zonep);
	if (result != ISC_R_SUCCESS)
		goto fail2;
 fail2:
	dns_view_detach(&view);
 fail1:
	return (result);
}

/*
 * Act on a "reload" command from the command channel.
 */
isc_result_t
ns_server_reloadcommand(ns_server_t *server, char *args) {
	isc_result_t result;
	dns_zone_t *zone = NULL;
	dns_zonetype_t type;
	
	UNUSED(server);
	result = zone_from_args(server, args, &zone);
	if (result != ISC_R_SUCCESS)
		return (result);
	if (zone == NULL) {
		ns_server_reloadwanted(server);
	} else {
		type = dns_zone_gettype(zone);
		if (type == dns_zone_slave || type == dns_zone_stub)
			dns_zone_refresh(zone);
		else
			dns_zone_load(zone);
		dns_zone_detach(&zone);
	}
	return (ISC_R_SUCCESS);
}	

/*
 * Act on a "refresh" command from the command channel.
 */
isc_result_t
ns_server_refreshcommand(ns_server_t *server, char *args) {
	isc_result_t result;
	dns_zone_t *zone = NULL;

	result = zone_from_args(server, args, &zone);
	if (result != ISC_R_SUCCESS)
		return (result);
	if (zone == NULL)
		return (ISC_R_UNEXPECTEDEND);
	
	dns_zone_refresh(zone);
	dns_zone_detach(&zone);

	return (ISC_R_SUCCESS);
}	

isc_result_t
ns_server_togglequerylog(ns_server_t *server) {
	server->log_queries = server->log_queries ? ISC_FALSE : ISC_TRUE;
	
	isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
		      NS_LOGMODULE_SERVER, ISC_LOG_INFO,
		      "query logging is now %s",
		      server->log_queries ? "on" : "off");
	return (ISC_R_SUCCESS);
}

static isc_result_t
ns_listenlist_fromconfig(dns_c_lstnlist_t *clist, dns_c_ctx_t *cctx,
			  ns_aclconfctx_t *actx,
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
		if (result != ISC_R_SUCCESS)
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
			 ns_aclconfctx_t *actx,
			 isc_mem_t *mctx, ns_listenelt_t **target)
{
	isc_result_t result;
	ns_listenelt_t *delt = NULL;
	REQUIRE(target != NULL && *target == NULL);
	result = ns_listenelt_create(mctx, celt->port, NULL, &delt);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = ns_acl_fromconfig(celt->iml, cctx, actx, mctx, &delt->acl);
	if (result != ISC_R_SUCCESS) {
		ns_listenelt_destroy(delt);
		return (result);
	}
	*target = delt;
	return (ISC_R_SUCCESS);
}

isc_result_t
ns_server_dumpstats(ns_server_t *server) {
	isc_result_t result;
	dns_zone_t *zone, *next;
	isc_stdtime_t now;
	FILE *fp = NULL;
	int i;
	int ncounters;

	isc_stdtime_get(&now);

	CHECKM(isc_stdio_open(server->statsfile, "a", &fp),
	       "could not open statistics dump file");
	
	ncounters = dns_stats_ncounters();
	fprintf(fp, "+++ Statistics Dump +++ (%lu)\n", (unsigned long)now);
	
	for (i = 0; i < ncounters; i++)
		fprintf(fp, "%s %" ISC_PRINT_QUADFORMAT "d\n",
			dns_statscounter_names[i],
			server->querystats[i]);
	
	dns_zonemgr_lockconf(server->zonemgr, isc_rwlocktype_read);
	zone = NULL;
	for (result = dns_zone_first(server->zonemgr, &zone);
	     result == ISC_R_SUCCESS;
	     next = NULL, result = dns_zone_next(zone, &next), zone = next)
	{
		isc_uint64_t *zonestats = dns_zone_getstatscounters(zone);
		if (zonestats != NULL) {
			char zonename[DNS_NAME_FORMATSIZE];
			dns_view_t *view;
			char *viewname;
			
			dns_name_format(dns_zone_getorigin(zone),
					zonename, sizeof(zonename));
			view = dns_zone_getview(zone);
			viewname = view->name;
			for (i = 0; i < ncounters; i++) {
				fprintf(fp, "%s %" ISC_PRINT_QUADFORMAT
					"d %s",
					dns_statscounter_names[i],
					zonestats[i],
					zonename);
				if (strcmp(viewname, "_default") != 0)
					fprintf(fp, " %s", viewname);
				fprintf(fp, "\n");
			}
		}
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;
	CHECK(result);
	
	fprintf(fp, "--- Statistics Dump --- (%lu)\n", (unsigned long)now);
	dns_zonemgr_unlockconf(server->zonemgr, isc_rwlocktype_read);

 cleanup:
	if (fp != NULL)
		(void)isc_stdio_close(fp);
	return (result);
}

isc_result_t
ns_server_dumpdb(ns_server_t *server) {
	FILE *fp = NULL;
	dns_view_t *view;
	isc_result_t result;

	CHECKM(isc_stdio_open(server->dumpfile, "w", &fp),
	       "could not open dump file");

	for (view = ISC_LIST_HEAD(server->viewlist);
	     view != NULL;
	     view = ISC_LIST_NEXT(view, link))
	{
		if (view->cachedb != NULL)
			CHECKM(dns_view_dumpdbtostream(view, fp),
			       "could not dump view databases");
	}
 cleanup:
	if (fp != NULL)
		(void)isc_stdio_close(fp);
	return (result);
}
