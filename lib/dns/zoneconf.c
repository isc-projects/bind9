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

/* $Id: zoneconf.c,v 1.43.2.1 2000/07/25 22:47:35 gson Exp $ */

#include <config.h>

#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/zone.h>
#include <dns/zoneconf.h>
#include <dns/ssu.h>

/*
 * These are BIND9 server defaults, not necessarily identical to the
 * library defaults defined in zone.c.
 */
#define MAX_XFER_TIME (2*3600)	/* Documented default is 2 hours. */
#define DNS_DEFAULT_IDLEIN 3600		/* 1 hour */
#define DNS_DEFAULT_IDLEOUT 3600	/* 1 hour */

#define RETERR(x) do { \
	isc_result_t _r = (x); \
	if (_r != ISC_R_SUCCESS) \
		return (_r); \
	} while (0)

/*
 * Convenience function for configuring a single zone ACL.
 */
static isc_result_t
configure_zone_acl(dns_c_zone_t *czone, dns_c_ctx_t *cctx, dns_c_view_t *cview,
		   dns_aclconfctx_t *aclconfctx, dns_zone_t *zone,
		   isc_result_t (*getcacl)(dns_c_zone_t *,
					   dns_c_ipmatchlist_t **),
		   isc_result_t (*getviewcacl)(dns_c_view_t *
					       , dns_c_ipmatchlist_t **),
		   isc_result_t (*getglobalcacl)(dns_c_ctx_t *,
						 dns_c_ipmatchlist_t **),
		   void (*setzacl)(dns_zone_t *, dns_acl_t *),
		   void (*clearzacl)(dns_zone_t *))
{
	isc_result_t result;
	dns_c_ipmatchlist_t *cacl;
	dns_acl_t *dacl = NULL;
	result = (*getcacl)(czone, &cacl);
	if (result == ISC_R_NOTFOUND && getviewcacl != NULL && cview != NULL) {
		result = (*getviewcacl)(cview, &cacl);
	}
	if (result == ISC_R_NOTFOUND && getglobalcacl != NULL) {
		result = (*getglobalcacl)(cctx, &cacl);
	}
	if (result == ISC_R_SUCCESS) {
		result = dns_acl_fromconfig(cacl, cctx, aclconfctx,
					   dns_zone_getmctx(zone), &dacl);
		dns_c_ipmatchlist_detach(&cacl);
		if (result != ISC_R_SUCCESS)
			return (result);
		(*setzacl)(zone, dacl);
		dns_acl_detach(&dacl);
		return (ISC_R_SUCCESS);
	} else if (result == ISC_R_NOTFOUND) {
		(*clearzacl)(zone);
		return (ISC_R_SUCCESS);
	} else {
		return (result);
	}
}

/*
 * Conver a config file zone type into a server zone type.
 */
static dns_zonetype_t
dns_zonetype_fromconf(dns_c_zonetype_t cztype) {
	switch (cztype) {
	case dns_c_zone_master:
		return dns_zone_master;
	case dns_c_zone_slave:
		return dns_zone_slave;
	case dns_c_zone_stub:
		return dns_zone_stub;
	default:
		/*
		 * Hint and forward zones are not really zones;
		 * they should never get this far.
		 */
		INSIST(0);
		return (dns_zone_none); /*NOTREACHED*/
	}
}

isc_result_t
dns_zone_configure(dns_c_ctx_t *cctx, dns_c_view_t *cview, 
		   dns_c_zone_t *czone, dns_aclconfctx_t *ac, 
		   dns_zone_t *zone)
{
	isc_result_t result;
	isc_boolean_t boolean;
	const char *filename = NULL;
#ifdef notyet
	dns_c_severity_t severity;
#endif
	dns_c_iplist_t *iplist;
	isc_sockaddr_t sockaddr;
	isc_uint32_t uintval;
	isc_sockaddr_t sockaddr_any4, sockaddr_any6;
	dns_ssutable_t *ssutable = NULL;

	isc_sockaddr_any(&sockaddr_any4);	
	isc_sockaddr_any6(&sockaddr_any6);
	
	/*
	 * Configure values common to all zone types.
	 */

	dns_zone_setclass(zone, czone->zclass);

	dns_zone_settype(zone, dns_zonetype_fromconf(czone->ztype));

	/* XXX needs to be an zone option */
	RETERR(dns_zone_setdbtype(zone, "rbt"));

	result = dns_c_zone_getfile(czone, &filename);
	if (result == ISC_R_SUCCESS)
		RETERR(dns_zone_setdatabase(zone, filename));
	else if (czone->ztype != dns_c_zone_slave &&
		 czone->ztype != dns_c_zone_stub)
		return (result);

#ifdef notyet
	result = dns_c_zone_getchecknames(czone, &severity);
	if (result == ISC_R_SUCCESS)
		dns_zone_setchecknames(zone, severity);
	else
		dns_zone_setchecknames(zone, dns_c_severity_warn);
#endif

	/*
	 * XXXAG This probably does not make sense for stubs.
	 */
	RETERR(configure_zone_acl(czone, cctx, cview, ac, zone,
				  dns_c_zone_getallowquery,
				  dns_c_view_getallowquery,
				  dns_c_ctx_getallowquery,
				  dns_zone_setqueryacl,
				  dns_zone_clearqueryacl));

	result = dns_c_zone_getdialup(czone, &boolean);
	if (result != ISC_R_SUCCESS)
		result = dns_c_ctx_getdialup(cctx, &boolean);
	if (result != ISC_R_SUCCESS)
		boolean = ISC_FALSE;
	dns_zone_setoption(zone, DNS_ZONEOPT_DIALUP, boolean);

	/*
	 * Configure master functionality.  This applies
	 * to primary masters (type "master") and slaves
	 * acting as masters (type "slave"), but not to stubs.
	 */
	if (czone->ztype != dns_c_zone_stub) {
		result = dns_c_zone_getnotify(czone, &boolean);
		if (result != ISC_R_SUCCESS && cview != NULL)
			result = dns_c_view_getnotify(cview, &boolean);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getnotify(cctx, &boolean);
		if (result != ISC_R_SUCCESS)
			boolean = ISC_TRUE;
		dns_zone_setoption(zone, DNS_ZONEOPT_NOTIFY, boolean);

		iplist = NULL;
		result = dns_c_zone_getalsonotify(czone, &iplist);
		if (result != ISC_R_SUCCESS && cview != NULL)
			result = dns_c_view_getalsonotify(cview, &iplist);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getalsonotify(cctx, &iplist);
		if (result == ISC_R_SUCCESS) {
			result = dns_zone_setalsonotify(zone, iplist->ips,
						        iplist->nextidx);
			dns_c_iplist_detach(&iplist);
			if (result != ISC_R_SUCCESS)
				return (result);

		} else
			RETERR(dns_zone_setalsonotify(zone, NULL, 0));
		
		RETERR(configure_zone_acl(czone, cctx, cview, ac, zone,
					  dns_c_zone_getallowtransfer,
					  dns_c_view_gettransferacl,
					  dns_c_ctx_getallowtransfer,
					  dns_zone_setxfracl,
					  dns_zone_clearxfracl));

		result = dns_c_zone_getmaxtranstimeout(czone, &uintval);
		if (result != ISC_R_SUCCESS && cview != NULL)
			result = dns_c_view_getmaxtransfertimeout(cview,
								  &uintval);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getmaxtransfertimeout(cctx,
								 &uintval);
		if (result != ISC_R_SUCCESS)
			uintval = MAX_XFER_TIME;
		dns_zone_setmaxxfrout(zone, uintval);

		result = dns_c_zone_getmaxtransidleout(czone, &uintval);
		if (result != ISC_R_SUCCESS && cview != NULL) 
			result = dns_c_view_getmaxtransferidleout(cview,
								  &uintval);
		if (result != ISC_R_SUCCESS) 
			result = dns_c_ctx_getmaxtransferidleout(cctx,
								 &uintval);
		if (result != ISC_R_SUCCESS)
			uintval = DNS_DEFAULT_IDLEOUT;
		dns_zone_setidleout(zone, uintval);
	}

	/*
	 * Configure update-related options.  These apply to
	 * primary masters only.
	 */
	if (czone->ztype == dns_c_zone_master) {
		RETERR(configure_zone_acl(czone, cctx, NULL, ac, zone,
					  dns_c_zone_getallowupd,
					  NULL, NULL,
					  dns_zone_setupdateacl,
					  dns_zone_clearupdateacl));

		dns_zone_getssutable(zone, &ssutable);
		if (ssutable != NULL)
			dns_ssutable_detach(&ssutable);
		result = dns_c_zone_getssuauth(czone, &ssutable);
		if (result == ISC_R_SUCCESS) {
			dns_ssutable_t *newssutable = NULL;
			dns_ssutable_attach(ssutable, &newssutable);
			dns_zone_setssutable(zone, newssutable);
		}

		result = dns_c_zone_getsigvalidityinterval(czone, &uintval);
		if (result != ISC_R_SUCCESS && cview != NULL)
			result = dns_c_view_getsigvalidityinterval(cview,
								  &uintval);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_getsigvalidityinterval(cctx,
								 &uintval);
		if (result != ISC_R_SUCCESS)
			uintval = 30 * 24 * 3600;
		dns_zone_setsigvalidityinterval(zone, uintval);
	}

	/*
	 * Configure slave functionality.
	 */
	switch (czone->ztype) {
	case dns_c_zone_slave:
	case dns_c_zone_stub:
		iplist = NULL;
		result = dns_c_zone_getmasterips(czone, &iplist);
		if (result == ISC_R_SUCCESS)
			result = dns_zone_setmasters(zone, iplist->ips,
						     iplist->nextidx);
		else
			result = dns_zone_setmasters(zone, NULL, 0);
		RETERR(result);

		result = dns_c_zone_getmaxtranstimein(czone, &uintval);
		if (result != ISC_R_SUCCESS) 
			result = dns_c_ctx_getmaxtransfertimein(cctx, &uintval);
		if (result != ISC_R_SUCCESS)
			uintval = MAX_XFER_TIME;
		dns_zone_setmaxxfrin(zone, uintval);

		result = dns_c_zone_getmaxtransidlein(czone, &uintval);
		if (result != ISC_R_SUCCESS) 
			result = dns_c_ctx_getmaxtransferidlein(cctx,
								&uintval);
		if (result != ISC_R_SUCCESS)
			uintval = DNS_DEFAULT_IDLEIN;
		dns_zone_setidlein(zone, uintval);

		result = dns_c_zone_gettransfersource(czone, &sockaddr);
		if (result != ISC_R_SUCCESS && cview != NULL)
			result = dns_c_view_gettransfersource(cview,
							      &sockaddr);
		if (result != ISC_R_SUCCESS)
			result = dns_c_ctx_gettransfersource(cctx, &sockaddr);
		if (result != ISC_R_SUCCESS)
			sockaddr = sockaddr_any4;
		dns_zone_setxfrsource4(zone, &sockaddr);

		result = dns_c_zone_gettransfersourcev6(czone, &sockaddr);
		if (result != ISC_R_SUCCESS && cview != NULL) 
			result = dns_c_view_gettransfersourcev6(cview,
								&sockaddr);
		if (result != ISC_R_SUCCESS) 
			result = dns_c_ctx_gettransfersourcev6(cctx,
							       &sockaddr);
		if (result != ISC_R_SUCCESS)
			sockaddr = sockaddr_any6;
		dns_zone_setxfrsource6(zone, &sockaddr);

		break;
		
	default:
		break;
	}

	return (ISC_R_SUCCESS);
}

isc_boolean_t
dns_zone_reusable(dns_zone_t *zone, dns_c_zone_t *czone) {
	const char *cfilename;
	const char *zfilename;

	if (dns_zonetype_fromconf(czone->ztype) != dns_zone_gettype(zone))
		return (ISC_FALSE);

	cfilename = NULL;
	(void) dns_c_zone_getfile(czone, &cfilename);
	zfilename = dns_zone_getdatabase(zone);
	if (cfilename == NULL || zfilename == NULL ||
	    strcmp(cfilename, zfilename) != 0)
		return (ISC_FALSE);

	return (ISC_TRUE);
}
	
isc_result_t
dns_zonemgr_configure(dns_c_ctx_t *cctx, dns_zonemgr_t *zmgr) {
	isc_uint32_t val;
	isc_result_t result;
	
	result = dns_c_ctx_gettransfersin(cctx, &val);
	if (result != ISC_R_SUCCESS)
		val = 10;
	dns_zonemgr_settransfersin(zmgr, val);

	result = dns_c_ctx_gettransfersperns(cctx, &val);
	if (result != ISC_R_SUCCESS)
		val = 2;
	dns_zonemgr_settransfersperns(zmgr, val);

	return (ISC_R_SUCCESS);
}

