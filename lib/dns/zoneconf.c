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

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>

#include <dns/aclconf.h>
#include <dns/types.h>
#include <dns/zone.h>
#include <dns/zoneconf.h>

/* XXX copied from zone.c */
#define MAX_XFER_TIME (2*3600)	/* Documented default is 2 hours. */
#define DNS_DEFAULT_IDLEIN 3600		/* 1 hour */
#define DNS_DEFAULT_IDLEOUT 3600	/* 1 hour */

/*
 * Convenience function for configuring a single zone ACL.
 */
static isc_result_t
configure_zone_acl(dns_c_zone_t *czone, dns_c_ctx_t *cctx,
		   dns_aclconfctx_t *aclconfctx, dns_zone_t *zone,
		   isc_result_t (*getcacl)(dns_c_zone_t *, dns_c_ipmatchlist_t **),
		   void (*setzacl)(dns_zone_t *, dns_acl_t *),
		   void (*clearzacl)(dns_zone_t *))
{
	isc_result_t result;
	dns_c_ipmatchlist_t *cacl;
	dns_acl_t *dacl = NULL;
	result = (*getcacl)(czone, &cacl);
	if (result == ISC_R_SUCCESS) {
		result = dns_acl_fromconfig(cacl, cctx, aclconfctx,
					   dns_zone_getmctx(zone), &dacl);
		dns_c_ipmatchlist_detach(&cacl);
		if (result != DNS_R_SUCCESS)
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


static dns_zonetype_t
dns_zonetype_fromconf(dns_c_zonetype_t cztype) {
	switch (cztype) {
	case dns_c_zone_master:
		return dns_zone_master;
	case dns_c_zone_forward:
		return dns_zone_forward;
	case dns_c_zone_slave:
		return dns_zone_slave;
	case dns_c_zone_stub:
		return dns_zone_stub;
	case dns_c_zone_hint:
		return dns_zone_hint;
	}
	INSIST(0);
	return (dns_zone_none); /*NOTREACHED*/
}

isc_result_t
dns_zone_configure(dns_c_ctx_t *cctx, dns_aclconfctx_t *ac,
		   dns_c_zone_t *czone, dns_zone_t *zone)
{
	isc_result_t result;
	isc_boolean_t boolean;
	const char *filename = NULL;
#ifdef notyet
	dns_c_severity_t severity;
#endif
	dns_c_iplist_t *iplist = NULL;
	isc_uint32_t i;
	isc_sockaddr_t sockaddr;
	isc_int32_t maxxfr;
	in_port_t port;
	struct in_addr in4addr_any;
	isc_sockaddr_t sockaddr_any4;

	in4addr_any.s_addr = htonl(INADDR_ANY);
	isc_sockaddr_fromin(&sockaddr_any4, &in4addr_any, 0);

	dns_zone_setclass(zone, czone->zclass);

	/* XXX needs to be an zone option */
	result = dns_zone_setdbtype(zone, "rbt");
	if (result != DNS_R_SUCCESS)
		return (result);

	switch (czone->ztype) {
	case dns_c_zone_master:
		dns_zone_settype(zone, dns_zone_master);
		result = dns_c_zone_getfile(czone, &filename);
		if (result != ISC_R_SUCCESS)
			return (result);

		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (result);
#ifdef notyet
		result = dns_c_zone_getchecknames(czone, &severity);
		if (result == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_fail);
#endif
		result = configure_zone_acl(czone, cctx, ac, zone,
					    dns_c_zone_getallowupd,
					    dns_zone_setupdateacl,
					    dns_zone_clearupdateacl);
		if (result != DNS_R_SUCCESS)
			return (result);

		result = configure_zone_acl(czone, cctx, ac, zone,
					    dns_c_zone_getallowquery,
					    dns_zone_setqueryacl,
					    dns_zone_clearqueryacl);
		if (result != DNS_R_SUCCESS)
			return (result);

		result = configure_zone_acl(czone, cctx, ac, zone,
					    dns_c_zone_getallowquery,
					    dns_zone_setqueryacl,
					    dns_zone_clearqueryacl);
		if (result != DNS_R_SUCCESS)
			return (result);

		result = configure_zone_acl(czone, cctx, ac, zone,
					    dns_c_zone_getallowtransfer,
					    dns_zone_setxfracl,
					    dns_zone_clearxfracl);
		if (result != DNS_R_SUCCESS)
			return (result);

		result = dns_c_zone_getdialup(czone, &boolean);
		if (result == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_DIALUP, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_DIALUP);

		result = dns_c_zone_getnotify(czone, &boolean);
		if (result == ISC_R_SUCCESS)  
			dns_zone_setoption(zone, DNS_ZONE_O_NOTIFY, boolean);
		else
			dns_zone_clearoption(zone, DNS_ZONE_O_NOTIFY);

		result = dns_c_zone_getalsonotify(czone, &iplist);
		if (result == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				result = dns_zone_addnotify(zone,
							    &iplist->ips[i]);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else
			dns_zone_clearnotify(zone);

		result = dns_c_zone_getmaxtranstimeout(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransfertimeout(cctx, &maxxfr);
			if (result != DNS_R_SUCCESS)
				maxxfr = MAX_XFER_TIME;
		}
		dns_zone_setmaxxfrout(zone, maxxfr);

		result = dns_c_zone_getmaxtransidleout(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransferidleout(cctx, &maxxfr);
			if (result != DNS_R_SUCCESS)
				maxxfr = DNS_DEFAULT_IDLEOUT;
		}
		dns_zone_setidleout(zone, maxxfr);

		break;
		
		
	case dns_c_zone_forward:
#ifdef notyet
		/*
		 * forward zones are still in a state of flux
		 */
		czone->u.fzone.check_names; /* XXX unused in BIND 8 */
		czone->u.fzone.forward; /* XXX*/
		czone->u.fzone.forwarders; /* XXX*/
#endif
		break;

	case dns_c_zone_slave:
		dns_zone_settype(zone, dns_zone_slave);
		result = dns_c_zone_getfile(czone, &filename);
		if (result != ISC_R_SUCCESS)
			return (result);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (result);
#ifdef notyet
		result = dns_c_zone_getchecknames(czone, &severity);
		if (result == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_warn);
#endif
		result = configure_zone_acl(czone, cctx, ac, zone,
					    dns_c_zone_getallowquery,
					    dns_zone_setqueryacl,
					    dns_zone_clearqueryacl);
		if (result != DNS_R_SUCCESS)
			return (result);

		
		result = dns_c_zone_getmasterport(czone, &port);
		if (result != ISC_R_SUCCESS)
			port = 53;
		dns_zone_setmasterport(zone, port);

		result = dns_c_zone_getmasterips(czone, &iplist);
		if (result == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				result = dns_zone_addmaster(zone,
							    &iplist->ips[i]);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else 
			dns_zone_clearmasters(zone);

		result = dns_c_zone_getmaxtranstimein(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransfertimein(cctx, &maxxfr);
			if (result != ISC_R_SUCCESS)
				maxxfr = MAX_XFER_TIME;
		}
		dns_zone_setmaxxfrin(zone, maxxfr);

		result = dns_c_zone_getmaxtransidlein(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransferidlein(cctx, &maxxfr);
			if (result != ISC_R_SUCCESS)
				maxxfr = DNS_DEFAULT_IDLEIN;
		}
		dns_zone_setidlein(zone, maxxfr);

		result = dns_c_zone_gettransfersource(czone, &sockaddr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_gettransfersource(cctx, &sockaddr);
			if (result != ISC_R_SUCCESS) {
				sockaddr = sockaddr_any4;
			}
		}
		dns_zone_setxfrsource4(zone, &sockaddr);

		result = dns_c_zone_getmaxtranstimeout(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransfertimeout(cctx, &maxxfr);
			if (result != DNS_R_SUCCESS)
				maxxfr = MAX_XFER_TIME;
		}
		dns_zone_setmaxxfrout(zone, maxxfr);

		result = dns_c_zone_getmaxtransidleout(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransferidleout(cctx, &maxxfr);
			if (result != DNS_R_SUCCESS)
				maxxfr = DNS_DEFAULT_IDLEOUT;
		}
		dns_zone_setidleout(zone, maxxfr);

		break;

	case dns_c_zone_stub:
		dns_zone_settype(zone, dns_zone_stub);
		result = dns_c_zone_getfile(czone, &filename);
		if (result != ISC_R_SUCCESS)
			return (result);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (result);
#ifdef notyet
		result = dns_c_zone_getchecknames(czone, &severity);
		if (result == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_warn);
#endif
		result = configure_zone_acl(czone, cctx, ac, zone,
					    dns_c_zone_getallowquery,
					    dns_zone_setqueryacl,
					    dns_zone_clearqueryacl);
		if (result != DNS_R_SUCCESS)
			return (result);

		result = dns_c_zone_getmasterport(czone, &port);
		if (result != ISC_R_SUCCESS)
			port = 53;
		dns_zone_setmasterport(zone, port);

		result = dns_c_zone_getmasterips(czone, &iplist);
		if (result == ISC_R_SUCCESS) {
			for (i = 0; i < iplist->nextidx; i++) {
				result = dns_zone_addmaster(zone,
							    &iplist->ips[i]);
				if (result != DNS_R_SUCCESS)
					return (result);
			}
		} else 
			dns_zone_clearmasters(zone);

		result = dns_c_zone_getmaxtranstimein(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransfertimein(cctx, &maxxfr);
			if (result != ISC_R_SUCCESS)
				maxxfr = MAX_XFER_TIME;
		}
		dns_zone_setmaxxfrin(zone, maxxfr);

		result = dns_c_zone_getmaxtransidlein(czone, &maxxfr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_getmaxtransferidlein(cctx, &maxxfr);
			if (result != ISC_R_SUCCESS)
				maxxfr = DNS_DEFAULT_IDLEIN;
		}
		dns_zone_setidlein(zone, maxxfr);

		result = dns_c_zone_gettransfersource(czone, &sockaddr);
		if (result != ISC_R_SUCCESS) {
			result = dns_c_ctx_gettransfersource(cctx, &sockaddr);
			if (result != ISC_R_SUCCESS) {
				sockaddr = sockaddr_any4;
			}
		}
		dns_zone_setxfrsource4(zone, &sockaddr);

	case dns_c_zone_hint:
		dns_zone_settype(zone, dns_zone_hint);
		result = dns_c_zone_getfile(czone, &filename);
		if (result != ISC_R_SUCCESS)
			return (result);
		result = dns_zone_setdatabase(zone, filename);
		if (result != DNS_R_SUCCESS)
			return (result);
#ifdef notyet
		result = dns_c_zone_getchecknames(czone, &severity);
		if (result == ISC_R_SUCCESS)
			dns_zone_setchecknames(zone, severity);
		else
			dns_zone_setchecknames(zone, dns_c_severity_fail);
#endif
		break;

	}

	return (DNS_R_SUCCESS);
}

isc_boolean_t
dns_zone_reusable(dns_zone_t *zone, dns_c_zone_t *czone)
{
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

	/* XXX Compare masters, too. */

	return (ISC_TRUE);
}
	
isc_result_t
dns_zonemgr_configure(dns_c_ctx_t *cctx, dns_zonemgr_t *zmgr)
{
	isc_int32_t val;
	isc_result_t result;
	
	result = dns_c_ctx_gettransfersin(cctx, &val);
	if (result != DNS_R_SUCCESS)
		val = 10;
	dns_zonemgr_settransfersin(zmgr, val);

	return (ISC_R_SUCCESS);
}

