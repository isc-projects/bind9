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

/* $Id: config.c,v 1.2 2001/03/04 22:28:32 bwelling Exp $ */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/util.h>

#include <isccfg/cfg.h>

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/zone.h>

#include <named/config.h>
#include <named/globals.h>

static char defaultconf[] = "
options {
#	blackhole {none;};
	coresize default;
	datasize default;
	deallocate-on-exit true;
#	directory <none>
	dump-file \"named_dump.db\";
	fake-iquery no;
	files default;
	has-old-clients false;
	heartbeat-interval 3600;
	host-statistics no;
	interface-interval 3600;
	listen-on {any;};
	listen-on-v6 {none;};
	memstatistics-file \"named.memstats\";
	multiple-cnames no;
#	named-xfer <obsolete>
#	pid-file \"" NS_LOCALSTATEDIR "/named.pid\"; /* or /lwresd.pid */
	port 53;
"
#ifdef PATH_RANDOMDEV
"
	random-device \"" PATH_RANDOMDEV "\";
"
#endif
"
	recursive-clients 1000;
	rrset-order {order cyclic;};
	serial-queries 20;
	stacksize default;
	statistics-file \"named.stats\";
	statistics-interval 3600;
	tcp-clients 100;
#	tkey-dhkey <none>
#	tkey-gssapi-credential <none>
#	tkey-domain <none>
	transfers-per-ns 2;
	transfers-in 10;
	transfers-out 10;
	treat-cr-as-space true;
	use-id-pool true;
	use-ixfr true;
	version \""VERSION"\";

	/* view */
	allow-notify {none;};
	allow-update-forwarding {none;};
	allow-recursion {any;};
	allow-v6-synthesis {none;};
#	sortlist <none>
#	topology <none>
	auth-nxdomain false;
	recursion true;
	provide-ixfr true;
	request-ixfr true;
	fetch-glue no;
	rfc2308-type1 no;
	additional-from-auth true;
	additional-from-cache true;
	query-source address *;
	query-source-v6 address *;
	notify-source *;
	notify-source-v6 *;
	cleaning-interval 3600;
	min-roots 2;
	lame-ttl 600;
	max-ncache-ttl 10800; /* 3 hours */
	max-cache-ttl 604800; /* 1 week */
	transfer-format many-answers;
	max-cache-size 0;
	check-names master ignore;
	check-names slave ignore;
	check-names response ignore;

	/* zone */
	allow-query {any;};
	allow-transfer {any;};
	notify yes;
#	also-notify <none>
	dialup no;
#	forward <none>
#	forwarders <none>
	maintain-ixfr-base no;
#	max-ixfr-log-size <obsolete>
	transfer-source *;
	transfer-source-v6 *;
	max-transfer-time-in 7200;
	max-transfer-time-out 7200;
	max-transfer-idle-in 3600;
	max-transfer-idle-out 3600;
	max-retry-time 1209600; /* 2 weeks */
	min-retry-time 500;
	max-refresh-time 2419200; /* 4 weeks */
	min-refresh-time 300;
	sig-validity-interval 30; /* days */
	zone-statistics false;
};";

isc_result_t
ns_config_parsedefaults(cfg_parser_t *parser, cfg_obj_t **conf) {
	isc_buffer_t b;

	isc_buffer_init(&b, defaultconf, sizeof(defaultconf) - 1);
	isc_buffer_add(&b, sizeof(defaultconf) - 1);
	return (cfg_parse_buffer(parser, &b, &cfg_type_namedconf, conf));
}

isc_result_t
ns_config_get(cfg_obj_t **maps, const char* name, cfg_obj_t **obj) {
	int i;

	for (i = 0; ; i++) {
		if (maps[i] == NULL)
			return (ISC_R_NOTFOUND);
		if (cfg_map_get(maps[i], name, obj) == ISC_R_SUCCESS)
			return (ISC_R_SUCCESS);
	}
}

int
ns_config_listcount(cfg_obj_t *list) {
	cfg_listelt_t *e;
	int i = 0;

	for (e = cfg_list_first(list); e != NULL; e = cfg_list_next(e))
		i++;

	return (i);
}

isc_result_t
ns_config_getclass(cfg_obj_t *classobj, dns_rdataclass_t *classp) {
	char *str;
	isc_textregion_t r;

	if (!cfg_obj_isstring(classobj)) {
		*classp = dns_rdataclass_in;
		return (ISC_R_SUCCESS);
	}
	str = cfg_obj_asstring(classobj);
	r.base = str;
	r.length = strlen(str);
	return (dns_rdataclass_fromtext(classp, &r));
}

isc_result_t
ns_config_getzonetype(cfg_obj_t *zonetypeobj) {
	dns_zonetype_t ztype;
	char *str;

	str = cfg_obj_asstring(zonetypeobj);
	if (strcmp(str, "master") == 0)
		ztype = dns_zone_master;
	else if (strcmp(str, "slave") == 0)
		ztype = dns_zone_slave;
	else if (strcmp(str, "stub") == 0)
		ztype = dns_zone_stub;
	else
		INSIST(0);
	return (ztype);
}

isc_result_t
ns_config_getiplist(cfg_obj_t *config, cfg_obj_t *list,
		    in_port_t defport, isc_mem_t *mctx,
		    isc_sockaddr_t **addrsp, isc_uint32_t *countp)
{
	int count, i = 0;
	cfg_obj_t *addrlist;
	cfg_obj_t *portobj;
	cfg_listelt_t *element;
	isc_sockaddr_t *addrs;
	in_port_t port;
	isc_result_t result;

	INSIST(addrsp != NULL && *addrsp == NULL);

	addrlist = cfg_tuple_get(list, "addresses");
	count = ns_config_listcount(addrlist);

	portobj = cfg_tuple_get(list, "port");
	if (cfg_obj_isuint32(portobj)) {
		isc_uint32_t val = cfg_obj_asuint32(portobj);
		if (val > ISC_UINT16_MAX) {
			cfg_obj_log(portobj, ns_g_lctx, ISC_LOG_ERROR,
				    "port '%u' out of range", val);
			return (ISC_R_RANGE);
		}
		port = (in_port_t) val;
	} else if (defport != 0)
		port = defport;
	else {
		result = ns_config_getport(config, &port);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	addrs = isc_mem_get(mctx, count * sizeof(isc_sockaddr_t));
	if (addrs == NULL)
		return (ISC_R_NOMEMORY);

	for (element = cfg_list_first(addrlist);
	     element != NULL;
	     element = cfg_list_next(element), i++)
	{
		INSIST(i < count);
		addrs[i] = *cfg_obj_assockaddr(cfg_listelt_value(element));
		if (isc_sockaddr_getport(&addrs[i]) == 0)
			isc_sockaddr_setport(&addrs[i], port);
	}
	INSIST(i == count);

	*addrsp = addrs;
	*countp = count;

	return (ISC_R_SUCCESS);
}

void
ns_config_putiplist(isc_mem_t *mctx, isc_sockaddr_t **addrsp,
		    isc_uint32_t count)
{
	INSIST(addrsp != NULL && *addrsp != NULL);

	isc_mem_put(mctx, *addrsp, count * sizeof(isc_sockaddr_t));
	*addrsp = NULL;
}

isc_result_t
ns_config_getipandkeylist(cfg_obj_t *config, cfg_obj_t *list, isc_mem_t *mctx,
			  isc_sockaddr_t **addrsp, dns_name_t ***keysp,
			  isc_uint32_t *countp)
{
	isc_uint32_t count, i = 0;
	isc_result_t result;
	cfg_listelt_t *element;
	cfg_obj_t *addrlist;
	cfg_obj_t *portobj;
	in_port_t port;
	dns_fixedname_t fname;
	isc_sockaddr_t *addrs = NULL;
	dns_name_t **keys = NULL;

	INSIST(addrsp != NULL && *addrsp == NULL);

	addrlist = cfg_tuple_get(list, "addresses");
	count = ns_config_listcount(addrlist);

	portobj = cfg_tuple_get(list, "port");
	if (cfg_obj_isuint32(portobj)) {
		isc_uint32_t val = cfg_obj_asuint32(portobj);
		if (val > ISC_UINT16_MAX) {
			cfg_obj_log(portobj, ns_g_lctx, ISC_LOG_ERROR,
				    "port '%u' out of range", val);
			return (ISC_R_RANGE);
		}
		port = (in_port_t) val;
	} else {
		result = ns_config_getport(config, &port);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	result = ISC_R_NOMEMORY;

	addrs = isc_mem_get(mctx, count * sizeof(isc_sockaddr_t));
	if (addrs == NULL)
		goto cleanup;

	keys = isc_mem_get(mctx, count * sizeof(dns_name_t *));
	if (keys == NULL)
		goto cleanup;

	for (element = cfg_list_first(addrlist);
	     element != NULL;
	     element = cfg_list_next(element), i++)
	{
		cfg_obj_t *addr;
		cfg_obj_t *key;
		char *keystr;
		isc_buffer_t b;

		INSIST(i < count);

		addr = cfg_tuple_get(cfg_listelt_value(element), "sockaddr");
		key = cfg_tuple_get(cfg_listelt_value(element), "key");

		addrs[i] = *cfg_obj_assockaddr(addr);
		if (isc_sockaddr_getport(&addrs[i]) == 0)
			isc_sockaddr_setport(&addrs[i], port);

		keys[i] = NULL;
		if (!cfg_obj_isstring(key))
			continue;
		keys[i] = isc_mem_get(mctx, sizeof(dns_name_t));
		if (keys[i] == NULL)
			goto cleanup;
		dns_name_init(keys[i], NULL);
		
		keystr = cfg_obj_asstring(key);
		isc_buffer_init(&b, keystr, strlen(keystr));
		isc_buffer_add(&b, strlen(keystr));
		dns_fixedname_init(&fname);
		result = dns_name_fromtext(dns_fixedname_name(&fname), &b,
					   dns_rootname, ISC_FALSE, NULL);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
		result = dns_name_dup(dns_fixedname_name(&fname), mctx,
				      keys[i]);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	}
	INSIST(i == count);

	*addrsp = addrs;
	*keysp = keys;
	*countp = count;

	return (ISC_R_SUCCESS);

 cleanup:
	if (addrs != NULL)
		isc_mem_put(mctx, addrs, count * sizeof(isc_sockaddr_t));
	if (keys != NULL) {
		unsigned int j;
		for (j = 0 ; j <= i; j++) {
			if (keys[j] == NULL)
				continue;
			if (dns_name_dynamic(keys[j]))
				dns_name_free(keys[j], mctx);
			isc_mem_put(mctx, keys[j], sizeof(dns_name_t));
		}
		isc_mem_put(mctx, keys, count * sizeof(dns_name_t *));
	}
	return (result);
}

void
ns_config_putipandkeylist(isc_mem_t *mctx, isc_sockaddr_t **addrsp,
			  dns_name_t ***keysp, isc_uint32_t count)
{
	unsigned int i;
	dns_name_t **keys = *keysp;

	INSIST(addrsp != NULL && *addrsp != NULL);

	isc_mem_put(mctx, *addrsp, count * sizeof(isc_sockaddr_t));
	for (i = 0; i < count; i++) {
		if (keys[i] == NULL)
			continue;
		if (dns_name_dynamic(keys[i]))
			dns_name_free(keys[i], mctx);
		isc_mem_put(mctx, keys[i], sizeof(dns_name_t));
	}
	isc_mem_put(mctx, *keysp, count * sizeof(dns_name_t *));
	*addrsp = NULL;
	*keysp = NULL;
}

isc_result_t
ns_config_getport(cfg_obj_t *config, in_port_t *portp) {
	cfg_obj_t *maps[3];
	cfg_obj_t *options = NULL;
	cfg_obj_t *portobj = NULL;
	isc_result_t result;
	int i;

	if (ns_g_port != 0) {
		*portp = ns_g_port;
		return (ISC_R_SUCCESS);
	}

	cfg_map_get(config, "options", &options);
	i = 0;
	if (options != NULL)
		maps[i++] = options;
	maps[i++] = ns_g_defaults;
	maps[i] = NULL;

	result = ns_config_get(maps, "port", &portobj);
	INSIST(result == ISC_R_SUCCESS);
	if (cfg_obj_asuint32(portobj) >= ISC_UINT16_MAX) {
		cfg_obj_log(portobj, ns_g_lctx, ISC_LOG_ERROR,
			    "port '%u' out of range",
			    cfg_obj_asuint32(portobj));
		return (ISC_R_RANGE);
	}
	*portp = (in_port_t)cfg_obj_asuint32(portobj);
	return (ISC_R_SUCCESS);
}
