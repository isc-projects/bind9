/*
 * Copyright (C) 2001, 2002, 2004-2007, 2009, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: config.h,v 1.16 2009/06/11 23:47:55 tbox Exp $ */

#ifndef NAMED_CONFIG_H
#define NAMED_CONFIG_H 1

/*! \file */

#include <isccfg/cfg.h>

#include <dns/types.h>
#include <dns/zone.h>

isc_result_t
ns_config_parsedefaults(cfg_parser_t *parser, cfg_obj_t **conf);

isc_result_t
ns_config_get(cfg_obj_t const * const *maps, const char *name,
	      const cfg_obj_t **obj);

isc_result_t
ns_checknames_get(const cfg_obj_t **maps, const char *name,
		  const cfg_obj_t **obj);

int
ns_config_listcount(const cfg_obj_t *list);

isc_result_t
ns_config_getclass(const cfg_obj_t *classobj, dns_rdataclass_t defclass,
		   dns_rdataclass_t *classp);

isc_result_t
ns_config_gettype(const cfg_obj_t *typeobj, dns_rdatatype_t deftype,
		  dns_rdatatype_t *typep);

dns_zonetype_t
ns_config_getzonetype(const cfg_obj_t *zonetypeobj);

isc_result_t
ns_config_getiplist(const cfg_obj_t *config, const cfg_obj_t *list,
		    in_port_t defport, isc_mem_t *mctx,
		    isc_sockaddr_t **addrsp, isc_dscp_t **dscpsp,
		    isc_uint32_t *countp);

void
ns_config_putiplist(isc_mem_t *mctx, isc_sockaddr_t **addrsp,
		    isc_dscp_t **dscpsp, isc_uint32_t count);

isc_result_t
ns_config_getipandkeylist(const cfg_obj_t *config, const cfg_obj_t *list,
			  isc_mem_t *mctx, dns_ipkeylist_t *ipkl);

isc_result_t
ns_config_getport(const cfg_obj_t *config, in_port_t *portp);

isc_result_t
ns_config_getkeyalgorithm(const char *str, dns_name_t **name,
			  isc_uint16_t *digestbits);
isc_result_t
ns_config_getkeyalgorithm2(const char *str, dns_name_t **name,
			   unsigned int *typep, isc_uint16_t *digestbits);

isc_result_t
ns_config_getdscp(const cfg_obj_t *config, isc_dscp_t *dscpp);

#endif /* NAMED_CONFIG_H */
