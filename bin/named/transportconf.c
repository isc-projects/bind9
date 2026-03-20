/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>

#include <isc/buffer.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/transport.h>

#include <isccfg/cfg.h>
#include <isccfg/clause.h>

#include <named/log.h>
#include <named/transportconf.h>

#define create_name(id, name)                                     \
	isc_buffer_t namesrc;                                     \
	dns_fixedname_t _fn;                                      \
	name = dns_fixedname_initname(&_fn);                      \
	isc_buffer_constinit(&namesrc, id, strlen(id));           \
	isc_buffer_add(&namesrc, strlen(id));                     \
	result = (dns_name_fromtext(name, &namesrc, dns_rootname, \
				    DNS_NAME_DOWNCASE));          \
	if (result != ISC_R_SUCCESS) {                            \
		goto cleanup;                                     \
	}

#define parse_transport_option(map, transport, name, setter)      \
	{                                                         \
		const cfg_obj_t *obj = NULL;                      \
		cfg_map_get(map, name, &obj);                     \
		if (obj != NULL) {                                \
			setter(transport, cfg_obj_asstring(obj)); \
		}                                                 \
	}

#define parse_transport_tls_versions(map, transport, name, setter)                \
	{                                                                         \
		const cfg_obj_t *obj = NULL;                                      \
		cfg_map_get(map, name, &obj);                                     \
		if (obj != NULL) {                                                \
			{                                                         \
				uint32_t tls_protos = 0;                          \
				INSIST(obj != NULL);                              \
				CFG_LIST_FOREACH(obj, proto) {                    \
					const cfg_obj_t *tls_proto_obj =          \
						cfg_listelt_value(proto);         \
					const char *tls_sver =                    \
						cfg_obj_asstring(                 \
							tls_proto_obj);           \
					const isc_tls_protocol_version_t ver =    \
						isc_tls_protocol_name_to_version( \
							tls_sver);                \
					INSIST(ver !=                             \
					       ISC_TLS_PROTO_VER_UNDEFINED);      \
					INSIST(isc_tls_protocol_supported(        \
						ver));                            \
					tls_protos |= ver;                        \
				}                                                 \
				if (tls_protos != 0) {                            \
					setter(transport, tls_protos);            \
				}                                                 \
			}                                                         \
		}                                                                 \
	}

#define parse_transport_bool_option(map, transport, name, setter)  \
	{                                                          \
		const cfg_obj_t *obj = NULL;                       \
		cfg_map_get(map, name, &obj);                      \
		if (obj != NULL) {                                 \
			setter(transport, cfg_obj_asboolean(obj)); \
		}                                                  \
	}

static isc_result_t
add_doh_transports(const cfg_obj_t *transportlist, dns_transport_list_t *list) {
	const cfg_obj_t *doh = NULL;
	const char *dohid = NULL;
	isc_result_t result;

	CFG_LIST_FOREACH(transportlist, element) {
		dns_name_t *dohname = NULL;
		dns_transport_t *transport = NULL;

		doh = cfg_listelt_value(element);
		dohid = cfg_obj_asstring(cfg_map_getname(doh));

		create_name(dohid, dohname);

		transport = dns_transport_new(dohname, DNS_TRANSPORT_HTTP,
					      list);

		dns_transport_set_tlsname(transport, dohid);
		parse_transport_option(doh, transport, CFG_CLAUSE_KEY_FILE,
				       dns_transport_set_keyfile);
		parse_transport_option(doh, transport, CFG_CLAUSE_CERT_FILE,
				       dns_transport_set_certfile);
		parse_transport_tls_versions(doh, transport,
					     CFG_CLAUSE_PROTOCOLS,
					     dns_transport_set_tls_versions);
		parse_transport_option(doh, transport, CFG_CLAUSE_CIPHERS,
				       dns_transport_set_ciphers);
		parse_transport_option(doh, transport, CFG_CLAUSE_CIPHER_SUITES,
				       dns_transport_set_cipher_suites);
		parse_transport_bool_option(
			doh, transport, CFG_CLAUSE_PREFER_SERVER_CIPHERS,
			dns_transport_set_prefer_server_ciphers);
		parse_transport_option(doh, transport, CFG_CLAUSE_CA_FILE,
				       dns_transport_set_cafile);
		parse_transport_option(doh, transport,
				       CFG_CLAUSE_REMOTE_HOSTNAME,
				       dns_transport_set_remote_hostname);
	}

	return ISC_R_SUCCESS;
cleanup:
	cfg_obj_log(doh, ISC_LOG_ERROR, "configuring DoH '%s': %s", dohid,
		    isc_result_totext(result));

	return result;
}

static isc_result_t
add_tls_transports(const cfg_obj_t *transportlist, dns_transport_list_t *list) {
	const cfg_obj_t *tls = NULL;
	const char *tlsid = NULL;
	isc_result_t result;

	CFG_LIST_FOREACH(transportlist, element) {
		dns_name_t *tlsname = NULL;
		dns_transport_t *transport = NULL;

		tls = cfg_listelt_value(element);
		tlsid = cfg_obj_asstring(cfg_map_getname(tls));

		if (!strcmp(tlsid, "ephemeral")) {
			CLEANUP(ISC_R_UNEXPECTEDTOKEN);
		}

		create_name(tlsid, tlsname);

		transport = dns_transport_new(tlsname, DNS_TRANSPORT_TLS, list);

		dns_transport_set_tlsname(transport, tlsid);
		parse_transport_option(tls, transport, CFG_CLAUSE_KEY_FILE,
				       dns_transport_set_keyfile);
		parse_transport_option(tls, transport, CFG_CLAUSE_CERT_FILE,
				       dns_transport_set_certfile);
		parse_transport_tls_versions(tls, transport,
					     CFG_CLAUSE_PROTOCOLS,
					     dns_transport_set_tls_versions);
		parse_transport_option(tls, transport, CFG_CLAUSE_CIPHERS,
				       dns_transport_set_ciphers);
		parse_transport_option(tls, transport, CFG_CLAUSE_CIPHER_SUITES,
				       dns_transport_set_cipher_suites);
		parse_transport_bool_option(
			tls, transport, CFG_CLAUSE_PREFER_SERVER_CIPHERS,
			dns_transport_set_prefer_server_ciphers);
		parse_transport_option(tls, transport, CFG_CLAUSE_CA_FILE,
				       dns_transport_set_cafile);
		parse_transport_option(tls, transport,
				       CFG_CLAUSE_REMOTE_HOSTNAME,
				       dns_transport_set_remote_hostname);
	}

	return ISC_R_SUCCESS;
cleanup:
	cfg_obj_log(tls, ISC_LOG_ERROR, "configuring tls '%s': %s", tlsid,
		    isc_result_totext(result));

	return result;
}

static isc_result_t
transport_list_fromconfig(const cfg_obj_t *config, dns_transport_list_t *list) {
	const cfg_obj_t *obj = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	if (result == ISC_R_SUCCESS &&
	    cfg_map_get(config, CFG_CLAUSE_TLS, &obj) == ISC_R_SUCCESS)
	{
		result = add_tls_transports(obj, list);
		obj = NULL;
	}

	if (result == ISC_R_SUCCESS &&
	    cfg_map_get(config, CFG_CLAUSE_DOH, &obj) == ISC_R_SUCCESS)
	{
		result = add_doh_transports(obj, list);
		obj = NULL;
	}

	return result;
}

static void
transport_list_add_ephemeral(dns_transport_list_t *list) {
	isc_result_t result;
	dns_name_t *tlsname = NULL;
	dns_transport_t *transport;

	create_name("ephemeral", tlsname);

	transport = dns_transport_new(tlsname, DNS_TRANSPORT_TLS, list);
	dns_transport_set_tlsname(transport, "ephemeral");

	return;
cleanup:
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

isc_result_t
named_transports_fromconfig(const cfg_obj_t *config, const cfg_obj_t *vconfig,
			    isc_mem_t *mctx, dns_transport_list_t **listp) {
	isc_result_t result;
	dns_transport_list_t *list = dns_transport_list_new(mctx);

	REQUIRE(listp != NULL && *listp == NULL);

	transport_list_add_ephemeral(list);

	if (config != NULL) {
		CHECK(transport_list_fromconfig(config, list));
	}

	if (vconfig != NULL) {
		config = cfg_tuple_get(vconfig, "options");
		transport_list_fromconfig(config, list);
	}

	*listp = list;
	return ISC_R_SUCCESS;
cleanup:
	dns_transport_list_detach(&list);
	return result;
}
