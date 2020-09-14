/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#define CONCAT(a, b) a##b
#define DNSCONF_SET_STRING(FIELD)                                         \
	void CONCAT(DNSConf_set, FIELD)(DNSConf * cfg, const char *arg) { \
		DBGPRINT("inside DNSConf_set" #FIELD "\n");               \
                                                                          \
		if (!DNSConf_initctx(cfg))                                \
			return;                                           \
                                                                          \
		if (arg == NULL) {                                        \
			DBGPRINT("null pointer\n");                       \
			CONCAT(dns_c_ctx_unset, FIELD)(cfg->confctx);     \
		} else if (*arg == '\0') {                                \
			DBGPRINT("empty string\n");                       \
			CONCAT(dns_c_ctx_unset, FIELD)(cfg->confctx);     \
		} else                                                    \
			CONCAT(dns_c_ctx_set, FIELD)(cfg->confctx, arg);  \
	}

#define DNSCONF_GET_STRING(FIELD)                                             \
	char *CONCAT(DNSConf_get, FIELD)(DNSConf * cfg) {                     \
		char *result = NULL;                                          \
		isc_result_t tmpres;                                          \
                                                                              \
		if (cfg == NULL || cfg->confctx == NULL)                      \
			return (NULL);                                        \
                                                                              \
		tmpres = CONCAT(dns_c_ctx_get, FIELD)(cfg->confctx, &result); \
		if (tmpres == ISC_R_NOTFOUND)                                 \
			return (NULL);                                        \
                                                                              \
		return (result);                                              \
	}

#define STRING_FIELD_DEFS(FIELD) \
	DNSCONF_GET_STRING(FIELD) DNSCONF_SET_STRING(FIELD)

#define INT_FIELD_DEFS(FIELD)
