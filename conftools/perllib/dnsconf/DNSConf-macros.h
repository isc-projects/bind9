/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
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

/* $Id: DNSConf-macros.h,v 1.5.4.1 2001/01/09 22:38:52 bwelling Exp $ */

#define CONCAT(a,b) a ## b
#define DNSCONF_SET_STRING(FIELD)					\
void CONCAT(DNSConf_set, FIELD)(DNSConf *cfg, const char *arg) {	\
									\
	DBGPRINT("inside DNSConf_set" #FIELD "\n");			\
									\
	if (!DNSConf_initctx(cfg)) 					\
		return;							\
									\
	if (arg == NULL) {						\
		DBGPRINT("null pointer\n");				\
		CONCAT(dns_c_ctx_unset, FIELD)(cfg->confctx);		\
	} else if (*arg == '\0') {				\
		DBGPRINT("empty string\n");				\
		CONCAT(dns_c_ctx_unset, FIELD)(cfg->confctx);		\
	} else								\
		CONCAT(dns_c_ctx_set, FIELD)(cfg->confctx, arg);	\
}

#define DNSCONF_GET_STRING(FIELD)					\
char * CONCAT(DNSConf_get, FIELD)(DNSConf *cfg) {			\
	char *result = NULL;						\
	isc_result_t tmpres;						\
									\
	if (cfg == NULL || cfg->confctx == NULL)			\
		return NULL;						\
									\
	tmpres = CONCAT(dns_c_ctx_get, FIELD)(cfg->confctx, &result);	\
	if (tmpres == ISC_R_NOTFOUND) 					\
		return NULL;						\
									\
	return result;							\
}									\


#define STRING_FIELD_DEFS(FIELD) \
	DNSCONF_GET_STRING(FIELD) DNSCONF_SET_STRING(FIELD)

#define INT_FIELD_DEFS(FIELD)
