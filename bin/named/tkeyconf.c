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

#include <isc/buffer.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/mem.h>

#include <dns/keyvalues.h>
#include <dns/name.h>
#include <dns/tkey.h>
#include <dns/tkeyconf.h>

#define RETERR(x) do { \
	result = (x); \
	if (result != ISC_R_SUCCESS) \
		goto failure; \
	} while (0)


isc_result_t
dns_tkeyctx_fromconfig(dns_c_ctx_t *cfg, isc_mem_t *mctx, isc_entropy_t *ectx,
		       dns_tkeyctx_t **tctxp)
{
	isc_result_t result;
	dns_tkeyctx_t *tctx = NULL;
	char *s;
	isc_uint32_t n;
	isc_buffer_t b, namebuf;
	unsigned char data[1024];
	dns_name_t domain, keyname;

	result = dns_tkeyctx_create(mctx, ectx, &tctx);
	if (result != ISC_R_SUCCESS)
		return (result);

	s = NULL;
	result = dns_c_ctx_gettkeydhkey(cfg, &s, &n);
	if (result == ISC_R_NOTFOUND) {
		*tctxp = tctx;
		return (ISC_R_SUCCESS);
	}
	isc_buffer_init(&namebuf, data, sizeof(data));
	dns_name_init(&keyname, NULL);
	isc_buffer_init(&b, s, strlen(s));
	isc_buffer_add(&b, strlen(s));
	dns_name_fromtext(&keyname, &b, dns_rootname, ISC_FALSE, &namebuf);
	RETERR(dst_key_fromfile(&keyname, n, DNS_KEYALG_DH,
				DST_TYPE_PUBLIC|DST_TYPE_PRIVATE,
				NULL, mctx, &tctx->dhkey));
	s = NULL;
	RETERR(dns_c_ctx_gettkeydomain(cfg, &s));
	dns_name_init(&domain, NULL);
	tctx->domain = (dns_name_t *) isc_mem_get(mctx, sizeof(dns_name_t));
	if (tctx->domain == NULL) {
		result = ISC_R_NOMEMORY;
		goto failure;
	}
	dns_name_init(tctx->domain, NULL);
	isc_buffer_init(&b, s, strlen(s));
	isc_buffer_add(&b, strlen(s));
	RETERR(dns_name_fromtext(&domain, &b, dns_rootname, ISC_FALSE,
				 &namebuf));
	RETERR(dns_name_dup(&domain, mctx, tctx->domain));

	*tctxp = tctx;
	return (ISC_R_SUCCESS);

 failure:
	if (tctx->dhkey != NULL)
		dst_key_free(&tctx->dhkey);
	if (tctx->domain != NULL) {
		dns_name_free(tctx->domain, mctx);
		isc_mem_put(mctx, tctx->domain, sizeof(dns_name_t));
		tctx->domain = NULL;
	}
	dns_tkeyctx_destroy(&tctx);
	return (result);
}

