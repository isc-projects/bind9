/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

/* $Id: tsigconf.c,v 1.14 2000/11/27 19:42:24 gson Exp $ */

#include <config.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/string.h>

#include <dns/tsig.h>

#include <named/log.h>

#include <named/tsigconf.h>

static isc_result_t
add_initial_keys(dns_c_kdeflist_t *list, dns_tsig_keyring_t *ring,
		 isc_mem_t *mctx)
{
	dns_c_kdef_t *key;
	unsigned char *secret = NULL;
	int secretalloc = 0;
	int secretlen = 0;
	isc_result_t ret;
	isc_stdtime_t now;

	key = ISC_LIST_HEAD(list->keydefs);
	while (key != NULL) {
		dns_name_t keyname;
		dns_name_t *alg, tempalg;
		char keynamedata[1024], algdata[1024];
		isc_buffer_t keynamesrc, keynamebuf, algsrc, algbuf;
		isc_buffer_t secretbuf;

		dns_name_init(&keyname, NULL);

		/*
		 * Create the key name.
		 */
		isc_buffer_init(&keynamesrc, key->keyid, strlen(key->keyid));
		isc_buffer_add(&keynamesrc, strlen(key->keyid));
		isc_buffer_init(&keynamebuf, keynamedata, sizeof(keynamedata));
		ret = dns_name_fromtext(&keyname, &keynamesrc, dns_rootname,
					ISC_TRUE, &keynamebuf);
		if (ret != ISC_R_SUCCESS)
			goto failure;

		/*
		 * Create the algorithm.
		 */
		if (strcasecmp(key->algorithm, "hmac-md5") == 0)
			alg = dns_tsig_hmacmd5_name;
		else {
			dns_name_init(&tempalg, NULL);
			isc_buffer_init(&algsrc, key->algorithm,
					strlen(key->algorithm));
			isc_buffer_add(&algsrc, strlen(key->algorithm));
			isc_buffer_init(&algbuf, algdata, sizeof(algdata));
			ret = dns_name_fromtext(&tempalg, &algsrc,
						dns_rootname,
						ISC_TRUE, &algbuf);
			if (ret != ISC_R_SUCCESS)
				goto failure;
			alg = &tempalg;
		}

		secretalloc = secretlen = strlen(key->secret) * 3 / 4;
		secret = isc_mem_get(mctx, secretlen);
		if (secret == NULL) {
			ret = ISC_R_NOMEMORY;
			goto failure;
		}
		isc_buffer_init(&secretbuf, secret, secretlen);
		ret = isc_base64_decodestring(mctx, key->secret, &secretbuf);
		if (ret != ISC_R_SUCCESS)
			goto failure;
		secretlen = isc_buffer_usedlength(&secretbuf);

		isc_stdtime_get(&now);
		ret = dns_tsigkey_create(&keyname, alg, secret, secretlen,
					 ISC_FALSE, NULL, now, now,
					 mctx, ring, NULL);
		isc_mem_put(mctx, secret, secretalloc);
		secret = NULL;
		if (ret != ISC_R_SUCCESS)
			goto failure;

		key = ISC_LIST_NEXT(key, next);
		continue;
		
	failure:
		isc_log_write(ns_g_lctx,
			      NS_LOGCATEGORY_GENERAL, NS_LOGMODULE_SERVER,
			      ISC_LOG_ERROR, "configuring TSIG key '%s': %s",
			      key->keyid, isc_result_totext(ret));
		ret = ISC_R_FAILURE;
		goto cleanup;
	}
	return (ISC_R_SUCCESS);

 cleanup:
	if (secret != NULL)
		isc_mem_put(mctx, secret, secretalloc);
	return (ret);

}

isc_result_t
ns_tsigkeyring_fromconfig(dns_c_view_t *confview, dns_c_ctx_t *confctx,
			   isc_mem_t *mctx, dns_tsig_keyring_t **ringp)
{
	dns_c_kdeflist_t *keylist;
	dns_tsig_keyring_t *ring = NULL;
	isc_result_t result;

	result = dns_tsigkeyring_create(mctx, &ring);
	if (result != ISC_R_SUCCESS)
		return (result);

	keylist = NULL;
	result = dns_c_ctx_getkdeflist(confctx, &keylist);
	if (result == ISC_R_SUCCESS)
		result = add_initial_keys(keylist, ring, mctx);
	else if (result == ISC_R_NOTFOUND)
		result = ISC_R_SUCCESS;
	if (result != ISC_R_SUCCESS)
		goto failure;

	if (confview != NULL) {
		keylist = NULL;
		result = dns_c_view_getkeydefs(confview, &keylist);
		if (result == ISC_R_SUCCESS)
			result = add_initial_keys(keylist, ring, mctx);
		else if (result == ISC_R_NOTFOUND)
			result = ISC_R_SUCCESS;
		if (result != ISC_R_SUCCESS)
			goto failure;
	}

	*ringp = ring;
	return (ISC_R_SUCCESS);

 failure:
	dns_tsigkeyring_destroy(&ring);
	return (result);
}
