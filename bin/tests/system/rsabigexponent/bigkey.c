/*
 * Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id$ */

#ifdef OPENSSL
#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/string.h>
#include <isc/util.h>

#define DST_KEY_INTERNAL

#include <dns/dnssec.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include <dst/dst.h>
#include <dst/result.h>

#include <openssl/err.h>

#include <openssl/objects.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER <= 0x00908000L
#error Require an OpenSSL version >= 9.8.0a
#endif
#include <openssl/bn.h>
#include <openssl/evp.h>

dst_key_t *key;
dns_fixedname_t fname;
dns_name_t *name;
unsigned int bits = 1024U;
isc_entropy_t *ectx;
isc_entropysource_t *source;
isc_mem_t *mctx;
isc_log_t *log_;
isc_logconfig_t *logconfig;
int level = ISC_LOG_WARNING;
isc_logdestination_t destination;
char filename[255];
isc_result_t result;
isc_buffer_t buf;
RSA *rsa;
BIGNUM *e;
EVP_PKEY *pkey;

#define CHECK(op, msg) \
do { result = (op); \
	if (result != ISC_R_SUCCESS) { \
		fprintf(stderr, \
			"fatal error: %s returns %s at file %s line %d\n", \
			msg, isc_result_totext(result), __FILE__, __LINE__); \
		exit(1); \
	} \
} while (0)

int
main(int argc, char **argv) {
	UNUSED(argc);
	UNUSED(argv);

	rsa = RSA_new();
	e = BN_new();
	pkey = EVP_PKEY_new();

	if ((rsa == NULL) || (e == NULL) || (pkey == NULL) ||
	    !EVP_PKEY_set1_RSA(pkey, rsa)) {
		fprintf(stderr, "fatal error: basic OpenSSL failure\n");
		exit(1);
	}

	/* e = 0x1000000000001 */
	BN_set_bit(e, 0);
	BN_set_bit(e, 48);

	if (RSA_generate_key_ex(rsa, bits, e, NULL)) {
		BN_free(e);
		RSA_free(rsa);
	} else {
		fprintf(stderr,
			"fatal error: RSA_generate_key_ex() fails "
			"at file %s line %d\n",
			__FILE__, __LINE__);
		exit(1);
	}

	dns_result_register();
	
	CHECK(isc_mem_create(0, 0, &mctx), "isc_mem_create()");
	CHECK(isc_entropy_create(mctx, &ectx), "isc_entropy_create()");
	CHECK(isc_entropy_usebestsource(ectx, &source,
					"random.data", ISC_ENTROPY_KEYBOARDNO),
	      "isc_entropy_usebestsource(\"random.data\")");
	CHECK(dst_lib_init2(mctx, ectx, NULL, 0), "dst_lib_init2()");
	CHECK(isc_log_create(mctx, &log_, &logconfig), "isc_log_create()");
	isc_log_setcontext(log_);
	dns_log_init(log_);
	dns_log_setcontext(log_);
	CHECK(isc_log_settag(logconfig, "bigkey"), "isc_log_settag()");
	destination.file.stream = stderr;
	destination.file.name = NULL;
	destination.file.versions = ISC_LOG_ROLLNEVER;
	destination.file.maximum_size = 0;
	CHECK(isc_log_createchannel(logconfig, "stderr",
				    ISC_LOG_TOFILEDESC,
				    level,
				    &destination,
				    ISC_LOG_PRINTTAG | ISC_LOG_PRINTLEVEL),
	      "isc_log_createchannel()");
	CHECK(isc_log_usechannel(logconfig, "stderr", NULL, NULL),
	      "isc_log_usechannel()");
	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);
	isc_buffer_init(&buf, "example.", strlen("example."));
	isc_buffer_add(&buf, strlen("example."));
	CHECK(dns_name_fromtext(name, &buf, dns_rootname, 0, NULL),
	      "dns_name_fromtext(\"example.\")");

	CHECK(dst_key_buildinternal(name, DNS_KEYALG_RSASHA1,
				    bits, DNS_KEYOWNER_ZONE,
				    DNS_KEYPROTO_DNSSEC, dns_rdataclass_in,
				    pkey, mctx, &key),
	      "dst_key_buildinternal(...)");

	CHECK(dst_key_tofile(key, DST_TYPE_PRIVATE | DST_TYPE_PUBLIC, NULL),
	      "dst_key_tofile()");
	isc_buffer_init(&buf, filename, sizeof(filename) - 1);
	isc_buffer_clear(&buf);
	CHECK(dst_key_buildfilename(key, 0, NULL, &buf),
	      "dst_key_buildfilename()");
	printf("%s\n", filename);
	dst_key_free(&key);

	isc_log_destroy(&log_);
	isc_log_setcontext(NULL);
	dns_log_setcontext(NULL);
	if (source != NULL)
		isc_entropy_destroysource(&source);
	isc_entropy_detach(&ectx);
	dst_lib_destroy();
	dns_name_destroy();
	isc_mem_destroy(&mctx);
	return (0);
}

#else /* OPENSSL */

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv) {
	fprintf(stderr, "Compiled without OpenSSL\n");
	exit(1);
}

#endif /* OPENSSL */
/*! \file */
