/*
 * Portions Copyright (C) 2000  Internet Software Consortium.
 * Portions Copyright (C) 1995-2000 by Network Associates, Inc.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM AND
 * NETWORK ASSOCIATES DISCLAIM ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE CONSORTIUM OR NETWORK
 * ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: dnssec-keygen.c,v 1.36.2.2 2000/11/09 00:39:14 gson Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/entropy.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include <dst/dst.h>
#include <dst/result.h>

#include "dnssectool.h"

#define MAX_RSA 2000 /* XXXBEW dnssafe is broken */

const char *program = "dnssec-keygen";
int verbose;

static isc_boolean_t
dsa_size_ok(int size) {
	return (ISC_TF(size >= 512 && size <= 1024 && size % 64 == 0));
}

static void
usage(void) {
	printf("Usage:\n");
	printf("    %s -a alg -b bits -n type [options] name\n\n", program);
	printf("Required options:\n");
	printf("    -a algorithm: RSA | RSAMD5 | DH | DSA | HMAC-MD5\n");
	printf("    -b key size, in bits:\n");
	printf("        RSA:\t\t[512..%d]\n", MAX_RSA);
	printf("        DH:\t\t[128..4096]\n");
	printf("        DSA:\t\t[512..1024] and dividable by 64\n");
	printf("        HMAC-MD5:\t[1..512]\n");
	printf("    -n nametype: ZONE | HOST | ENTITY | USER\n");
	printf("    name: owner of the key\n");
	printf("Other options:\n");
	printf("    -e use large exponent (RSA only)\n");
	printf("    -g use specified generator (DH only)\n");
 	printf("    -t type: AUTHCONF | NOAUTHCONF | NOAUTH | NOCONF "
 	       "(default: AUTHCONF)\n");
 	printf("    -p protocol value "
 	       "(default: 2 [email] for USER, 3 [dnssec] otherwise)\n");
 	printf("    -s strength value this key signs DNS records with "
 	       "(default: 0)\n");
 	printf("    -r randomdev (a file containing random data)\n");
	printf("    -v verbose level\n");

	exit (-1);
}

int
main(int argc, char **argv) {
	char		*algname = NULL, *nametype = NULL, *type = NULL;
	char		*randomfile = NULL;
	char		*prog, *endp;
	dst_key_t	*key = NULL, *oldkey;
	dns_fixedname_t	fname;
	dns_name_t	*name;
	isc_uint16_t	flags = 0;
	dns_secalg_t	alg;
	isc_boolean_t	conflict = ISC_FALSE, null_key = ISC_FALSE;
	isc_mem_t	*mctx = NULL;
	int		ch, rsa_exp = 0, generator = 0, param = 0;
	int		protocol = -1, size = -1, signatory = 0;
	isc_result_t	ret;
	isc_textregion_t r;
	char		filename[255];
	isc_buffer_t	buf;
	isc_log_t	*log = NULL;
	isc_entropy_t	*ectx = NULL;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	if ((prog = strrchr(argv[0],'/')) == NULL)
		prog = isc_mem_strdup(mctx, argv[0]);
	else
		prog = isc_mem_strdup(mctx, ++prog);
	if (prog == NULL)
		fatal("out of memory");

	if (argc == 1)
		usage();

	dns_result_register();

	while ((ch = isc_commandline_parse(argc, argv,
					   "a:b:eg:n:t:p:s:hr:v:")) != -1)
	{
	    switch (ch) {
		case 'a':
			algname = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (algname == NULL)
				fatal("out of memory");
			break;
		case 'b':
			size = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || size < 0)
				fatal("-b requires a non-negative number");
			break;
		case 'e':
			rsa_exp = 1;
			break;
		case 'g':
			generator = strtol(isc_commandline_argument,
					   &endp, 10);
			if (*endp != '\0' || generator <= 0)
				fatal("-g requires a positive number");
			break;
		case 'n':
			nametype = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (nametype == NULL)
				fatal("out of memory");
			break;
		case 't':
			type = isc_mem_strdup(mctx, isc_commandline_argument);
			if (type == NULL)
				fatal("out of memory");
			break;
		case 'p':
			protocol = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || protocol < 0 || protocol > 255)
				fatal("-p must be followed by a number "
				      "[0..255]");
			break;
		case 's':
			signatory = strtol(isc_commandline_argument,
					   &endp, 10);
			if (*endp != '\0' || signatory < 0 || signatory > 15)
				fatal("-s must be followed by a number "
				      "[0..15]");
			break;
		case 'r':
			randomfile = isc_mem_strdup(mctx,
						    isc_commandline_argument);
			if (randomfile == NULL)
				fatal("out of memory");
			break;
		case 'v':
			endp = NULL;
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				fatal("-v must be followed by a number");
			break;

		case 'h':
			usage();
		default:
			fprintf(stderr, "%s: invalid argument -%c\n",
				program, ch);
			usage();
		} 
	}

	setup_entropy(mctx, randomfile, &ectx);
	if (randomfile != NULL)
		isc_mem_free(mctx, randomfile);
	ret = dst_lib_init(mctx, ectx,
			   ISC_ENTROPY_BLOCKING | ISC_ENTROPY_GOODONLY);
	if (ret != ISC_R_SUCCESS)
		fatal("could not initialize dst");

	setup_logging(verbose, mctx, &log);

	if (argc < isc_commandline_index + 1)
		fatal("the key name was not specified");
	if (argc > isc_commandline_index + 1)
		fatal("extraneous arguments");

	if (algname == NULL)
		fatal("no algorithm was specified");
	if (strcasecmp(algname, "RSA") == 0)
		alg = DNS_KEYALG_RSA;
	else if (strcasecmp(algname, "HMAC-MD5") == 0)
		alg = DST_ALG_HMACMD5;
	else {
		r.base = algname;
		r.length = strlen(algname);
		ret = dns_secalg_fromtext(&alg, &r);
		if (ret != ISC_R_SUCCESS)
			fatal("unknown algorithm %s", algname);
	}
	if (dst_algorithm_supported(alg) == ISC_FALSE)
		fatal("unsupported algorithm %s", algname);

	if (type != NULL) {
		if (strcasecmp(type, "NOAUTH") == 0)
			flags |= DNS_KEYTYPE_NOAUTH;
		else if (strcasecmp(type, "NOCONF") == 0)
			flags |= DNS_KEYTYPE_NOCONF;
		else if (strcasecmp(type, "NOAUTHCONF") == 0) {
			flags |= (DNS_KEYTYPE_NOAUTH | DNS_KEYTYPE_NOCONF);
			if (size < 0)
				size = 0;
		}
		else if (strcasecmp(type, "AUTHCONF") == 0)
			/* nothing */;
		else
			fatal("invalid type %s", type);
	}

	if (size < 0)
		fatal("key size not specified (-b option)");

	switch (alg) {
	case DNS_KEYALG_RSA:
		if (size != 0 && (size < 512 || size > MAX_RSA))
			fatal("RSA key size %d out of range", size);
		break;
	case DNS_KEYALG_DH:
		if (size != 0 && (size < 128 || size > 4096))
			fatal("DH key size %d out of range", size);
		break;
	case DNS_KEYALG_DSA:
		if (size != 0 && !dsa_size_ok(size))
			fatal("Invalid DSS key size: %d", size);
		break;
	case DST_ALG_HMACMD5:
		if (size < 1 || size > 512)
			fatal("HMAC-MD5 key size %d out of range", size);
		break;
	}

	if (alg != DNS_KEYALG_RSA && rsa_exp != 0)
		fatal("specified RSA exponent without RSA");

	if (alg != DNS_KEYALG_DH && generator != 0)
		fatal("specified DH generator without DH");

	if (nametype == NULL)
		fatal("no nametype specified");
	if (strcasecmp(nametype, "zone") == 0)
		flags |= DNS_KEYOWNER_ZONE;
	else if (strcasecmp(nametype, "host") == 0 ||
		 strcasecmp(nametype, "entity") == 0)
		flags |= DNS_KEYOWNER_ENTITY;
	else if (strcasecmp(nametype, "user") == 0)
		flags |= DNS_KEYOWNER_USER;
	else
		fatal("invalid nametype %s", nametype);

	flags |= signatory;

	if (protocol == -1) {
		if ((flags & DNS_KEYFLAG_OWNERMASK) == DNS_KEYOWNER_USER)
			protocol = DNS_KEYPROTO_EMAIL;
		else
			protocol = DNS_KEYPROTO_DNSSEC;
	}

	if ((flags & DNS_KEYFLAG_TYPEMASK) == DNS_KEYTYPE_NOKEY) {
		if (size > 0)
			fatal("Specified null key with non-zero size");
		if ((flags & DNS_KEYFLAG_SIGNATORYMASK) != 0)
			fatal("Specified null key with signing authority");
	}

	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);
	isc_buffer_init(&buf, argv[isc_commandline_index],
			strlen(argv[isc_commandline_index]));
	isc_buffer_add(&buf, strlen(argv[isc_commandline_index]));
	ret = dns_name_fromtext(name, &buf, dns_rootname, ISC_FALSE, NULL);
	if (ret != ISC_R_SUCCESS)
		fatal("Invalid key name %s: %s", argv[isc_commandline_index],
		      isc_result_totext(ret));

	switch(alg) {
	case DNS_KEYALG_RSA:
		param = rsa_exp;
		break;
	case DNS_KEYALG_DH:
		param = generator;
		break;
	case DNS_KEYALG_DSA:
	case DST_ALG_HMACMD5:
		param = 0;
		break;
	}

	if ((flags & DNS_KEYFLAG_TYPEMASK) == DNS_KEYTYPE_NOKEY)
		null_key = ISC_TRUE;

	isc_buffer_init(&buf, filename, sizeof(filename) - 1);

	do { 
		conflict = ISC_FALSE; 
		oldkey = NULL;

		/* generate the key */
		ret = dst_key_generate(name, alg, size, param, flags, protocol,
				       mctx, &key);
		isc_entropy_stopcallbacksources(ectx);

		if (ret != ISC_R_SUCCESS) {
			fatal("failed to generate key %s/%s: %s\n",
			      nametostr(name), algtostr(alg),
			      dst_result_totext(ret));
			exit(-1);
		}
		
		/*
		 * Try to read a key with the same name, alg and id from disk.
		 * If there is one we must continue generating a new one 
		 * unless we were asked to generate a null key, in which
		 * case we return failure.
		 */
		ret = dst_key_fromfile(name, dst_key_id(key), alg, 
				       DST_TYPE_PRIVATE, NULL, mctx, &oldkey);
		/* do not overwrite an existing key  */
		if (ret == ISC_R_SUCCESS) {
			dst_key_free(&oldkey);
			conflict = ISC_TRUE;
			if (null_key)
				break;
		}
		if (conflict == ISC_TRUE) {
			if (verbose > 0) {
				isc_buffer_clear(&buf);
				ret = dst_key_buildfilename(key, 0, NULL, &buf);
				fprintf(stderr,
					"%s: %s already exists, "
					"generating a new key\n",
					program, filename);
			}
			dst_key_free(&key);
		}

	} while (conflict == ISC_TRUE);

	if (conflict)
		fatal("cannot generate a null key when a key with id 0 "
		      "already exists");

	ret = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE, NULL);
	if (ret != ISC_R_SUCCESS)
		fatal("failed to write key %s/%s/%d: %s\n", nametostr(name),
		      algtostr(alg), dst_key_id(key), isc_result_totext(ret));

	isc_buffer_clear(&buf);
	ret = dst_key_buildfilename(key, 0, NULL, &buf);
	printf("%s\n", filename);
	isc_mem_free(mctx, algname);
	isc_mem_free(mctx, nametype);
	isc_mem_free(mctx, prog);
	if (type != NULL)
		isc_mem_free(mctx, type);
	dst_key_free(&key);

	if (log != NULL)
		isc_log_destroy(&log);
	cleanup_entropy(&ectx);
	dst_lib_destroy();
	if (verbose > 10)
		isc_mem_stats(mctx, stdout);
        isc_mem_destroy(&mctx);

	return (0);
}
