/*
 * Portions Copyright (c) 1995-1999 by TISLabs at Network Associates, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND NETWORK ASSOCIATES
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */

/* $Id: dnssec-keygen.c,v 1.12 2000/04/27 18:24:26 bwelling Exp $ */

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <isc/boolean.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <dns/keyvalues.h>
#include <dns/secalg.h>
#include <dst/dst.h>
#include <dst/result.h>

static isc_boolean_t dsa_size_ok(int size);
static void die(char *str);
static void usage(char *prog);

static int verbose;

int
main(int argc, char **argv) {
	char			*algname = NULL, *nametype = NULL, *type = NULL;
	char			*prog, *endp;
	dst_key_t		*key;
	char			*name = NULL;
	isc_uint16_t		flags = 0;
	dns_secalg_t		alg;
	isc_mem_t		*mctx = NULL;
	int			ch, rsa_exp = 0, generator = 0, param = 0;
	int			protocol = -1, size = -1, signatory = 0;
	isc_textregion_t	r;
	isc_result_t		ret;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	if ((prog = strrchr(argv[0],'/')) == NULL)
		prog = isc_mem_strdup(mctx, argv[0]);
	else
		prog = isc_mem_strdup(mctx, ++prog);
	if (prog == NULL)
		die("strdup failure");

	if (argc == 1)
		usage(prog);

	while ((ch = isc_commandline_parse(argc, argv,
					   "a:b:eg:n:t:p:s:hv:")) != -1)
	{
	    switch (ch) {
		case 'a':
			algname = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (algname == NULL)
				die("strdup failure");
			break;
		case 'b':
			size = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || size < 0)
				die("-b requires a non-negative number");
			break;
		case 'e':
			rsa_exp = 1;
			break;
		case 'g':
			generator = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || generator <= 0)
				die("-g requires a positive number");
			break;
		case 'n':
			nametype = isc_mem_strdup(mctx,
						  isc_commandline_argument);
			if (nametype == NULL)
				die("strdup failure");
			break;
		case 't':
			type = isc_mem_strdup(mctx, isc_commandline_argument);
			if (type == NULL)
				die("strdup failure");
			break;
		case 'p':
			protocol = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || protocol < 0 || protocol > 255)
				die("-p must be followed by a number [0..255]");
			break;
		case 's':
			signatory = strtol(isc_commandline_argument, &endp, 10);
			if (*endp != '\0' || signatory < 0 || signatory > 15)
				die("-s must be followed by a number [0..15]");
			break;
		case 'v':
			endp = NULL;
			verbose = strtol(isc_commandline_argument, &endp, 0);
			if (*endp != '\0')
				die("-v must be followed by a number");
			break;

		case 'h':
			usage(prog);
		default:
			printf("invalid argument -%c\n", ch);
			usage(prog);
		} 
	}

	if (isc_commandline_index + 1 < argc)
		die("Extraneous arguments");

	if (algname == NULL)
		die("No algorithm specified");
	if (strcasecmp(algname, "RSA") == 0)
		alg = DNS_KEYALG_RSA;
	else if (strcasecmp(algname, "HMAC-MD5") == 0)
		alg = DST_ALG_HMACMD5;
	else {
		r.base = algname;
		r.length = strlen(algname);
		ret = dns_secalg_fromtext(&alg, &r);
		if (ret != ISC_R_SUCCESS)
			die("Unknown algorithm");
	}
	if (dst_supported_algorithm(alg) == ISC_FALSE)
		die("Unsupported algorithm");

	if (size < 0)
		die("Must specify key size (-b option)");

	if (type != NULL) {
		if (strcasecmp(type, "NOAUTH") == 0)
			flags |= DNS_KEYTYPE_NOAUTH;
		else if (strcasecmp(type, "NOCONF") == 0)
			flags |= DNS_KEYTYPE_NOCONF;
		else if (strcasecmp(type, "NOAUTHCONF") == 0)
			flags |= (DNS_KEYTYPE_NOAUTH | DNS_KEYTYPE_NOCONF);
		else if (strcasecmp(type, "AUTHCONF") == 0)
			/* nothing */;
		else
			die("Invalid type");
	}

	switch (alg) {
	case DNS_KEYALG_RSA:
		if (size != 0 && (size < 512 || size > 1024))
			die("RSA key size out of range");
		break;
	case DNS_KEYALG_DH:
		if (size != 0 && (size < 128 || size > 4096))
			die("DH key size out of range");
		break;
	case DNS_KEYALG_DSA:
		if (!dsa_size_ok(size))
			die("Invalid DSS key size");
		break;
	case DST_ALG_HMACMD5:
		if (size < 1 || size > 512)
			die("Invalid HMAC-MD5 key size");
		break;
	}

	if (alg != DNS_KEYALG_RSA && rsa_exp != 0)
		die("Cannot specify RSA exponent without RSA");

	if (alg != DNS_KEYALG_DH && generator != 0)
		die("Cannot specify DH generator without DH");

	if (nametype == NULL)
		die("No nametype specified");
	if (strcasecmp(nametype, "zone") == 0)
		flags |= DNS_KEYOWNER_ZONE;
	else if (strcasecmp(nametype, "host") == 0 ||
		 strcasecmp(nametype, "entity") == 0)
		flags |= DNS_KEYOWNER_ENTITY;
	else if (strcasecmp(nametype, "user") == 0)
		flags |= DNS_KEYOWNER_USER;
	else
		die("Invalid nametype");

	flags |= signatory;

	if (protocol == -1) {
		if ((flags & DNS_KEYFLAG_OWNERMASK) == DNS_KEYOWNER_USER)
			protocol = DNS_KEYPROTO_EMAIL;
		else
			protocol = DNS_KEYPROTO_DNSSEC;
	}

	if ((flags & DNS_KEYFLAG_TYPEMASK) == DNS_KEYTYPE_NOKEY) {
		if (size > 0)
			die("Specified null key with non-zero size");
		if ((flags & DNS_KEYFLAG_SIGNATORYMASK) != 0)
			die("Specified null key with signing authority");
	}

	name = isc_mem_allocate(mctx, strlen(argv[isc_commandline_index]) + 2);
	if (name == NULL)
		die("strdup failure");
	strcpy(name, argv[isc_commandline_index]);
	if (name[strlen(name) - 1] != '.') {
		strcat(name, ".");
		printf("** Added a trailing dot to fully qualify the name\n");
	}

	printf("Generating %d bit %s key for %s\n", size, algname, name);
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

	dst_result_register();
	ret = dst_key_generate(name, alg, size, param, flags, protocol, mctx,
			       &key);

	if (ret != ISC_R_SUCCESS) {
		printf("Failed to generate key: %s\n", dst_result_totext(ret));
		exit(-1);
	}

	ret = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE);
	if (ret != ISC_R_SUCCESS) {
		printf("Failed to write key %s(%d)\n", name, dst_key_id(key));
		exit(-1); 
	}

	printf("Generated %d bit key %s: id=%d alg=%d flags=%d\n\n", size,
	       name, dst_key_id(key), dst_key_alg(key), dst_key_flags(key));

	isc_mem_free(mctx, name);
	isc_mem_free(mctx, algname);
	isc_mem_free(mctx, nametype);
	isc_mem_free(mctx, prog);
	if (type != NULL)
		isc_mem_free(mctx, type);
	dst_key_free(key);
	isc_mem_destroy(&mctx);
	exit(0);
}

static isc_boolean_t
dsa_size_ok(int size) {
	return (ISC_TF(size >= 512 && size <= 1024 && size % 64 == 0));
}

static void
die(char *str) {
	printf("%s\n", str);
	exit(-1);
}

static void
usage(char *prog) {
	printf("Usage:\n");
	printf ("    %s [options] name\n\n", prog);
	printf("Required options:\n");
	printf("    -a algorithm: RSA | RSAMD5 | DH | DSA | HMAC-MD5\n");
	printf("    -b key size, in bits:\n");
	printf("        RSA:\t\t[512..1024]\n");
	printf("        DH:\t\t[128..4096]\n");
	printf("        DSA:\t\t[512..1024] and a multiple of 64\n");
	printf("        HMAC-MD5:\t[1..512]\n");
	printf("    -n nametype: ZONE | HOST | ENTITY | USER\n");
	printf("    name: owner of the key\n");
	printf("Other options:\n");
	printf("    -e use large exponent (RSA only)\n");
	printf("    -g use specified generator (DH only)\n");
	printf("    -t type: AUTHCONF | NOAUTHCONF | NOAUTH | NOCONF\n");
	printf("        default: AUTHCONF\n");
	printf("    -p protocol value\n");
	printf("        default: 2 (email) for User keys, 3 (dnssec) for all others\n");
	printf("    -s strength value this key signs DNS records with\n");
	printf("        default: 0\n");
	printf("    -v verbose level\n");

	exit (-1);
}
