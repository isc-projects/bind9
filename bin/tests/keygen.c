/*
 * Portions Copyright (c) 1995-2000 by Network Associates, Inc.
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

/* $Id: keygen.c,v 1.18 2000/05/15 21:06:41 bwelling Exp $ */

#include <config.h>

#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/secalg.h>
#include <dst/dst.h>
#include <dst/result.h>

static isc_boolean_t dsa_size_ok(int size);
static void die(char *str);
static void usage(char *prog);

static int verbose;
#define MAX_RSA 2048 /* XXX ogud update this when rsa library is updated */

int
main(int argc, char **argv) {
	char		*algname = NULL, *nametype = NULL, *type = NULL;
	char		*prog, *endp;
	dst_key_t	*key, *oldkey;
	char		*name = NULL;
	isc_uint16_t	flags = 0;
	dns_secalg_t	alg;
	isc_boolean_t    conflict = ISC_FALSE, null_key = ISC_FALSE;
	isc_mem_t	*mctx = NULL;
	int		ch, rsa_exp = 0, generator = 0, param = 0;
	int		protocol = -1, size = -1, signatory = 0;
	isc_result_t	ret;
	isc_textregion_t r;
	char		filename[255];
	isc_buffer_t	buf;

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
				die("-p must be followed by "
				    "a number [0..255]");
			break;
		case 's':
			signatory = strtol(isc_commandline_argument,
					   &endp, 10);
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
			fprintf(stderr, "keygen: invalid argument -%c\n", ch);
			usage(prog);
		} 
	}

	if (argc < isc_commandline_index + 1)
		die("Must specify a domain name");
	if (argc > isc_commandline_index + 1)
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
			die("Invalid type");
	}

	if (size < 0)
		die("Must specify key size (-b option)");

	switch (alg) {
	case DNS_KEYALG_RSA:
		if (size != 0 && (size < 512 || size > MAX_RSA))
			die("RSA key size out of range");
		break;
	case DNS_KEYALG_DH:
		if (size != 0 && (size < 128 || size > 4096))
			die("DH key size out of range");
		break;
	case DNS_KEYALG_DSA:
		if (size != 0 && !dsa_size_ok(size))
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
		fprintf(stderr,
			"keygen: added a trailing dot to fully qualify "
			"the name\n");
	}

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
	dst_result_register();

	do { 
		conflict = ISC_FALSE; 
		oldkey = NULL;

		/* generate the key */
		ret = dst_key_generate(name, alg, size, param, flags, protocol,
				       mctx, &key);

		if (ret != ISC_R_SUCCESS) {
			fprintf(stderr, "keygen: failed to generate key: %s\n", 
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
				       DST_TYPE_PRIVATE, mctx, &oldkey);
		/* do not overwrite an existing key  */
		if (ret == ISC_R_SUCCESS) {
			dst_key_free(oldkey);
			conflict = ISC_TRUE;
			if (null_key)
				break;
		}
		if (conflict == ISC_TRUE)
			dst_key_free(key);

	} while (conflict == ISC_TRUE);

	if (conflict)
		die("Attempting to generate a null key when a key with id 0 "
		    "already exists\n");

	ret = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE);
	if (ret != ISC_R_SUCCESS) {
		fprintf(stderr, "keygen: failed to write key %s(%d)\n", name, 
			dst_key_id(key));
		exit(-1); 
	}

	isc_buffer_clear(&buf);
	ret = dst_key_buildfilename(key, 0, &buf);
	filename[isc_buffer_usedlength(&buf)] = 0;
	printf("%s\n", filename);
	isc_mem_free(mctx, name);
	isc_mem_free(mctx, algname);
	isc_mem_free(mctx, nametype);
	isc_mem_free(mctx, prog);
	if (type != NULL)
		isc_mem_free(mctx, type);
	dst_key_free(key);
	isc_mem_destroy(&mctx);

	return (0);
}

static isc_boolean_t
dsa_size_ok(int size) {
	return (ISC_TF(size >= 512 && size <= 1024 && size % 64 == 0));
}

static void
die(char *str) {
	fprintf(stderr, "keygen: %s\n", str);
	exit(-1);
}

static void
usage(char *prog) {
	printf("Usage:\n");
	printf("    %s [options] name\n\n", prog);
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
	printf("    -t type: AUTHCONF | NOAUTHCONF | NOAUTH | NOCONF\n");
	printf("        default: AUTHCONF\n");
	printf("    -p protocol value\n");
	printf("        default: 2 (email) for User keys, "
	       			"3 (dnssec) for all others\n");
	printf("    -s strength value this key signs DNS records with\n");
	printf("        default: 0\n");
	printf("    -v verbose level\n");

	exit (-1);
}
