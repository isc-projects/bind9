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

/* $Id: dnssec-keygen.c,v 1.23 2000/05/19 00:20:39 bwelling Exp $ */

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

#define PROGRAM "dnssec-keygen"

#define MAX_RSA 2048 /* XXX ogud update this when rsa library is updated */

static int verbose;

static void
fatal(char *format, ...) {
	va_list args;

	fprintf(stderr, "%s: ", PROGRAM);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

static inline void
check_result(isc_result_t result, char *message) {
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "%s: %s: %s\n", PROGRAM, message,
			isc_result_totext(result));
		exit(1);
	}
}

/* Not thread-safe! */
static char *
algtostr(const dns_secalg_t alg) {
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;
	static char data[10];

	isc_buffer_init(&b, data, sizeof(data));
	result = dns_secalg_totext(alg, &b);
	check_result(result, "dns_secalg_totext()");
	isc_buffer_usedregion(&b, &r);
	r.base[r.length] = 0;
	return (char *) r.base;
}

static isc_boolean_t
dsa_size_ok(int size) {
	return (ISC_TF(size >= 512 && size <= 1024 && size % 64 == 0));
}

static void
usage() {
	printf("Usage:\n");
	printf("    %s [options] name\n\n", PROGRAM);
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

int
main(int argc, char **argv) {
	char		*algname = NULL, *nametype = NULL, *type = NULL;
	char		*prog, *endp;
	dst_key_t	*key = NULL, *oldkey;
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
		fatal("out of memory");

	if (argc == 1)
		usage();

	while ((ch = isc_commandline_parse(argc, argv,
					   "a:b:eg:n:t:p:s:hv:")) != -1)
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
			generator = strtol(isc_commandline_argument, &endp, 10);
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
				PROGRAM, ch);
			usage();
		} 
	}

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

	name = isc_mem_allocate(mctx, strlen(argv[isc_commandline_index]) + 2);
	if (name == NULL)
		fatal("out of memory");
	strcpy(name, argv[isc_commandline_index]);
	if (name[strlen(name) - 1] != '.') {
		strcat(name, ".");
		fprintf(stderr,
			"%s: added a trailing dot to fully qualify the name\n",
			PROGRAM);
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
			fatal("failed to generate key %s/%d: %s\n", name, alg,
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
			dst_key_free(&oldkey);
			conflict = ISC_TRUE;
			if (null_key)
				break;
		}
		if (conflict == ISC_TRUE)
			dst_key_free(&key);

	} while (conflict == ISC_TRUE);

	if (conflict)
		fatal("cannot generate a null key when a key with id 0 "
		      "already exists");

	ret = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE);
	if (ret != ISC_R_SUCCESS)
		fatal("failed to write key %s/%s/%d: %s\n", name, 
			dst_key_id(key), algtostr(alg), isc_result_totext(ret));

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
	dst_key_free(&key);
	isc_mem_destroy(&mctx);

	return (0);
}
