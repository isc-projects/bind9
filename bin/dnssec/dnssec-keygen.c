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

 /* $Id: dnssec-keygen.c,v 1.1 1999/09/10 19:52:56 bwelling Exp $ */

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/boolean.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <dns/keyvalues.h>
#include <dst/dst.h>
#include <dst/result.h>

static isc_boolean_t dsa_size_ok(int size);
static void die(char *str);
static void usage(char *prog);

int
main(int argc, char **argv) {
	char		*prog;
	dst_key_t	*key;
	char		*name = NULL, *zonefile = NULL;
	isc_uint16_t	flags = 0;
	int		alg = -1;
	isc_mem_t	*mctx = NULL;
	int		ch, rsa_exp = 0;
	int		protocol = -1, size = -1;
	extern char	*optarg;
	extern int	optind;
	dst_result_t	ret;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	if ((prog = strrchr(argv[0],'/')) == NULL)
		prog = strdup(argv[0]);
	else
		prog = strdup(++prog);

/* process input arguments */
	while ((ch = getopt(argc, argv, "achiuzn:s:p:D:H:R:F"))!= EOF) {
	    switch (ch) {
		case 'a':
			flags |= DNS_KEYTYPE_NOAUTH;
			break;
		case 'c':
			flags |= DNS_KEYTYPE_NOCONF;
			break;
		case 'F':
			rsa_exp=1;
			break;
		case 'p':
			if (optarg && isdigit(optarg[0]))
				protocol = atoi(optarg);
				if (protocol < 0 || protocol > 255)
					die("-s value is not [0..15] ");
			else
				die("-p not followed by a number [0..255]");
			break;
		case 's':
			/* Default: not signatory key */
			if (optarg != NULL && isdigit(optarg[0])) {
				int sign_val = (int) atoi(optarg);
				if (sign_val < 0 || sign_val > 15)
					die("-s value is not [0..15] ");
				flags |= sign_val;
			}
			else
				die("-s not followed by a number [0..15] ");
			break;
		case 'h':
			if ((flags & DNS_KEYFLAG_OWNERMASK) != 0)
				die("Only one key type can be specified");
			flags |= DNS_KEYOWNER_ENTITY;
			break;
		case 'u' :
			if ((flags & DNS_KEYFLAG_OWNERMASK) != 0)
				die("Only one key type can be specified");
			flags |= DNS_KEYOWNER_USER;
			break ;
		case 'z':
			if ((flags & DNS_KEYFLAG_OWNERMASK) != 0)
				die("Only one key type can be specified");
			flags |= DNS_KEYOWNER_ZONE;
			break;
		case 'H':
			if (alg > 0) 
				die("Only one alg can be specified");
			if (optarg && isdigit(optarg[0]))
				size = (int) atoi(optarg);
			else
				die("-H requires a size");
			alg = DST_ALG_HMACMD5;
			break;
		case 'R':
			if (alg > 0) 
				die("Only one alg can be specified");
			if (optarg && isdigit(optarg[0]))
				size = (int) atoi(optarg);
			else
				die("-R requires a size");
			alg = DNS_KEYALG_RSA;
			break;
		case 'D':
			if (alg > 0) 
				die("Only one alg can be specified");
			if (optarg && isdigit(optarg[0]))
				size = (int) atoi(optarg);
			else
				die("-D requires a size");
			alg = DNS_KEYALG_DSA;
			break;
		default:
			printf("invalid argument -%c\n", ch);
			usage(prog);
		} 
	}

	if (optind == argc)
		usage(prog);

	if (alg < 0)
		die("No algorithm specified");
	if (dst_supported_algorithm(alg) == ISC_FALSE)
		die("Unsupported algorithm");

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
		
	if (size > 0) {
		if (alg == DNS_KEYALG_RSA) {
			if (size < 512 || size > 4096)
				die("RSA key size out of range");
		}
		else if (rsa_exp != 0)
			die("-F can only be specified with -R");

		if (alg == DNS_KEYALG_DSA && !dsa_size_ok(size))
			die("Invalid DSS key size");
	}
	else if (size < 0)
		die("No key size specified");

	name = argv[optind++];
	if (argc > optind)
		zonefile = argv[optind];
	if (name[strlen(name) - 1] != '.' && alg != DST_ALG_HMACMD5) {
		name = isc_mem_get(mctx, strlen(name) + 2);
		sprintf(name, "%s.", argv[optind - 1]);
		printf("** Added a trailing dot to the name to make it"
			" fully qualified **\n");
	}

	printf("Generating %d bit ", size);
	switch(alg) {
		case DNS_KEYALG_RSA:
			printf("RSA");
			break;
		case DNS_KEYALG_DSA:
			printf("DSS");
			break;
		case DST_ALG_HMACMD5:
			printf("HMAC-MD5");
			break;
		default:
			break;
	}
	printf(" key for %s\n\n", name);

	ret = dst_key_generate(name, alg, size, rsa_exp, flags, protocol, mctx,
			       &key);

	if (ret != DST_R_SUCCESS) {
		printf("Failed generating key %s\n", name);
		exit(-1);
	}

	ret = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE);
	if (ret != DST_R_SUCCESS) {
		printf("Failed to write key %s(%d)\n", name, dst_key_id(key));
		exit(-1); 
	}

	printf("Generated %d bit key %s: id=%d alg=%d flags=%d\n\n", size,
	       name, dst_key_id(key), dst_key_alg(key), dst_key_flags(key));

	if (zonefile != NULL) {
		/* append key to zonefile */
	}

	exit(0);
}

static isc_boolean_t
dsa_size_ok(int size) {
	return (size >= 512 && size <= 1024 && size % 64 == 0);
}

static void
die(char *str) {
	printf("%s\n", str);
	exit(-1);
}

static void
usage(char *prog) {
	printf("Usage:\n\t");
	printf ("%s <-D|-H|-R> <size> [-F] [-z|-h|-u] [-a] [-c] [-p n]"
	       " [-s n] name [zonefile] \n\n", prog);
	printf("\t-D generate DSA/DSS key: size must be in the range\n");
	printf("\t\t[512..1024] and a multiple of 64\n");
	printf("\t-H generate HMAC-MD5 key: size in the range [1..512]\n");
	printf("\t-R generate RSA key: size in the range [512..4096]\n");
	printf("\t-F use large exponent (RSA only)\n");

	printf("\t-z Zone key \n");
	printf("\t-h Host/Entity key \n");
	printf("\t-u User key (default) \n");

	printf("\t-a Key CANNOT be used for authentication\n");
	printf("\t-c Key CANNOT be used for encryption\n");

	printf("\t-p Set protocol field to <n>\n");
	printf("\t\t default: 2 (email) for User keys, 3 (dnssec) for all others\n");
	printf("\t-s Strength value this key signs DNS records with\n");
	printf("\t\t default: 0\n");
	printf("\tname: the owner of the key\n");

	exit (-1);
}


