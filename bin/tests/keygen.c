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

/* $Id: keygen.c,v 1.10 2000/03/23 19:03:32 bwelling Exp $ */

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <isc/boolean.h>
#include <isc/commandline.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
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
	int		ch, rsa_exp = 0, generator = 0, param = 0;
	int		protocol = -1, size = -1;
	isc_result_t	ret;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	if ((prog = strrchr(argv[0],'/')) == NULL)
		prog = strdup(argv[0]);
	else
		prog = strdup(++prog);

	while ((ch = isc_commandline_parse(argc, argv,
					   "achiuzn:s:p:D:H:R:d:Fg:")) != -1) {
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
		case 'g':
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff)) {
				generator = atoi(isc_commandline_argument);
				if (generator < 0)
					die("-g value is not positive");
			}
			else
				die("-g not followed by a number");
			break;
		case 'p':
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff)) {
				protocol = atoi(isc_commandline_argument);
				if (protocol < 0 || protocol > 255)
					die("-p value is not [0..15]");
			}
			else
				die("-p not followed by a number [0..255]");
			break;
		case 's':
			/* Default: not signatory key */
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff)) {
				int sign_val = atoi(isc_commandline_argument);
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
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff))
				size = atoi(isc_commandline_argument);
			else
				die("-H requires a size");
			alg = DST_ALG_HMACMD5;
			break;
		case 'R':
			if (alg > 0) 
				die("Only one alg can be specified");
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff))
				size = atoi(isc_commandline_argument);
			else
				die("-R requires a size");
			alg = DNS_KEYALG_RSA;
			break;
		case 'D':
			if (alg > 0) 
				die("Only one alg can be specified");
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff))
				size = atoi(isc_commandline_argument);
			else
				die("-D requires a size");
			alg = DNS_KEYALG_DSA;
			break;
		case 'd':
			if (alg > 0) 
				die("Only one alg can be specified");
			if (isc_commandline_argument != NULL &&
			    isdigit(isc_commandline_argument[0] & 0xff))
				size = atoi(isc_commandline_argument);
			else
				die("-d requires a size");
			alg = DNS_KEYALG_DH;
			break;
		default:
			printf("invalid argument -%c\n", ch);
			usage(prog);
		} 
	}

	if (isc_commandline_index == argc)
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

		if (alg == DNS_KEYALG_DH) {
			if (size < 16 || size > 4096)
				die("DH key size out of range");
		}
		else if (generator != 0)
			die("-g can only be specified with -d");

		if (alg == DNS_KEYALG_DSA && !dsa_size_ok(size))
			die("Invalid DSS key size");
	}
	else if (size < 0)
		die("No key size specified");

	name = argv[isc_commandline_index++];
	if (argc > isc_commandline_index)
		zonefile = argv[isc_commandline_index];
	if (name[strlen(name) - 1] != '.' && alg != DST_ALG_HMACMD5) {
		name = isc_mem_get(mctx, strlen(name) + 2);
		sprintf(name, "%s.", argv[isc_commandline_index - 1]);
		printf("** Added a trailing dot to the name to make it"
			" fully qualified **\n");
	}

	printf("Generating %d bit ", size);
	switch(alg) {
		case DNS_KEYALG_RSA:
			printf("RSA");
			param = rsa_exp;
			break;
		case DNS_KEYALG_DH:
			printf("DH");
			param = generator;
			break;
		case DNS_KEYALG_DSA:
			printf("DSS");
			param = 0;
			break;
		case DST_ALG_HMACMD5:
			printf("HMAC-MD5");
			param = 0;
			break;
		default:
			die("Unknown algorithm");
	}
	printf(" key for %s\n\n", name);

	dst_result_register();
	ret = dst_key_generate(name, alg, size, param, flags, protocol, mctx,
			       &key);

	if (ret != ISC_R_SUCCESS) {
		printf("Failed generating key %s\n", name);
		exit(-1);
	}

	ret = dst_key_tofile(key, DST_TYPE_PUBLIC | DST_TYPE_PRIVATE);
	if (ret != ISC_R_SUCCESS) {
		printf("Failed to write key %s(%d)\n", name, dst_key_id(key));
		exit(-1); 
	}

	printf("Generated %d bit key %s: id=%d alg=%d flags=%d\n\n", size,
	       name, dst_key_id(key), dst_key_alg(key), dst_key_flags(key));

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
	printf("Usage:\n\t");
	printf ("%s <-D|-H|-R|-d> <size> [-F] [-g n] [-z|-h|-u] [-a] [-c] "
		" [-p n] [-s n] name [zonefile] \n\n", prog);
	printf("\t-D generate DSA/DSS key: size must be in the range\n");
	printf("\t\t[512..1024] and a multiple of 64\n");
	printf("\t-H generate HMAC-MD5 key: size in the range [1..512]\n");
	printf("\t-R generate RSA key: size in the range [512..4096]\n");
	printf("\t-d generate DH key in the range [16..4096]\n");
	printf("\t-F use large exponent (RSA only)\n");
	printf("\t-g use specified generator (DH only)\n");

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


