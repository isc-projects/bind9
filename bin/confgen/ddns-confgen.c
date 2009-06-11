/*
 * Copyright (C) 2009  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id: ddns-confgen.c,v 1.3 2009/06/11 20:01:22 jinmei Exp $ */

/*! \file */

/**
 * ddns-confgen generates configuration files for dynamic DNS. It can
 * be used as a convenient alternative to writing the ddns.key file
 * and the corresponding key and update-policy statements in named.conf.
 */

#include <config.h>

#include <stdlib.h>
#include <stdarg.h>

#include <isc/assertions.h>
#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/entropy.h>
#include <isc/file.h>
#include <isc/keyboard.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/name.h>

#include <dst/dst.h>
#include <confgen/os.h>

#include "util.h"
#include "keygen.h"

#define DEFAULT_KEYNAME		"ddns-key"

static char program[256];
const char *progname;

isc_boolean_t verbose = ISC_FALSE;

static void
usage(int status) {

	fprintf(stderr, "\
Usage:\n\
 %s [-a alg] [-k keyname] [-r randomfile] [-q] [-z zone]\n\
  -a alg:        algorithm (default hmac-sha256)\n\
  -k keyname:	 name of the key as it will be used in named.conf\n\
  -r randomfile: source of random data (use \"keyboard\" for key timing)\n\
  -z zone:	 name of the zone as it will be used named.conf\n\
  -q:		 quiet mode: print the key, with no explanatory text\n",
		 progname);

	exit (status);
}

int
main(int argc, char **argv) {
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_boolean_t quiet = ISC_FALSE;
	isc_boolean_t self = ISC_FALSE;
	isc_buffer_t key_txtbuffer;
	char key_txtsecret[256];
	isc_mem_t *mctx = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	const char *randomfile = NULL;
	const char *keyname = NULL;
	const char *zone = NULL;
	char *keybuf = NULL;
	dns_secalg_t alg = DST_ALG_HMACSHA256;
	const char *algname = alg_totext(alg);
	int keysize = 256;
	int len = 0;
	int ch;

	result = isc_file_progname(*argv, program, sizeof(program));
	if (result != ISC_R_SUCCESS)
		memcpy(program, "ddns-confgen", 13);
	progname = program;

	isc_commandline_errprint = ISC_FALSE;

	while ((ch = isc_commandline_parse(argc, argv,
					   "a:hk:Mmr:qsVy:")) != -1) {
		switch (ch) {
		case 'a':
			algname = isc_commandline_argument;
                        alg = alg_fromtext(algname);
                        if (alg == DST_ALG_UNKNOWN)
				fatal("Unsupported algorithm '%s'", algname);
                        keysize = alg_bits(alg);
			break;
		case 'h':
			usage(0);
		case 'k':
		case 'y':
			keyname = isc_commandline_argument;
			break;
		case 'M':
			isc_mem_debugging = ISC_MEM_DEBUGTRACE;
			break;
		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		case 'q':
			quiet = ISC_TRUE;
			break;
		case 'r':
			randomfile = isc_commandline_argument;
			break;
		case 's':
			self = ISC_TRUE;
			break;
		case 'V':
			verbose = ISC_TRUE;
			break;
		case '?':
			if (isc_commandline_option != '?') {
				fprintf(stderr, "%s: invalid argument -%c\n",
					program, isc_commandline_option);
				usage(1);
			} else
				usage(0);
			break;
		default:
			fprintf(stderr, "%s: unhandled option -%c\n",
				program, isc_commandline_option);
			exit(1);
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

        if (argc == 1)
                zone = argv[0];

	if (argc > 1)
		usage(1);

	DO("create memory context", isc_mem_create(0, 0, &mctx));

        if (self) {
                if (zone == NULL)
                        usage(1);
                keyname = zone;
        } else {
                if (keyname == NULL)
                        keyname = DEFAULT_KEYNAME;

                if (zone != NULL) {
                        len = strlen(keyname) + strlen(zone) + 2;
                        keybuf = isc_mem_get(mctx, len);
                        snprintf(keybuf, len, "%s.%s", keyname, zone);
                        keyname = (const char *) keybuf;
                }
        }

	isc_buffer_init(&key_txtbuffer, &key_txtsecret, sizeof(key_txtsecret));

	generate_key(mctx, randomfile, alg, keysize, &key_txtbuffer);


	if (!quiet)
		printf("\
# To activate this key, place the following in named.conf, and\n\
# in a separate keyfile on the system or systems from which nsupdate\n\
# will be run:\n");

	printf("\
key \"%s\" {\n\
	algorithm %s;\n\
	secret \"%.*s\";\n\
};\n",
	       keyname, algname,
	       (int)isc_buffer_usedlength(&key_txtbuffer),
	       (char *)isc_buffer_base(&key_txtbuffer));

	if (!quiet) {
		if (zone == NULL) {
			printf("\n\
# Then, in the \"zone\" statement for each zone you wish to dynamically\n\
# update, place an \"update-policy\" statement granting update permission\n\
# to this key.  For example, the following statement grants this key\n\
# permission to update any name within the zone:\n\
update-policy {\n\
	grant %s zonesub ANY;\n\
};\n",
			       keyname);
		} else if (self) {
			printf("\n\
# Finally, in the \"zone\" statement for the zone containing the\n\
# name \"%s\", place an \"update-policy\" statement\n\
# like this one, adjusted as needed for your preferred permissions:\n\
update-policy {\n\
	  grant %s self . ANY;\n\
};\n",
			       zone, keyname);
		} else {
			printf("\n\
# Finally, in the \"zone\" definition statement for \"%s\",\n\
# place an \"update-policy\" statement like this one, adjusted as \n\
# needed for your preferred permissions:\n\
update-policy {\n\
	  grant %s subdomain %s%s ANY;\n\
};\n",
			       zone, keyname, zone,
                               zone[strlen(zone) - 1] == '.' ? "" : ".");
		}

	printf("\n\
# After the keyfile has been created, the following command will\n\
# execute nsupdate using this key:\n\
nsupdate -k <keyfile>\n");
	}

	if (zone != NULL && keybuf != NULL)
		isc_mem_put(mctx, keybuf, len);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	isc_mem_destroy(&mctx);

	return (0);
}
