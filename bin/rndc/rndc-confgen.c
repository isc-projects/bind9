/*
 * Copyright (C) 2001  Internet Software Consortium.
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

/* $Id: rndc-confgen.c,v 1.2 2001/06/29 23:32:09 gson Exp $ */

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
#include <isc/result.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/keyvalues.h>
#include <dns/name.h>

#include <dst/dst.h>

#include "util.h"

#define DEFAULT_KEYLENGTH	128		/* Bits. */
#define DEFAULT_KEYNAME		"rndc-key"
#define DEFAULT_SERVER		"127.0.0.1"
#define DEFAULT_PORT		953

char progname[256];
isc_boolean_t verbose = ISC_FALSE;

static void
usage(int status) {
	fprintf(stderr, "\
Usage:\n\
 %s [-b bits] [-k keyname] [-P] [-p port] [-r randomfile] [-s addr]\n\
  -b bits:	from 1 through 512, default %d; total length of the secret\n\
  -k keyname:	the name as it will be used  in named.conf and rndc.conf\n\
  -P:		using pseudorandom data for key generation is ok\n\
  -p port:	the port named will listen on and rndc will connect to\n\
  -r randomfile: a file containing random data\n\
  -s addr:	the address to which rndc should connect\n",
		progname, DEFAULT_KEYLENGTH);

	exit (status);
}

int
main(int argc, char **argv) {
	isc_boolean_t show_final_mem = ISC_FALSE;
	isc_boolean_t pseudorandom = ISC_FALSE;
	isc_buffer_t key_rawbuffer;
	isc_buffer_t key_txtbuffer;
	isc_region_t key_rawregion;
	isc_mem_t *mctx = NULL;
	isc_entropy_t *ectx = NULL;
	isc_entropysource_t *entropy_source = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	dst_key_t *key = NULL;
	const char *keyname = NULL;
	const char *randomfile = NULL;
	const char *serveraddr = NULL;
	char key_rawsecret[64];
	char key_txtsecret[256];
	char *p;
	int ch;
	int port;
	int keysize;
	int entropy_flags = 0;
	int open_keyboard = ISC_ENTROPY_KEYBOARDMAYBE;
	struct in_addr addr;

	result = isc_file_progname(*argv, progname, sizeof(progname));
	if (result != ISC_R_SUCCESS)
		memcpy(progname, "rndc", 5);

	keyname = DEFAULT_KEYNAME;
	keysize = DEFAULT_KEYLENGTH;
	serveraddr = DEFAULT_SERVER;
	port = DEFAULT_PORT;

	while ((ch = isc_commandline_parse(argc, argv, "b:hk:MmPp:r:s:Vy"))
	       != -1) {
		switch (ch) {
		case 'b':
			keysize = strtol(isc_commandline_argument, &p, 10);
			if (*p != '\0' || keysize < 0)
				fatal("-b requires a non-negative number");
			if (keysize < 1 || keysize > 512)
				fatal("-b must be in the range 1 through 512");
			break;
		case 'h':
			usage(0);
		case 'k':
		case 'y':	/* Compatible with rndc -y. */
			keyname = isc_commandline_argument;
			break;
		case 'M':
			isc_mem_debugging = 1;
			break;

		case 'm':
			show_final_mem = ISC_TRUE;
			break;
		case 'P':
			pseudorandom = ISC_TRUE;
			open_keyboard = ISC_ENTROPY_KEYBOARDNO;
			break;
		case 'p':
			port = strtol(isc_commandline_argument, &p, 10);
			if (*p != '\0' || port < 0 || port > 65535)
				fatal("port '%s' out of range",
				      isc_commandline_argument);
			break;
		case 'r':
			randomfile = isc_commandline_argument;
			break;
		case 's':
			serveraddr = isc_commandline_argument;
			if (inet_aton(serveraddr, &addr) == 0)
				fatal("-s should be an IPv4 or IPv6 address");
				
			break;
		case 'V':
			verbose = ISC_TRUE;
			break;
		case '?':
			usage(1);
			break;
		default:
			fatal("unexpected error parsing command arguments: "
			      "got %c\n", ch);
			break;
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc > 0)
		usage(1);

	DO("create memory context", isc_mem_create(0, 0, &mctx));

	DO("create entropy context", isc_entropy_create(mctx, &ectx));

	DO("start entropy source", isc_entropy_usebestsource(ectx,
							     &entropy_source,
							     randomfile,
							     open_keyboard));

	if (! pseudorandom)
		entropy_flags = ISC_ENTROPY_BLOCKING | ISC_ENTROPY_GOODONLY;

	DO("initialize dst library", dst_lib_init(mctx, ectx, entropy_flags));

	DO("generate key", dst_key_generate(dns_rootname, DST_ALG_HMACMD5,
					    keysize, 0, 0,
					    DNS_KEYPROTO_ANY,
					    dns_rdataclass_in, mctx, &key));

	isc_buffer_init(&key_rawbuffer, &key_rawsecret, sizeof(key_rawsecret));

	DO("dump key to buffer", dst_key_tobuffer(key, &key_rawbuffer));

	isc_buffer_init(&key_txtbuffer, &key_txtsecret, sizeof(key_txtsecret));
	isc_buffer_usedregion(&key_rawbuffer, &key_rawregion);

	DO("bsse64 encode secret", isc_base64_totext(&key_rawregion, -1, "",
						     &key_txtbuffer));

	/*
	 * Shut down the entropy source now so the "stop typing" message
	 * does not muck with the output.
	 */
	if (entropy_source != NULL)
		isc_entropy_destroysource(&entropy_source);

	if (key != NULL)
		dst_key_free(&key);

	isc_entropy_detach(&ectx);
	dst_lib_destroy();

	if (open_keyboard)
		/*
		 * Add a little vertical whitespace to separate it
		 * from the "stop typing" message".
		 */
		printf("\n\n");

	printf("\
# Start of rndc.conf\n\
key \"%s\" {\n\
	algorithm hmac-md5;\n\
	secret \"%.*s\";\n\
};\n\
\n\
options {\n\
	default-key \"%s\";\n\
	default-server %s;\n\
	default-port %d;\n\
};\n\
# End of rndc.conf\n\
\n\
# Use with the following in named.conf, adjusting the allow list as needed:\n\
# key \"%s\" {\n\
# 	algorithm hmac-md5;\n\
# 	secret \"%.*s\";\n\
# };\n\
# \n\
# controls {\n\
# 	inet %s port %d\n\
# 		allow { %s; } keys { \"%s\"; };\n\
# };\n\
# End of named.conf\n",
	       keyname,
	       (int)isc_buffer_usedlength(&key_txtbuffer),
	       (char *)isc_buffer_base(&key_txtbuffer),
	       keyname, serveraddr, port,
	       keyname,
	       (int)isc_buffer_usedlength(&key_txtbuffer),
	       (char *)isc_buffer_base(&key_txtbuffer),
	       serveraddr, port, serveraddr, keyname);

	if (show_final_mem)
		isc_mem_stats(mctx, stderr);

	isc_mem_destroy(&mctx);

	return (0);
}
