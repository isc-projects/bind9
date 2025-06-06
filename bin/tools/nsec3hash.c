/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/attributes.h>
#include <isc/base32.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/hex.h>
#include <isc/iterated_hash.h>
#include <isc/lib.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/tls.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/nsec3.h>
#include <dns/types.h>

ISC_NORETURN static void
fatal(const char *format, ...);

static void
fatal(const char *format, ...) {
	va_list args;

	fprintf(stderr, "%s: ", isc_commandline_progname);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	_exit(EXIT_FAILURE);
}

static void
check_result(isc_result_t result, const char *message) {
	if (result != ISC_R_SUCCESS) {
		fatal("%s: %s", message, isc_result_totext(result));
	}
}

static void
usage(void) {
	fprintf(stderr, "Usage: %s salt algorithm iterations domain\n",
		isc_commandline_progname);
	fprintf(stderr, "       %s -r algorithm flags iterations salt domain\n",
		isc_commandline_progname);
	exit(EXIT_FAILURE);
}

typedef void
nsec3printer(unsigned int algo, unsigned int flags, unsigned int iters,
	     const char *saltstr, const char *domain, const char *digest);

static void
nsec3hash(nsec3printer *nsec3print, const char *algostr, const char *flagstr,
	  const char *iterstr, const char *saltstr, const char *domain) {
	dns_fixedname_t fixed;
	dns_name_t *name;
	isc_buffer_t buffer;
	isc_region_t region;
	isc_result_t result;
	unsigned char hash[NSEC3_MAX_HASH_LENGTH];
	unsigned char salt[DNS_NSEC3_SALTSIZE];
	unsigned char text[1024];
	unsigned int hash_alg;
	unsigned int flags;
	unsigned int length;
	unsigned int iterations;
	unsigned int salt_length;
	const char dash[] = "-";

	if (strcmp(saltstr, "-") == 0) {
		salt_length = 0;
		salt[0] = 0;
	} else {
		isc_buffer_init(&buffer, salt, sizeof(salt));
		result = isc_hex_decodestring(saltstr, &buffer);
		check_result(result, "isc_hex_decodestring(salt)");
		salt_length = isc_buffer_usedlength(&buffer);
		if (salt_length > DNS_NSEC3_SALTSIZE) {
			fatal("salt too long");
		}
		if (salt_length == 0) {
			saltstr = dash;
		}
	}
	hash_alg = atoi(algostr);
	if (hash_alg > 255U) {
		fatal("hash algorithm too large");
	}
	flags = flagstr == NULL ? 0 : atoi(flagstr);
	if (flags > 255U) {
		fatal("flags too large");
	}
	iterations = atoi(iterstr);
	if (iterations > 0xffffU) {
		fatal("iterations to large");
	}

	name = dns_fixedname_initname(&fixed);
	isc_buffer_constinit(&buffer, domain, strlen(domain));
	isc_buffer_add(&buffer, strlen(domain));
	result = dns_name_fromtext(name, &buffer, dns_rootname, 0);
	check_result(result, "dns_name_fromtext() failed");

	dns_name_downcase(name, name);
	length = isc_iterated_hash(hash, hash_alg, iterations, salt,
				   salt_length, name->ndata, name->length);
	if (length == 0) {
		fatal("isc_iterated_hash failed");
	}
	region.base = hash;
	region.length = length;
	isc_buffer_init(&buffer, text, sizeof(text));
	isc_base32hexnp_totext(&region, 1, "", &buffer);
	isc_buffer_putuint8(&buffer, '\0');

	nsec3print(hash_alg, flags, iterations, saltstr, domain, (char *)text);
}

static void
nsec3hash_print(unsigned int algo, unsigned int flags, unsigned int iters,
		const char *saltstr, const char *domain, const char *digest) {
	UNUSED(flags);
	UNUSED(domain);

	fprintf(stdout, "%s (salt=%s, hash=%u, iterations=%u)\n", digest,
		saltstr, algo, iters);
}

static void
nsec3hash_rdata_print(unsigned int algo, unsigned int flags, unsigned int iters,
		      const char *saltstr, const char *domain,
		      const char *digest) {
	fprintf(stdout, "%s NSEC3 %u %u %u %s %s\n", domain, algo, flags, iters,
		saltstr, digest);
}

int
main(int argc, char *argv[]) {
	bool rdata_format = false;
	int ch;

	isc_commandline_init(argc, argv);

	while ((ch = isc_commandline_parse(argc, argv, "-r")) != -1) {
		switch (ch) {
		case 'r':
			rdata_format = true;
			break;
		case '-':
			isc_commandline_index -= 1;
			goto skip;
		default:
			break;
		}
	}

skip:
	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (rdata_format) {
		if (argc != 5) {
			usage();
		}
		nsec3hash(nsec3hash_rdata_print, argv[0], argv[1], argv[2],
			  argv[3], argv[4]);
	} else {
		if (argc != 4) {
			usage();
		}
		nsec3hash(nsec3hash_print, argv[1], NULL, argv[2], argv[0],
			  argv[3]);
	}
	return 0;
}
