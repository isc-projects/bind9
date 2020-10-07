/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/print.h>
#include <isc/util.h>
#include <isc/net.h>
#include <dns/edns.h>

#ifdef WIN32
#include <Winsock2.h>
#endif

#ifndef MAXHOSTNAMELEN
#ifdef HOST_NAME_MAX
#define MAXHOSTNAMELEN HOST_NAME_MAX
#else
#define MAXHOSTNAMELEN 256
#endif
#endif

static void
usage() {
	fprintf(stderr, "usage: feature-test <arg>\n");
	fprintf(stderr, "args:\n");
	fprintf(stderr, "\t--edns-version\n");
	fprintf(stderr, "\t--enable-filter-aaaa\n");
	fprintf(stderr, "\t--gethostname\n");
	fprintf(stderr, "\t--gssapi\n");
	fprintf(stderr, "\t--have-aes\n");
	fprintf(stderr, "\t--have-dlopen\n");
	fprintf(stderr, "\t--have-geoip2\n");
	fprintf(stderr, "\t--have-geoip\n");
	fprintf(stderr, "\t--have-libxml2\n");
	fprintf(stderr, "\t--ipv6only=no\n");
	fprintf(stderr, "\t--rpz-log-qtype-qclass\n");
	fprintf(stderr, "\t--rpz-nsdname\n");
	fprintf(stderr, "\t--rpz-nsip\n");
	fprintf(stderr, "\t--tsan\n");
	fprintf(stderr, "\t--with-dlz-filesystem\n");
	fprintf(stderr, "\t--with-idn\n");
	fprintf(stderr, "\t--with-lmdb\n");
}

int
main(int argc, char **argv) {
	if (argc != 2) {
		usage();
		return (1);
	}

	if (strcmp(argv[1], "--edns-version") == 0) {
#ifdef DNS_EDNS_VERSION
		printf("%d\n", DNS_EDNS_VERSION);
#else
		printf("0\n");
#endif
		return (0);
	}

	if (strcmp(argv[1], "--enable-filter-aaaa") == 0) {
#ifdef ALLOW_FILTER_AAAA
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--gethostname") == 0) {
		char hostname[MAXHOSTNAMELEN];
		int n;
#ifdef WIN32
		/* From lwres InitSocket() */
		WORD wVersionRequested;
		WSADATA wsaData;
		int err;

		wVersionRequested = MAKEWORD(2, 0);
		err = WSAStartup( wVersionRequested, &wsaData );
		if (err != 0) {
			fprintf(stderr, "WSAStartup() failed: %d\n", err);
			exit(1);
		}
#endif

		n = gethostname(hostname, sizeof(hostname));
		if (n == -1) {
			perror("gethostname");
			return(1);
		}
		fprintf(stdout, "%s\n", hostname);
#ifdef WIN32
		WSACleanup();
#endif
		return (0);
	}

	if (strcmp(argv[1], "--gssapi") == 0) {
#if defined(GSSAPI)
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-aes") == 0) {
#if defined(HAVE_OPENSSL_AES) || defined(HAVE_OPENSSL_EVP_AES)
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-dlopen") == 0) {
#if defined(HAVE_DLOPEN) && defined(ISC_DLZ_DLOPEN)
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-geoip") == 0) {
#ifdef HAVE_GEOIP
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-geoip2") == 0) {
#ifdef HAVE_GEOIP2
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--have-libxml2") == 0) {
#ifdef HAVE_LIBXML2
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--ipv6only=no") == 0) {
#ifdef WIN32
		return (0);
#elif defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
		int s;
		int n = -1;
		int v6only = -1;
		ISC_SOCKADDR_LEN_T len = sizeof(v6only);

		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (s >= 0) {
			n = getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
				       (void *)&v6only, &len);
			close(s);
		}
		return ((n == 0 && v6only == 0) ? 0 : 1);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--rpz-log-qtype-qclass") == 0) {
#ifdef RPZ_LOG_QTYPE_QCLASS
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--rpz-nsdname") == 0) {
#ifdef ENABLE_RPZ_NSDNAME
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--rpz-nsip") == 0) {
#ifdef ENABLE_RPZ_NSIP
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--tsan") == 0) {
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
		return (0);
#endif
#endif
#if __SANITIZE_THREAD__
		return (0);
#else
		return (1);
#endif
	}

	if (strcmp(argv[1], "--with-dlz-filesystem") == 0) {
#ifdef DLZ_FILESYSTEM
		return (0);
#else  /* ifdef DLZ_FILESYSTEM */
		return (1);
#endif /* ifdef DLZ_FILESYSTEM */
	}

	if (strcmp(argv[1], "--with-idn") == 0) {
#ifdef HAVE_LIBIDN2
		return (0);
#else  /* ifdef HAVE_LIBIDN2 */
		return (1);
#endif /* ifdef HAVE_LIBIDN2 */
	}

	if (strcmp(argv[1], "--with-lmdb") == 0) {
#ifdef HAVE_LMDB
		return (0);
#else  /* ifdef HAVE_LMDB */
		return (1);
#endif /* ifdef HAVE_LMDB */
	}

	fprintf(stderr, "unknown arg: %s\n", argv[1]);
	usage();
	return (1);
}
