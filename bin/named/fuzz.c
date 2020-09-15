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

#include "config.h"

#include <inttypes.h>
#include <stdbool.h>

#include <named/fuzz.h>

#ifdef ENABLE_AFL
#include <named/globals.h>
#include <named/server.h>
#include <errno.h>

#include <isc/app.h>
#include <isc/condition.h>
#include <isc/mutex.h>
#include <isc/thread.h>
#include <isc/util.h>
#include <named/log.h>
#include <dns/log.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#ifndef __AFL_LOOP
#error To use American Fuzzy Lop you have to set CC to afl-clang-fast!!!
#endif

/*
 * We are using pthreads directly because we might be using it with unthreaded
 * version of BIND, where all thread functions are mocks. Since AFL for now only
 * works on Linux it's not a problem.
 */
static pthread_cond_t cond;
static pthread_mutex_t mutex;
static bool ready;


static void *
fuzz_main_client(void *arg) {
	char *host;
	char *port;
	struct sockaddr_in servaddr;
	int sockfd;
	int loop;
	void *buf;

	UNUSED(arg);

	/*
	 * Parse named -A argument in the "address:port" syntax. Due to
	 * the syntax used, this only supports IPv4 addresses.
	 */

	host = strdup(ns_g_fuzz_named_addr);
	RUNTIME_CHECK(host != NULL);
	port = strchr(host, ':');
	RUNTIME_CHECK(port != NULL);
	*port = 0;
	++port;

	memset(&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	RUNTIME_CHECK(inet_pton(AF_INET, host, &servaddr.sin_addr) == 1);
	servaddr.sin_port = htons(atoi(port));

	free(host);

	/* Wait for named to start. */
	while (!ns_g_run_done) {
		usleep(10000);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	RUNTIME_CHECK(sockfd != -1);

	buf = malloc(65536);
	RUNTIME_CHECK(buf != NULL);

	loop = 100000;
	while (loop--) {
		ssize_t length;

		length = read(0, buf, 65536);
		if (length <= 0) {
			usleep(1000000);
			continue;
		}

		if (length > 4096) {
			if (getenv("AFL_CMIN")) {
				ns_server_flushonshutdown(ns_g_server,
							  false);
				isc_app_shutdown();
				return (NULL);
			}
			raise(SIGSTOP);
			continue;
		}

		RUNTIME_CHECK(pthread_mutex_lock(&mutex) == ISC_R_SUCCESS);

		ready = false;

		ssize_t sent;

		sent = sendto(sockfd, buf, length, 0,
			      (struct sockaddr *) &servaddr, sizeof(servaddr));
		RUNTIME_CHECK(sent == length);

		/* unclog */
		recvfrom(sockfd, buf, 65536, MSG_DONTWAIT, NULL, NULL);

		while (!ready)
			pthread_cond_wait(&cond, &mutex);

		RUNTIME_CHECK(pthread_mutex_unlock(&mutex) == ISC_R_SUCCESS);
	}

	free(buf);
	close(sockfd);

	ns_server_flushonshutdown(ns_g_server, false);
	isc_app_shutdown();

	return (NULL);
}

static void *
fuzz_main_resolver(void *arg) {
	char *shost, *sport, *rhost, *rport;
	/* Query for A? aaaaaaaaaa.example. */
	char respacket[] =
		 "\0\0\1 \0\1\0\0\0\0\0\0\naaaaaaaaaa\7example\0\0\1\0\1";
	struct sockaddr_in servaddr, recaddr, recvaddr;
	int sockfd;
	int listenfd;
	int loop;
	char *buf, *rbuf;

	UNUSED(arg);

	/*
	 * Parse named -A argument in the "laddress:sport:raddress:rport"
	 * syntax.  Due to the syntax used, this only supports IPv4 addresses.
	 */

	shost = strdup(ns_g_fuzz_named_addr);
	RUNTIME_CHECK(shost != NULL);
	sport = strchr(shost, ':');
	RUNTIME_CHECK(sport != NULL);
	*sport = 0;
	sport++;
	rhost = strchr(sport, ':');
	RUNTIME_CHECK(rhost != NULL);
	*rhost = 0;
	rhost++;
	rport = strchr(rhost, ':');
	RUNTIME_CHECK(rport != NULL);
	*rport = 0;
	rport++;

	memset(&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	RUNTIME_CHECK(inet_pton(AF_INET, shost, &servaddr.sin_addr) == 1);
	servaddr.sin_port = htons(atoi(sport));

	memset(&recaddr, 0, sizeof (recaddr));
	recaddr.sin_family = AF_INET;
	RUNTIME_CHECK(inet_pton(AF_INET, rhost, &recaddr.sin_addr) == 1);
	recaddr.sin_port = htons(atoi(rport));

	free(shost);

	/* Wait for named to start */
	while (!ns_g_run_done) {
		usleep(10000);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	RUNTIME_CHECK(sockfd != -1);

	listenfd = socket(AF_INET, SOCK_DGRAM, 0);
	RUNTIME_CHECK(listenfd != -1);
	RUNTIME_CHECK(bind(listenfd, (struct sockaddr *)&recaddr,
			   sizeof(struct sockaddr_in)) == 0);

	buf = malloc(65536);
	rbuf = malloc(65536);
	RUNTIME_CHECK(buf != NULL);
	RUNTIME_CHECK(rbuf != NULL);

	loop = 100000;
	while (loop--) {
		ssize_t length;
		memset(buf, 0, 16);
		length = read(0, buf, 65536);
		if (length <= 0) {
			usleep(1000000);
			continue;
		}

		if (length > 4096) {
			if (getenv("AFL_CMIN")) {
				ns_server_flushonshutdown(ns_g_server,
					false);
				isc_app_shutdown();
				return (NULL);
			}
			raise(SIGSTOP);
			continue;
		}

		if (length < 16) {
		    length = 16;
		}

		RUNTIME_CHECK(pthread_mutex_lock(&mutex) == ISC_R_SUCCESS);

		ready = false;

		ssize_t sent;
		/* Randomize query ID. */
		int id = random();
		respacket[0] = id >> 8;
		respacket[1] = id & 0xff;

		/* flush */
		socklen_t socklen = sizeof(recvaddr);
		sent = recvfrom(listenfd, rbuf, 65536, MSG_DONTWAIT,
			(struct sockaddr *) &recvaddr, &socklen);

		sent = sendto(sockfd, respacket, sizeof(respacket), 0,
		       (struct sockaddr *) &servaddr, sizeof(servaddr));
		RUNTIME_CHECK(sent == sizeof(respacket));

		socklen = sizeof(recvaddr);
		sent = recvfrom(listenfd, rbuf, 65536, 0,
				(struct sockaddr *) &recvaddr, &socklen);
		RUNTIME_CHECK(sent > 0);

		/* Copy QID and set QR so that response is always processed. */
		buf[0] = rbuf[0];
		buf[1] = rbuf[1];
		buf[2] |= 0x80;

		sent = sendto(listenfd, buf, length, 0,
			      (struct sockaddr *) &recvaddr, sizeof(recvaddr));
		RUNTIME_CHECK(sent == length);

		/* We might get additional questions here (e.g. for CNAME). */
		for (;;) {
			fd_set fds;
			struct timeval tv;
			int rv;
			int max;

			FD_ZERO(&fds);
			FD_SET(listenfd, &fds);
			FD_SET(sockfd, &fds);
			tv.tv_sec = 10;
			tv.tv_usec = 0;
			max = (listenfd > sockfd ? listenfd : sockfd)+1;

			rv = select(max, &fds, NULL, NULL, &tv);
			RUNTIME_CHECK(rv > 0);

			if (FD_ISSET(sockfd, &fds)) {
				/* It's the reply, we're done. */
				recvfrom(sockfd, buf, 65536, 0, NULL, NULL);
				break;
			}

			/*
			 * We've got additional question (eg. cname chain)
			 * We are bouncing it - setting QR flag and NOERROR
			 * rcode and sending it back.
			 */

			length = recvfrom(listenfd, buf, 65536, 0,
				   (struct sockaddr *) &recvaddr, &socklen);
			buf[2] |= 0x80;
			buf[3] &= 0xF0;
			sent = sendto(listenfd, buf, length, 0,
				      (struct sockaddr *) &recvaddr,
				      sizeof(recvaddr));
			RUNTIME_CHECK(sent == length);
		}

		while (!ready)
			pthread_cond_wait(&cond, &mutex);

		RUNTIME_CHECK(pthread_mutex_unlock(&mutex) == 0);
	}

	free(buf);
	free(rbuf);
	close(sockfd);
	ns_server_flushonshutdown(ns_g_server, false);
	isc_app_shutdown();

	/*
	 * It's here just for the signature, that's how AFL detects if it's
	 * a 'persistent mode' binary.
	 */
	__AFL_LOOP(0);

	return (NULL);
}

static void *
fuzz_main_tcp(void *arg) {
	char *host;
	char *port;
	struct sockaddr_in servaddr;
	int sockfd;
	char *buf;
	int loop;

	UNUSED(arg);

	/*
	 * Parse named -A argument in the "address:port" syntax. Due to
	 * the syntax used, this only supports IPv4 addresses.
	 */

	host = strdup(ns_g_fuzz_named_addr);
	RUNTIME_CHECK(host != NULL);
	port = strchr(host, ':');
	RUNTIME_CHECK(port != NULL);
	*port = 0;
	++port;

	memset(&servaddr, 0, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	RUNTIME_CHECK(inet_pton(AF_INET, host, &servaddr.sin_addr) == 1);
	servaddr.sin_port = htons(atoi(port));

	free(host);

	/* Wait for named to start */
	while (!ns_g_run_done) {
		usleep(10000);
	}

	buf = malloc(65539);
	RUNTIME_CHECK(buf != NULL);

	loop = 100000;
	while (loop--) {
		ssize_t length;

		if (ns_g_fuzz_type == ns_fuzz_tcpclient) {
			/*
			 * To fuzz TCP client we have to put length at
			 * the start of packet.
			 */
			length = read(0, buf+2, 65535);
			buf[0] = length >> 8;
			buf[1] = length & 0xff;
			length += 2;
		} else {
			length = read(0, buf, 65535);
		}
		if (length <= 0) {
			usleep(1000000);
			continue;
		}
		if (ns_g_fuzz_type == ns_fuzz_http) {
			/*
			 * This guarantees that the request will be processed.
			 */
			buf[length++]='\r';
			buf[length++]='\n';
			buf[length++]='\r';
			buf[length++]='\n';
		}

		RUNTIME_CHECK(pthread_mutex_lock(&mutex) == ISC_R_SUCCESS);

		ready = false;

		ssize_t sent;
		int yes = 1;
		int r;
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

		RUNTIME_CHECK(sockfd != -1);
		RUNTIME_CHECK(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
					 &yes, sizeof(int)) == 0);

		do {
			r = connect(sockfd, (struct sockaddr*)&servaddr,
				    sizeof(servaddr));
		} while (r != 0);

		sent = write(sockfd, buf, length);
		RUNTIME_CHECK(sent == length);
		close(sockfd);

		/* unclog */
		recvfrom(sockfd, buf, 65537, MSG_DONTWAIT, NULL, NULL);

		while (!ready)
			pthread_cond_wait(&cond, &mutex);

		RUNTIME_CHECK(pthread_mutex_unlock(&mutex) == ISC_R_SUCCESS);
	}

	free(buf);
	close(sockfd);
	ns_server_flushonshutdown(ns_g_server, false);
	isc_app_shutdown();

	return (NULL);
}

#endif /* ENABLE_AFL */

void
named_fuzz_notify(void) {
#ifdef ENABLE_AFL
	if (getenv("AFL_CMIN")) {
		ns_server_flushonshutdown(ns_g_server, false);
		isc_app_shutdown();
		return;
	}

	raise(SIGSTOP);

	RUNTIME_CHECK(pthread_mutex_lock(&mutex) == 0);

	ready = true;

	RUNTIME_CHECK(pthread_cond_signal(&cond) == 0);
	RUNTIME_CHECK(pthread_mutex_unlock(&mutex) == 0);
#endif /* ENABLE_AFL */
}

void
named_fuzz_setup(void) {
#ifdef ENABLE_AFL
	if (getenv("__AFL_PERSISTENT") || getenv("AFL_CMIN")) {
		pthread_t thread;
		void *(fn) = NULL;

		switch (ns_g_fuzz_type) {
		case ns_fuzz_client:
			fn = fuzz_main_client;
			break;

		case ns_fuzz_http:
		case ns_fuzz_tcpclient:
		case ns_fuzz_rndc:
			fn = fuzz_main_tcp;
			break;
		case ns_fuzz_resolver:
			fn = fuzz_main_resolver;
			break;
		default:
			RUNTIME_CHECK(fn != NULL);
		}

		RUNTIME_CHECK(pthread_mutex_init(&mutex, NULL) == 0);
		RUNTIME_CHECK(pthread_cond_init(&cond, NULL) == 0);
		RUNTIME_CHECK(pthread_create(&thread, NULL, fn, NULL) == 0);
	}
#endif /* ENABLE_AFL */
}
