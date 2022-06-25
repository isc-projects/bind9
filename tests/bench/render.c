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
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/time.h>

#include <dns/message.h>

static void
CHECKRESULT(isc_result_t result, const char *msg) {
	if (result != ISC_R_SUCCESS) {
		printf("%s: %s\n", msg, isc_result_totext(result));
		exit(1);
	}
}

int
main(int argc, char *argv[]) {
	isc_result_t result;
	ssize_t r;

	isc_mem_t *mctx = NULL;
	isc_mem_create(&mctx);

	dns_message_t **message;
	message = isc_mem_allocate(mctx, argc * sizeof(*message));

	for (int i = 1; i < argc; i++) {
		const char *filename = argv[i];

		int fd = open(filename, O_RDONLY);
		if (fd < 0)
			err(1, "open(%s)", filename);

		isc_buffer_t *filebuf = NULL;
		isc_buffer_allocate(mctx, &filebuf, 64 * 1024);

		struct stat st;
		r = fstat(fd, &st);
		if (r < 0)
			err(1, "stat(%s)", filename);
		if (st.st_size > isc_buffer_availablelength(filebuf))
			errx(1, "%s is too large", filename);
		unsigned int filelen = (unsigned int)st.st_size;

		isc_buffer_reserve(&filebuf, filelen);
		r = read(fd, isc_buffer_base(filebuf), filelen);
		if (r < 0)
			err(1, "read(%s)", filename);
		if (st.st_size > r)
			errx(1, "read(%s) truncated", filename);
		isc_buffer_add(filebuf, filelen);
		close(fd);

		message[i] = NULL;
		dns_message_create(mctx, DNS_MESSAGE_INTENTPARSE, &message[i]);

		result = dns_message_parse(message[i], filebuf,
					   DNS_MESSAGEPARSE_PRESERVEORDER);
		CHECKRESULT(result, "dns_message_parse()");
		isc_buffer_free(&filebuf);

		continue;

		isc_buffer_t *printbuf = NULL;
		isc_buffer_allocate(mctx, &printbuf, 1024 * 1024);

		result = dns_message_totext(message[i], &dns_master_style_debug,
					    0, printbuf);
		CHECKRESULT(result, "dns_message_totext()");

		r = write(1, isc_buffer_base(printbuf),
			  isc_buffer_usedlength(printbuf));
		if (r < 0)
			err(1, "write(%s)", filename);
		isc_buffer_free(&printbuf);
	}

	isc_time_t start;
	isc_time_now_hires(&start);

	unsigned int count = 0;
	int repeat = 100;
	for (int n = 0; n < repeat; n++) {
		for (int i = 1; i < argc; i++) {
			isc_buffer_t *wirebuf = NULL;
			isc_buffer_allocate(mctx, &wirebuf, 64 * 1024);

			/* hacks! see wire_test.c */
			message[i]->from_to_wire = DNS_MESSAGE_INTENTRENDER;
			for (int s = 0; s < DNS_SECTION_MAX; s++) {
				message[i]->counts[s] = 0;
			}

			dns_compress_t cctx;
			dns_compress_init(&cctx, mctx, DNS_COMPRESS_LARGE);

			result = dns_message_renderbegin(message[i], &cctx,
							 wirebuf);
			CHECKRESULT(result, "dns_message_renderbegin()");
			result = dns_message_rendersection(
				message[i], DNS_SECTION_QUESTION, 0);
			CHECKRESULT(result,
				    "dns_message_rendersection(QUESTION)");
			result = dns_message_rendersection(
				message[i], DNS_SECTION_ANSWER, 0);
			CHECKRESULT(result,
				    "dns_message_rendersection(ANSWER)");
			result = dns_message_rendersection(
				message[i], DNS_SECTION_AUTHORITY, 0);
			CHECKRESULT(result,
				    "dns_message_rendersection(AUTHORITY)");
			result = dns_message_rendersection(
				message[i], DNS_SECTION_ADDITIONAL, 0);
			CHECKRESULT(result,
				    "dns_message_rendersection(ADDITIONAL)");
			if (count < cctx.count)
				count = cctx.count;

			dns_message_renderend(message[i]);

			dns_compress_invalidate(&cctx);
			isc_buffer_free(&wirebuf);
		}
	}

	isc_time_t finish;
	isc_time_now_hires(&finish);
	uint64_t microseconds = isc_time_microdiff(&finish, &start);
	printf("time %f\n", (double)microseconds / (repeat * 1000000.0));
	printf("count %u\n", count);

	for (int i = 1; i < argc; i++) {
		dns_message_detach(&message[i]);
	}

	isc_mem_free(mctx, message);
	isc_mem_destroy(&mctx);

	return (0);
}
