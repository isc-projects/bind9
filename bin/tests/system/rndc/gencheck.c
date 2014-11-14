/*
 * Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define USAGE "usage: gencheck <filename>\n"

static int
check(const char *buf, ssize_t count, size_t *start) {
	const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	ssize_t i;

	for (i = 0; i < count; i++, *start = (*start + 1) % (sizeof(chars) - 1)) {
		/* Just ignore the trailing newline */
		if (buf[i] == '\n')
			continue;
		if (buf[i] != chars[*start])
			return 0;
	}

	return 1;
}

int
main(int argc, char **argv)
{
	int ret;
	int fd;
	ssize_t count;
	char buf[1024];
	size_t start;
	size_t length;

	ret = EXIT_FAILURE;
	fd = -1;
	length = 0;

	if (argc != 2) {
		fputs(USAGE, stderr);
		goto out;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		goto out;

	start = 0;
	while ((count = read(fd, buf, sizeof(buf))) != 0) {
		if (count < 0)
			goto out;

		if (!check(buf, count, &start))
			goto out;

		length += count;
	}

	ret = EXIT_SUCCESS;

 out:
	printf("%zu\n", length);

	if (fd != -1)
		close(fd);

	return (ret);
}
