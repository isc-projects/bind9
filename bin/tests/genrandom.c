/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: genrandom.c,v 1.2 2000/08/09 00:21:26 bwelling Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int
main(int argc, char **argv) {
	unsigned int bytes;
	unsigned int k;
	char *endp;
	FILE *urandom, *fp;

	if (argc != 3) {
		printf("usage: genrandom k file\n");
		exit(1);
	}
	k = strtoul(argv[1], &endp, 10);
	if (*endp != 0) {
		printf("usage: genrandom k file\n");
		exit(1);
	}
	bytes = k << 10;

	fp = fopen(argv[2], "w");
	if (fp == NULL) {
		printf("failed to open %s\n", argv[2]);
		exit(1);
	}

	urandom = fopen("/dev/urandom", "r");
	if (urandom != NULL) {
		unsigned char data[1024];
		while (bytes > 0) {
			size_t n, toread;
			toread = sizeof(data);
			if (toread > bytes)
				toread = bytes;
			n = fread(data, 1, toread, urandom);
			if (n <= 0) {
				printf("error reading /dev/urandom\n");
				exit(1);
			}
			if (fwrite(data, 1, n, fp) != n) {
				printf("error writing to file\n");
				exit(1);
			}
			bytes -= n;
		}
		fclose(urandom);
	} else {
		unsigned int seed = (unsigned int) time(NULL);
		srand(seed);
		while (bytes > 0) {
			int x = rand();
			if (fwrite(&x, 1, sizeof(int), fp) != sizeof(int)) {
				printf("error writing to file\n");
				exit(1);
			}
			bytes -= sizeof(int);
		}
	}
	fclose(fp);

	exit(0);

	

}
