/*
 * Copyright (C) 2000  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <isc/sha1.h>
#include <isc/util.h>

#include <stdio.h>

static void
print_digest(char *s, unsigned char d[20]) {
	int i, j;

	printf("hashed %s:\n\t", s);
	for (i = 0 ; i < 5 ; i++) {
		printf(" ");
		for (j = 0 ; j < 4 ; j++)
			printf("%02x", d[i * 4 + j]);
	}
	printf("\n");
}

int
main(int argc, char **argv) {
	isc_sha1_t sha1;
	unsigned char digest[20];
	unsigned char buffer[1024];
	const unsigned char *s;

	UNUSED(argc);
	UNUSED(argv);


	s = "abc";
	isc_sha1_init(&sha1);
	strcpy(buffer, s);
	isc_sha1_update(&sha1, buffer, strlen(s));
	isc_sha1_final(&sha1, digest);
	print_digest(buffer, digest);

	s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	isc_sha1_init(&sha1);
	strcpy(buffer, s);
	isc_sha1_update(&sha1, buffer, strlen(s));
	isc_sha1_final(&sha1, digest);
	print_digest(buffer, digest);

	return (0);
}
