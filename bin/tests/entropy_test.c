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

#include <isc/entropy.h>
#include <isc/util.h>
#include <isc/string.h>

#include <stdio.h>

static void
hex_dump(char *msg, void *data, unsigned int len) {
        unsigned int len;

        printf("DUMP of %d bytes:  %s\n", len, msg);
        for (len = 0 ; len < r.length ; len++) {
                if (len % 16 == 0)
                        printf("\n");
                printf("%02x ", r.base[len]);
        }
        printf("\n");
}

int
main(int argc, char **argv) {
	isc_sha1_t sha1;
	isc_md5_t md5;
	unsigned char digest[20];
	unsigned char buffer[1024];
	const unsigned char *s;

	UNUSED(argc);
	UNUSED(argv);

	return (0);
}
