/*
 * Copyright (C) 1999  Internet Software Consortium.
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

#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/compress.h>

dns_decompress_t dctx;

static void
print_wirename(isc_region_t *name) {
	unsigned char *ccurr, *cend;
		
	ccurr = name->base;
	cend = ccurr + name->length;
	while (ccurr != cend)
		printf("%02x ", *ccurr++);
	printf("\n");
}

static int
fromhex(char c) {
	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	printf("bad input format: %02x\n", c);
	exit(3);
}

static unsigned int
getshort(isc_buffer_t *buffer) {
	isc_region_t r;
	unsigned int result;

	isc_buffer_remaining(buffer, &r);
	if (r.length < 2) {
		printf("not enough input\n");
		exit(5);
	}
	result = r.base[0]*256 + r.base[1];
	isc_buffer_forward(buffer, 2);

	return (result);
}

static unsigned int
getname(isc_buffer_t *source) {
	unsigned char t[255];
	unsigned char c[255];
	dns_result_t result;
	dns_name_t name;
	isc_buffer_t target, text;
	isc_region_t r;
	unsigned int current;

	isc_buffer_init(&target, t, 255, ISC_BUFFERTYPE_BINARY);
	isc_buffer_init(&text, c, 255, ISC_BUFFERTYPE_TEXT);

	current = source->current;
	result = dns_name_fromwire(&name, source, &dctx, ISC_FALSE, &target);
				   
	if (result == DNS_R_SUCCESS) {
		dns_name_toregion(&name, &r);
		print_wirename(&r);
		printf("%u labels, %u bytes.\n",
		       dns_name_countlabels(&name),
		       r.length);
		result = dns_name_totext(&name, 0, &text);
		if (result == DNS_R_SUCCESS) {
			isc_buffer_used(&text, &r);
			printf("%.*s\n", (int)r.length, r.base);
		} else
			printf("%s\n", dns_result_totext(result));
	} else
		printf("%s\n", dns_result_totext(result));

	return (source->current - current);
}

int
main(int argc, char *argv[]) {
	char s[1000];
	char *cp;
	unsigned char *bp;
	unsigned char b[255];
	isc_buffer_t source;
	isc_region_t r;
	size_t len, i;
	int n;
	FILE *f;
	isc_boolean_t need_close = ISC_FALSE;
	unsigned int ui, tc, type, class;
	
	if (argc > 1) {
		f = fopen(argv[1], "r");
		if (f == NULL) {
			printf("fopen failed\n");
			exit(1);
		}
		need_close = ISC_TRUE;
	} else
		f = stdin;

	bp = b;
	while (fgets(s, sizeof s, f) != NULL) {
		len = strlen(s);
		if (len > 0 && s[len - 1] == '\n') {
			len--;
			s[len] = '\0';
		}
		if (len == 0)
			break;
		if (len % 2 != 0) {
			printf("bad input format: %d\n", len);
			exit(1);
		}
		if (len > 510) {
			printf("input too long\n");
			exit(2);
		}
		cp = s;
		for (i = 0; i < len; i += 2) {
			n = fromhex(*cp++);
			n *= 16;
			n += fromhex(*cp++);
			*bp++ = n;
		}
	}

	if (need_close)
		fclose(f);

	dctx.allowed = DNS_COMPRESS_GLOBAL14 | DNS_COMPRESS_GLOBAL16;
	dns_name_init(&dctx.owner_name);

	isc_buffer_init(&source, b, 255, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, bp - b);

	ui = getshort(&source);
	printf("id = %u\n", ui);
	ui = getshort(&source);
	printf("2nd short = %u\n", ui);
	ui = getshort(&source);
	printf("qdcount = %u\n", ui);
	if (ui > 1) {
		printf("qdcount > 1 not supported\n");
		exit(6);
	}
	if (ui == 0) {
		printf("qdcount 0\n");
		exit(6);
	}
	ui = getshort(&source);
	printf("ancount = %u\n", ui);
	tc = ui;
	ui = getshort(&source);
	printf("nscount = %u\n", ui);
	tc += ui;
	ui = getshort(&source);
	printf("arcount = %u\n", ui);
	tc += ui;

	(void)getname(&source);
	ui = getshort(&source);
	printf("type = %u\n", ui);
	ui = getshort(&source);
	printf("class = %u\n\n", ui);

	while (tc > 0) {
		tc--;
		
		(void)getname(&source);
		type = getshort(&source);
		printf("type = %u\n", type);
		class = getshort(&source);
		printf("class = %u\n", class);
		ui = getshort(&source);
		ui *= 65536;
		ui += getshort(&source);
		printf("ttl = %u\n", ui);
		ui = getshort(&source);
		printf("rdlength = %u\n", ui);
		isc_buffer_remaining(&source, &r);
		if (r.length < ui) {
			printf("unexpected end of rdata\n");
			exit(7);
		}
		if (type == 2 && class == 1) {
			if (getname(&source) != ui) {
				printf("rdata length mismatch\n");
				exit(11);
			}
		} else
			isc_buffer_forward(&source, ui);
		printf("\n");
	}
	isc_buffer_remaining(&source, &r);
	if (r.length != 0)
		printf("extra data at end of packet.\n");

	return (0);
}
