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

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lwres/context.h>
#include <lwres/lwbuffer.h>
#include <lwres/lwres.h>
#include <lwres/lwpacket.h>

static inline void
CHECK(int val, char *msg)
{
	if (val != 0) {
		fprintf(stderr, "%s returned %d\n", msg, val);
		exit(1);
	}
}

static void
hexdump(char *msg, void *base, size_t len)
{
	unsigned char *p;
	unsigned int cnt;

	p = base;
	cnt = 0;

	printf("*** %s (%u bytes @ %p)\n", msg, len, base);

	while (cnt < len) {
		if (cnt % 16 == 0)
			printf("%p: ", p);
		else if (cnt % 8 == 0)
			printf(" |");
		printf(" %02x", *p++);
		cnt++;

		if (cnt % 16 == 0)
			printf("\n");
	}

	if (cnt % 16 != 0)
		printf("\n");
}

static char *TESTSTRING = "This is a test.  This is only a test.  !!!";
static lwres_context_t *ctx;

static void
test_noop(void)
{
	int ret;
	lwres_lwpacket_t pkt, pkt2;
	lwres_nooprequest_t nooprequest, *nooprequest2;
	lwres_noopresponse_t noopresponse, *noopresponse2;
	lwres_buffer_t b;

	pkt.flags = 0;
	pkt.serial = 0x11223344;
	pkt.recvlength = 0x55667788;
	pkt.result = 0;

	nooprequest.datalength = strlen(TESTSTRING);
	nooprequest.data = TESTSTRING;
	ret = lwres_nooprequest_render(ctx, &nooprequest, &pkt, &b);
	CHECK(ret, "lwres_nooprequest_render");

	hexdump("rendered noop request", b.base, b.used);

	/*
	 * Now, parse it into a new structure.
	 */
	lwres_buffer_first(&b);
	ret = lwres_lwpacket_parseheader(&b, &pkt2);
	CHECK(ret, "lwres_lwpacket_parseheader");

	hexdump("parsed pkt2", &pkt2, sizeof(pkt2));

	nooprequest2 = NULL;
	ret = lwres_nooprequest_parse(ctx, &b, &pkt2, &nooprequest2);
	CHECK(ret, "lwres_nooprequest_parse");

	assert(nooprequest.datalength == nooprequest2->datalength);
	assert(memcmp(nooprequest.data, nooprequest2->data,
		       nooprequest.datalength) == 0);

	lwres_nooprequest_free(ctx, &nooprequest2);

	lwres_context_freemem(ctx, b.base, b.length);
	b.base = NULL;
	b.length = 0;

	pkt.flags = 0;
	pkt.serial = 0x11223344;
	pkt.recvlength = 0x55667788;
	pkt.result = 0xdeadbeef;

	noopresponse.datalength = strlen(TESTSTRING);
	noopresponse.data = TESTSTRING;
	ret = lwres_noopresponse_render(ctx, &noopresponse, &pkt, &b);
	CHECK(ret, "lwres_noopresponse_render");

	hexdump("rendered noop response", b.base, b.used);

	/*
	 * Now, parse it into a new structure.
	 */
	lwres_buffer_first(&b);
	ret = lwres_lwpacket_parseheader(&b, &pkt2);
	CHECK(ret, "lwres_lwpacket_parseheader");

	hexdump("parsed pkt2", &pkt2, sizeof(pkt2));

	noopresponse2 = NULL;
	ret = lwres_noopresponse_parse(ctx, &b, &pkt2, &noopresponse2);
	CHECK(ret, "lwres_noopresponse_parse");

	assert(noopresponse.datalength == noopresponse2->datalength);
	assert(memcmp(noopresponse.data, noopresponse2->data,
		       noopresponse.datalength) == 0);

	lwres_noopresponse_free(ctx, &noopresponse2);

	lwres_context_freemem(ctx, b.base, b.length);
	b.base = NULL;
	b.length = 0;
}

static void
test_gabn(void)
{
	lwres_gabnresponse_t *res;
	int ret;

	res = NULL;
	ret = lwres_getaddrsbyname(ctx, "www.flame.org", LWRES_ADDRTYPE_V4,
				   &res);
	printf("ret == %d\n", ret);
	assert(ret == 0);

	lwres_gabnresponse_free(ctx, &res);
}

int
main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ctx = NULL;
	ret = lwres_context_create(&ctx, NULL, NULL, NULL);
	CHECK(ret, "lwres_context_create");

	test_noop();
	test_gabn();

	lwres_context_destroy(&ctx);

	return (0);
}
