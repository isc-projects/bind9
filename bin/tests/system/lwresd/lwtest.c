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

#include <config.h>

#include <assert.h>
#include <stdlib.h>

#include <isc/net.h>

#include <lwres/lwres.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

static int fails = 0;

static void
CHECK(int val, const char *msg) {
	if (val != 0) {
		printf("I: %s returned %d\n", msg, val);
		exit(1);
	}
}

#if 0
static void
hexdump(const char *msg, void *base, size_t len) {
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
#endif

static char TESTSTRING[] = "This is a test.  This is only a test.  !!!";
static lwres_context_t *ctx;

static void
test_noop() {
	int ret;
	lwres_lwpacket_t pkt, pkt2;
	lwres_nooprequest_t nooprequest, *nooprequest2;
	lwres_noopresponse_t noopresponse, *noopresponse2;
	lwres_buffer_t b;

	pkt.pktflags = 0;
	pkt.serial = 0x11223344;
	pkt.recvlength = 0x55667788;
	pkt.result = 0;

	nooprequest.datalength = strlen(TESTSTRING);
	nooprequest.data = TESTSTRING;
	ret = lwres_nooprequest_render(ctx, &nooprequest, &pkt, &b);
	CHECK(ret, "lwres_nooprequest_render");

	/*
	 * Now, parse it into a new structure.
	 */
	lwres_buffer_first(&b);
	ret = lwres_lwpacket_parseheader(&b, &pkt2);
	CHECK(ret, "lwres_lwpacket_parseheader");

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

	pkt.pktflags = 0;
	pkt.serial = 0x11223344;
	pkt.recvlength = 0x55667788;
	pkt.result = 0xdeadbeef;

	noopresponse.data = TESTSTRING;
	ret = lwres_noopresponse_render(ctx, &noopresponse, &pkt, &b);
	CHECK(ret, "lwres_noopresponse_render");

	/*
	 * Now, parse it into a new structure.
	 */
	lwres_buffer_first(&b);
	ret = lwres_lwpacket_parseheader(&b, &pkt2);
	CHECK(ret, "lwres_lwpacket_parseheader");

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
test_gabn(const char *target, int pass) {
	lwres_gabnresponse_t *res;
#if 0
	lwres_addr_t *addr;
	unsigned int i;
	char outbuf[64];
#endif
	int ret;

	res = NULL;
	ret = lwres_getaddrsbyname(ctx, target,
				   LWRES_ADDRTYPE_V4 | LWRES_ADDRTYPE_V6,
				   &res);
	if ((pass && ret != LWRES_R_SUCCESS) ||
	    (!pass && ret != LWRES_R_NOTFOUND))
	{
		printf("I: gabn(%s) failed: %d\n", target, ret);
		if (res != NULL)
			lwres_gabnresponse_free(ctx, &res);
		fails++;
		return;
	}
#if 0
	printf("Returned real name: (%u, %s)\n",
	       res->realnamelen, res->realname);
	printf("%u aliases:\n", res->naliases);
	for (i = 0 ; i < res->naliases ; i++)
		printf("\t(%u, %s)\n", res->aliaslen[i], res->aliases[i]);
	printf("%u addresses:\n", res->naddrs);
	addr = LWRES_LIST_HEAD(res->addrs);
	for (i = 0 ; i < res->naddrs ; i++) {
		if (addr->family == LWRES_ADDRTYPE_V4)
			(void)inet_ntop(AF_INET, addr->address,
					outbuf, sizeof(outbuf));
		else
			(void)inet_ntop(AF_INET6, addr->address,
					outbuf, sizeof(outbuf));
		printf("\tAddr len %u family %08x %s\n",
		       addr->length, addr->family, outbuf);
		addr = LWRES_LIST_NEXT(addr, link);
	}
#endif
	if (res != NULL)
		lwres_gabnresponse_free(ctx, &res);
}

static void
test_gnba(const char *target, lwres_uint32_t af, int pass) {
	lwres_gnbaresponse_t *res;
	int ret;
#if 0
	unsigned int i;
#endif
	unsigned char addrbuf[16];
	unsigned int len;

	if (af == LWRES_ADDRTYPE_V4) {
		len = 4;
		ret = inet_pton(AF_INET, target, addrbuf);
		assert(ret == 1);
	} else {
		len = 16;
		ret = inet_pton(AF_INET6, target, addrbuf);
		assert(ret == 1);
	}

	res = NULL;
	ret = lwres_getnamebyaddr(ctx, af, len, addrbuf, &res);
	if ((pass && ret != LWRES_R_SUCCESS) ||
	    (!pass && ret != LWRES_R_NOTFOUND))
	{
		printf("I: gnba(%s) failed: %d\n", target, ret);
		if (res != NULL)
			lwres_gnbaresponse_free(ctx, &res);
		fails++;
		return;
	}
#if 0
	printf("Returned real name: (%u, %s)\n",
	       res->realnamelen, res->realname);
	printf("%u aliases:\n", res->naliases);
	for (i = 0 ; i < res->naliases ; i++)
		printf("\t(%u, %s)\n", res->aliaslen[i], res->aliases[i]);
#endif
	if (res != NULL)
		lwres_gnbaresponse_free(ctx, &res);
}

int
main() {
	lwres_result_t ret;

	lwres_udp_port = 9210;

	ret = lwres_context_create(&ctx, NULL, NULL, NULL, 0);
	CHECK(ret, "lwres_context_create");

	ret = lwres_conf_parse(ctx, "resolv.conf");
	CHECK(ret, "lwres_conf_parse");

	test_noop();

	test_gabn("a.example1", TRUE);
	test_gabn("a.example1.", TRUE);
	test_gabn("a.example2", TRUE);
	test_gabn("a.example2.", TRUE);
	test_gabn("a.example3", FALSE);
	test_gabn("a.example3.", FALSE);
	test_gabn("a", TRUE);
	test_gabn("a.", FALSE);

	test_gabn("b.example1", TRUE);
	test_gabn("b.example1.", TRUE);
	test_gabn("b.example2", TRUE);
	test_gabn("b.example2.", TRUE);
	test_gabn("b.example3", FALSE);
	test_gabn("b.example3.", FALSE);
	test_gabn("b", TRUE);
	test_gabn("b.", FALSE);

	test_gabn("d.example1", FALSE);

	test_gabn("x", TRUE);
	test_gabn("x.", TRUE);

	test_gnba("10.10.10.1", LWRES_ADDRTYPE_V4, TRUE);
	test_gnba("10.10.10.17", LWRES_ADDRTYPE_V4, FALSE);
	test_gnba("0123:4567:89ab:cdef:0123:4567:89ab:cdef",
		  LWRES_ADDRTYPE_V6, TRUE);
	test_gnba("0123:4567:89ab:cdef:0123:4567:89ab:cde0",
		  LWRES_ADDRTYPE_V6, FALSE);

	return (fails);
}
