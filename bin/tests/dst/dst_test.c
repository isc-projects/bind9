/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <unistd.h>		/* XXX */

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/region.h>
#include <isc/mem.h>
#include <isc/result.h>

#include <dns/result.h>

#include <dst/dst.h>
#include <dst/result.h>

char *current, *tmp = "/tmp";

static void
use(dst_key_t *key) {
	isc_result_t ret;
	char *data = "This is some data";
	unsigned char sig[512];
	isc_buffer_t databuf, sigbuf;
	isc_region_t datareg, sigreg;

	isc_buffer_init(&sigbuf, sig, sizeof(sig), ISC_BUFFERTYPE_BINARY);
	/* Advance 1 byte for fun */
	isc_buffer_add(&sigbuf, 1);

	isc_buffer_init(&databuf, data, strlen(data), ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&databuf, strlen(data));
	isc_buffer_used(&databuf, &datareg);

	ret = dst_sign(DST_SIGMODE_ALL, key, NULL, &datareg, &sigbuf);
	printf("sign(%d) returned: %s\n", dst_key_alg(key),
	       isc_result_totext(ret));

	isc_buffer_forward(&sigbuf, 1);
	isc_buffer_remaining(&sigbuf, &sigreg);
	ret = dst_verify(DST_SIGMODE_ALL, key, NULL, &datareg, &sigreg);
	printf("verify(%d) returned: %s\n", dst_key_alg(key),
	       isc_result_totext(ret));
}

static void
io(char *name, int id, int alg, int type, isc_mem_t *mctx) {
	dst_key_t *key;
	isc_result_t ret;

	chdir(current);
	ret = dst_key_fromfile(name, id, alg, type, mctx, &key);
	printf("read(%d) returned: %s\n", alg, isc_result_totext(ret));
	if (ret != 0)
		return;
	chdir(tmp);
	ret = dst_key_tofile(key, type);
	printf("write(%d) returned: %s\n", alg, isc_result_totext(ret));
	if (ret != 0)
		return;
	use(key);
	dst_key_free(key);
}

static void
dh(char *name1, int id1, char *name2, int id2, isc_mem_t *mctx) {
	dst_key_t *key1, *key2;
	isc_result_t ret;
	isc_buffer_t b1, b2;
	isc_region_t r1, r2;
	unsigned char array1[1024], array2[1024];
	int alg = DST_ALG_DH;
	int type = DST_TYPE_PUBLIC|DST_TYPE_PRIVATE;

	chdir(current);
	ret = dst_key_fromfile(name1, id1, alg, type, mctx, &key1);
	printf("read(%d) returned: %s\n", alg, isc_result_totext(ret));
	if (ret != 0)
		return;
	ret = dst_key_fromfile(name2, id2, alg, type, mctx, &key2);
	printf("read(%d) returned: %s\n", alg, isc_result_totext(ret));
	if (ret != 0)
		return;

	chdir(tmp);
	ret = dst_key_tofile(key1, type);
	printf("write(%d) returned: %s\n", alg, isc_result_totext(ret));
	if (ret != 0)
		return;
	ret = dst_key_tofile(key2, type);
	printf("write(%d) returned: %s\n", alg, isc_result_totext(ret));
	if (ret != 0)
		return;

	isc_buffer_init(&b1, array1, sizeof(array1), ISC_BUFFERTYPE_BINARY);
	ret = dst_computesecret(key1, key2, &b1);
	printf("computesecret() returned: %s\n", isc_result_totext(ret));
	if (ret != 0)
		return;

	isc_buffer_init(&b2, array2, sizeof(array2), ISC_BUFFERTYPE_BINARY);
	ret = dst_computesecret(key2, key1, &b2);
	printf("computesecret() returned: %s\n", isc_result_totext(ret));
	if (ret != 0)
		return;

	isc_buffer_used(&b1, &r1);
	isc_buffer_used(&b2, &r2);

	if (r1.length != r2.length || memcmp(r1.base, r2.base, r1.length) != 0)
	{
		int i;
		printf("secrets don't match\n");
		printf("secret 1: %d bytes\n", r1.length);
		for (i = 0; i < (int) r1.length; i++)
			printf("%02x ", r1.base[i]);
		printf("\n");
		printf("secret 2: %d bytes\n", r2.length);
		for (i = 0; i < (int) r2.length; i++)
			printf("%02x ", r2.base[i]);
		printf("\n");
	}
	dst_key_free(key1);
	dst_key_free(key2);
}

static void
generate(int alg, isc_mem_t *mctx) {
	isc_result_t ret;
	dst_key_t *key;

	ret = dst_key_generate("test.", alg, 512, 0, 0, 0, mctx, &key);
	printf("generate(%d) returned: %s\n", alg, isc_result_totext(ret));

	if (alg != DST_ALG_DH)
		use(key);

	dst_key_free(key);
}

static void
get_random() {
	unsigned char data[25];
	isc_buffer_t databuf;
	isc_result_t ret;
	unsigned int i;

	isc_buffer_init(&databuf, data, sizeof data, ISC_BUFFERTYPE_BINARY);
	ret = dst_random_get(sizeof(data), &databuf);
	printf("random() returned: %s\n", isc_result_totext(ret));
	for (i = 0; i < sizeof data; i++)
		printf("%02x ", data[i]);
	printf("\n");
}

int
main() {
	isc_mem_t *mctx = NULL;

	isc_mem_create(0, 0, &mctx);

	current = isc_mem_get(mctx, 256);
	getcwd(current, 256);

	dns_result_register();
	dst_result_register();

	io("test.", 6204, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);
	io("test.", 54622, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);

	io("test.", 0, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);
	io("test.", 0, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);

	dh("dh.", 18088, "dh.", 48443, mctx);

	generate(DST_ALG_RSA, mctx);
	generate(DST_ALG_DH, mctx);
	generate(DST_ALG_DSA, mctx);
	generate(DST_ALG_HMACMD5, mctx);

	get_random();

	isc_mem_put(mctx, current, 256);
/*	isc_mem_stats(mctx, stdout);*/
	isc_mem_destroy(&mctx);

	exit(0);
}
