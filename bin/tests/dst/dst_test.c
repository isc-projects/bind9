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

#include <unistd.h>		/* XXX */

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/region.h>
#include <isc/mem.h>

#include <dst/dst.h>
#include <dst/result.h>

char *current, *tmp = "/tmp";

static void
use(dst_key_t *key) {
	dst_result_t ret;
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

	ret = dst_sign(DST_SIG_MODE_ALL, key, NULL, &datareg, &sigbuf);
	printf("sign(%d) returned: %s\n", dst_key_alg(key),
	       dst_result_totext(ret));

	isc_buffer_forward(&sigbuf, 1);
	isc_buffer_remaining(&sigbuf, &sigreg);
	ret = dst_verify(DST_SIG_MODE_ALL, key, NULL, &datareg, &sigreg);
	printf("verify(%d) returned: %s\n", dst_key_alg(key),
	       dst_result_totext(ret));
}

static void
io(char *name, int id, int alg, int type, isc_mem_t *mctx) {
	dst_key_t *key;
	dst_result_t ret;

	chdir(current);
	ret = dst_key_fromfile(name, id, alg, type, mctx, &key);
	printf("read(%d) returned: %s\n", alg, dst_result_totext(ret));
	if (ret != 0)
		return;
	chdir(tmp);
	ret = dst_key_tofile(key, type);
	printf("write(%d) returned: %s\n", alg, dst_result_totext(ret));
	if (ret != 0)
		return;
	use(key);
	dst_key_free(key);
}

static void
generate(int alg, isc_mem_t *mctx) {
	dst_result_t ret;
	dst_key_t *key;

	ret = dst_key_generate("test.", alg, 512, 0, 0, 0, mctx, &key);
	printf("generate(%d) returned: %s\n", alg, dst_result_totext(ret));

	use(key);

	dst_key_free(key);
}

static void
get_random() {
	unsigned char data[25];
	isc_buffer_t databuf;
	dst_result_t ret;
	unsigned int i;

	isc_buffer_init(&databuf, data, sizeof data, ISC_BUFFERTYPE_BINARY);
	ret = dst_random(sizeof(data), &databuf);
	printf("random() returned: %s\n", dst_result_totext(ret));
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

	io("test.", 6204, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);
	io("test.", 54622, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);

	io("test.", 0, DST_ALG_DSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);
	io("test.", 0, DST_ALG_RSA, DST_TYPE_PRIVATE|DST_TYPE_PUBLIC, mctx);

	generate(DST_ALG_RSA, mctx);
	generate(DST_ALG_DSA, mctx);
	generate(DST_ALG_HMAC_MD5, mctx);

	get_random();

	isc_mem_put(mctx, current, 256);
/*	isc_mem_stats(mctx, stdout);*/
	isc_mem_destroy(&mctx);

	exit(0);
}
