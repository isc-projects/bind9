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
#include <isc/mem.h>
#include <isc/util.h>
#include <isc/string.h>

#include <stdio.h>

static void
hex_dump(const char *msg, void *data, unsigned int length) {
        unsigned int len;
	unsigned char *base;
	isc_boolean_t first = ISC_TRUE;

	base = data;

        printf("DUMP of %d bytes:  %s\n\t", length, msg);
        for (len = 0 ; len < length ; len++) {
                if (len % 16 == 0 && !first)
			printf("\n\t");
                printf("%02x ", base[len]);
		first = ISC_FALSE;
        }
        printf("\n");
}

static void
CHECK(const char *msg, isc_result_t result) {
	if (result != ISC_R_SUCCESS) {
		printf("FAILURE:  %s:  %s\n", msg, isc_result_totext(result));
		exit(1);
	}
}

static isc_result_t
start(isc_entropysource_t *source, void *arg, isc_boolean_t blocking)
{
	printf("start called, non-blocking mode.\n");

	return (ISC_R_SUCCESS);
}

static void
stop(isc_entropysource_t *source, void *arg) {
	printf("stop called\n");
}

/*
 * This function is by no way a good one to actually add entropy into
 * the system.  It is intended to fool the entropy system into beliving
 * there are actual bits from us.
 */
static isc_result_t
get(isc_entropysource_t *source, void *arg, isc_boolean_t blocking) {
	isc_result_t result;
	static isc_uint32_t val = 1;
	static int count = 0;

	/*
	 * Here, we should check to see if we are in blocking mode or not.
	 * If we will block and the application asked us not to,
	 * we should return an error instead, rather than block.
	 */
	if (!blocking) {
		count++;
		if (count > 6)
			return (ISC_R_NOENTROPY);
	}

	do {
		if (val == 0)
			val = 0x12345678;
		val <<= 3;
		val %= 100000;

		result = isc_entropy_addcallbacksample(source, val, 0);
	} while (result == ISC_R_SUCCESS);

	return (result);
}

int
main(int argc, char **argv) {
	isc_mem_t *mctx;
	unsigned char buffer[512];
	isc_entropy_t *ent;
	isc_entropysource_t *source;
	unsigned int returned;
	unsigned int flags;
	isc_result_t result;

	UNUSED(argc);
	UNUSED(argv);

	mctx = NULL;
	CHECK("isc_mem_create()",
	      isc_mem_create(0, 0, &mctx));

	ent = NULL;
	CHECK("isc_entropy_create()",
	      isc_entropy_create(mctx, &ent));

	isc_entropy_stats(ent, stderr);

	source = NULL;
	result = isc_entropy_createcallbacksource(ent, start, get, stop, NULL,
						  &source);
	CHECK("isc_entropy_createcallbacksource()", result);

	fprintf(stderr,
		"Reading 32 bytes of GOOD random data only, partial OK\n");

	flags = 0;
	flags |= ISC_ENTROPY_GOODONLY;
	flags |= ISC_ENTROPY_PARTIAL;
#if 0
	flags |= ISC_ENTROPY_BLOCKING;
#endif
	returned = 0;
	result = isc_entropy_getdata(ent, buffer, 32, &returned, flags);
	if (result == ISC_R_NOENTROPY) {
		fprintf(stderr, "No entropy.\n");
	}
	hex_dump("good data only:", buffer, returned);

	isc_entropy_stats(ent, stderr);

	isc_entropy_destroysource(&source);
	isc_entropy_detach(&ent);

	isc_mem_stats(mctx, stderr);
	isc_mem_destroy(&mctx);

	return (0);
}

