/*
 * Copyright (C) 1998  Internet Software Consortium.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/lex.h>
#include <dns/rdata.h>
#include <dns/compress.h>

isc_mem_t *mctx;
isc_lex_t *lex;

isc_lexspecials_t specials;

int
main(int argc, char *argv[]) {
	isc_token_t token;
	isc_result_t result;
	int quiet = 0;
	int c;
	int stats = 0;
	unsigned int options = 0;
	unsigned int parens = 0;
	int type;
	char outbuf[1024];
	char inbuf[1024];
	char wirebuf[1024];
	isc_buffer_t dbuf;
	isc_buffer_t tbuf;
	isc_buffer_t wbuf;
	dns_rdata_t rdata;
	int need_eol = 0;
	int wire = 0;
	dns_compress_t cctx;
	dns_decompress_t dctx;
	int trunc = 0;
	int add = 0;
	int len;
	int zero = 0;
	int debug = 0;

	while ((c = getopt(argc, argv, "dqswtaz")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			quiet = 0;
			break;
		case 'q':
			quiet = 1;
			debug = 0;
			break;
		case 's':
			stats = 1;
			break;
		case 'w':
			wire = 1;
			break;
		case 't':
			trunc = 1;
			break;
		case 'a':
			add = 1;
			break;
		case 'z':
			zero = 1;
			break;
		}
	}

	memset(&cctx, '0', sizeof cctx);
	memset(&dctx, '0', sizeof dctx);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_lex_create(mctx, 256, &lex) == ISC_R_SUCCESS);

	/* Set up to lex DNS master file. */

	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	isc_lex_setspecials(lex, specials);
	options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF;
	isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

	RUNTIME_CHECK(isc_lex_openstream(lex, stdin) == ISC_R_SUCCESS);

	while ((result = isc_lex_gettoken(lex, options | ISC_LEXOPT_NUMBER,
					  &token)) == ISC_R_SUCCESS) {
		if (debug) fprintf(stdout, "token.type = %d\n", token.type);
		if (token.type == isc_tokentype_special) {
			if (token.value.as_char == '(') {
				parens++;
				options &= ~ISC_LEXOPT_EOL;
				options &= ~ISC_LEXOPT_INITIALWS;
			} else if (token.value.as_char == ')') {
				if (parens == 0) {
					printf("mismatched parens\n");
					exit(1);
				}
				parens--;
				if (parens == 0) {
					options |= ISC_LEXOPT_EOL;
					options |= ISC_LEXOPT_INITIALWS;
				}
			}
			continue;
		}

		if (need_eol) {
			if (token.type == isc_tokentype_eol ||
			    token.type == isc_tokentype_eof)
				need_eol = 0;
			continue;
		}
	
		if (token.type != isc_tokentype_number)
			continue;

		dns_rdata_init(&rdata);

		type = token.value.as_ulong;
		fprintf(stdout, "type = %d\n", type);
		fflush(stdout);
		isc_buffer_init(&dbuf, inbuf, sizeof(inbuf),
				ISC_BUFFERTYPE_BINARY);
		result = dns_rdata_fromtext(&rdata, 1, type, lex,
					    NULL, ISC_FALSE, &dbuf);
		if (result != DNS_R_SUCCESS) {
			fprintf(stdout,
				"dns_rdata_fromtext returned %s(%d)\n",
				dns_result_totext(result), result);
			fflush(stdout);
			continue;
		}

		/* Convert to wire and back? */
		if (wire) {
			isc_buffer_init(&wbuf, wirebuf, sizeof(wirebuf),
					ISC_BUFFERTYPE_BINARY);
			result = dns_rdata_towire(&rdata, &cctx, &wbuf);
			if (result != DNS_R_SUCCESS) {
				fprintf(stdout,
					"dns_rdata_towire returned %s(%d)\n",
					dns_result_totext(result), result);
				continue;
			}
			len = wbuf.used - dbuf.current;
			if (zero)
				len = 0;
			if (trunc)
				len = (len * 3) / 4;
			if (add) {
				isc_buffer_add(&wbuf, len / 4 + 1);
				len += len / 4 + 1;
			}
			isc_buffer_setactive(&wbuf, len);
			dns_rdata_init(&rdata);
			isc_buffer_init(&dbuf, inbuf, sizeof(inbuf),
					ISC_BUFFERTYPE_BINARY);
			result = dns_rdata_fromwire(&rdata, 1, type, &wbuf,
						    &dctx, ISC_FALSE, &dbuf);
			if (result != DNS_R_SUCCESS) {
				fprintf(stdout,
					"dns_rdata_fromwire returned %s(%d)\n",
					dns_result_totext(result), result);
				fflush(stdout);
				continue;
			}
		}

		isc_buffer_init(&tbuf, outbuf, sizeof(outbuf),
				ISC_BUFFERTYPE_TEXT);
		result = dns_rdata_totext(&rdata, &tbuf);
		if (result != DNS_R_SUCCESS)
			fprintf(stdout, "dns_rdata_totext returned %s(%d)\n",
				dns_result_totext(result), result);
		else
			fprintf(stdout, "\"%.*s\"\n",
				(int)tbuf.used, (char*)tbuf.base);
		fflush(stdout);
	}
	if (result != ISC_R_EOF)
		printf("Result: %s\n", isc_result_totext(result));

	isc_lex_close(lex);
	isc_lex_destroy(&lex);
	if (!quiet && stats)
		isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
