/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#include <isc/assertions.h>
#include <isc/commandline.h>
#include <isc/error.h>
#include <isc/lex.h>

#include <dns/rdata.h>
#include <dns/compress.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>

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
	dns_rdatatype_t type;
	dns_rdataclass_t class;
	dns_rdatatype_t lasttype = 0;
	char outbuf[16*1024];
	char inbuf[16*1024];
	char wirebuf[16*1024];
	isc_buffer_t dbuf;
	isc_buffer_t tbuf;
	isc_buffer_t wbuf;
	dns_rdata_t rdata;
	dns_rdata_t last;
	int need_eol = 0;
	int wire = 0;
	dns_compress_t cctx;
	dns_decompress_t dctx;
	int trunc = 0;
	int add = 0;
	int len;
	int zero = 0;
	int debug = 0;
	isc_region_t region;
	int first = 1;
	int raw = 0;

	while ((c = isc_commandline_parse(argc, argv, "dqswtarz")) != -1) {
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
		case 'r':
			raw++;
			break;
		}
	}

	memset(&dctx, '0', sizeof dctx);
	dctx.allowed = DNS_COMPRESS_ALL;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_lex_create(mctx, 256, &lex) == ISC_R_SUCCESS);

	/* Set up to lex DNS master file. */

	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	isc_lex_setspecials(lex, specials);
	options = ISC_LEXOPT_EOL;
	isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

	RUNTIME_CHECK(isc_lex_openstream(lex, stdin) == ISC_R_SUCCESS);

	dns_rdata_init(&last);
	while ((result = isc_lex_gettoken(lex, options | ISC_LEXOPT_NUMBER,
					  &token)) == ISC_R_SUCCESS) {
		if (debug) fprintf(stdout, "token.type = %d\n", token.type);
		if (need_eol) {
			if (token.type == isc_tokentype_eol)
				need_eol = 0;
			continue;
		}
		if (token.type == isc_tokentype_eof)
			break;
	
		/* get type */
		if (token.type == isc_tokentype_number) {
			type = token.value.as_ulong;
			isc_buffer_init(&tbuf, outbuf, sizeof(outbuf),
					ISC_BUFFERTYPE_TEXT);
			result = dns_rdatatype_totext(type, &tbuf);
			fprintf(stdout, "type = %.*s(%d)\n",
				(int)tbuf.used, (char*)tbuf.base, type);
		} else if (token.type == isc_tokentype_string) {
			result = dns_rdatatype_fromtext(&type,
					&token.value.as_textregion);
			if (result != DNS_R_SUCCESS) {
				fprintf(stdout,
				    "dns_rdatatype_fromtext returned %s(%d)\n",
					dns_result_totext(result), result);
				fflush(stdout);
				need_eol = 1;
				continue;
			}
			fprintf(stdout, "type = %.*s(%d)\n",
				(int)token.value.as_textregion.length,
				token.value.as_textregion.base, type);
		} else
			continue;

		if ((result = isc_lex_gettoken(lex, options | ISC_LEXOPT_NUMBER,
					  &token)) != ISC_R_SUCCESS)
				  break;
		if (token.type == isc_tokentype_eol)
				continue;
		if (token.type == isc_tokentype_eof)
				break;
		if (token.type == isc_tokentype_number) {
			class = token.value.as_ulong;
			isc_buffer_init(&tbuf, outbuf, sizeof(outbuf),
					ISC_BUFFERTYPE_TEXT);
			result = dns_rdatatype_totext(class, &tbuf);
			fprintf(stdout, "class = %.*s(%d)\n",
				(int)tbuf.used, (char*)tbuf.base, class);
		} else if (token.type == isc_tokentype_string) {
			result = dns_rdataclass_fromtext(&class,
					&token.value.as_textregion);
			if (result != DNS_R_SUCCESS) {
				fprintf(stdout,
				    "dns_rdataclass_fromtext returned %s(%d)\n",
					dns_result_totext(result), result);
				fflush(stdout);
				need_eol = 1;
				continue;
			}
			fprintf(stdout, "class = %.*s(%d)\n",
				(int)token.value.as_textregion.length,
				token.value.as_textregion.base, class);
		} else
			continue;

		fflush(stdout);
		dns_rdata_init(&rdata);
		isc_buffer_init(&dbuf, inbuf, sizeof(inbuf),
				ISC_BUFFERTYPE_BINARY);
		result = dns_rdata_fromtext(&rdata, class, type, lex,
					    NULL, ISC_FALSE, &dbuf, NULL);
		if (result != DNS_R_SUCCESS) {
			fprintf(stdout,
				"dns_rdata_fromtext returned %s(%d)\n",
				dns_result_totext(result), result);
			fflush(stdout);
			continue;
		}
		if (raw) {
			unsigned int i;
			for (i = 0 ; i < rdata.length ; /* */ ) {
				fprintf(stdout, "%02x", rdata.data[i]);
				if ((++i % 20) == 0)
					fputs("\n", stdout);
				else
					if (i == rdata.length)
						fputs("\n", stdout);
					else
						fputs(" ", stdout);
			}
		}

		/* Convert to wire and back? */
		if (wire) {
			result = dns_compress_init(&cctx, -1, mctx);
			if (result != DNS_R_SUCCESS) {
				fprintf(stdout,
					"dns_compress_init returned %s(%d)\n",
					dns_result_totext(result), result);
				continue;
			}
			isc_buffer_init(&wbuf, wirebuf, sizeof(wirebuf),
					ISC_BUFFERTYPE_BINARY);
			result = dns_rdata_towire(&rdata, &cctx, &wbuf);
			dns_compress_invalidate(&cctx);
			if (result != DNS_R_SUCCESS) {
				fprintf(stdout,
					"dns_rdata_towire returned %s(%d)\n",
					dns_result_totext(result), result);
				continue;
			}
			len = wbuf.used - wbuf.current;
			if (raw > 2) {
				unsigned int i;
				fputs("\n", stdout);
				for (i = 0 ; i < (unsigned int)len ; /* */ ) {
					fprintf(stdout, "%02x",
				((unsigned char*)wbuf.base)[i + wbuf.current]);
					if ((++i % 20) == 0)
						fputs("\n", stdout);
					else
						if (i == wbuf.used)
							fputs("\n", stdout);
						else
							fputs(" ", stdout);
				}
			}
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
			dns_decompress_init(&dctx, -1, ISC_FALSE);
			result = dns_rdata_fromwire(&rdata, class, type, &wbuf,
						    &dctx, ISC_FALSE, &dbuf);
			dns_decompress_invalidate(&dctx);
			if (result != DNS_R_SUCCESS) {
			fprintf(stdout,
					"dns_rdata_fromwire returned %s(%d)\n",
					dns_result_totext(result), result);
				fflush(stdout);
				continue;
			}
		}
		if (raw > 1) {
			unsigned int i;
			fputs("\n", stdout);
			for (i = 0 ; i < rdata.length ; /* */ ) {
				fprintf(stdout, "%02x", rdata.data[i]);
				if ((++i % 20) == 0)
					fputs("\n", stdout);
				else
					if (i == rdata.length)
						fputs("\n", stdout);
					else
						fputs(" ", stdout);
			}
		}

		isc_buffer_init(&tbuf, outbuf, sizeof(outbuf),
				ISC_BUFFERTYPE_TEXT);
		result = dns_rdata_totext(&rdata, NULL, &tbuf);
		if (result != DNS_R_SUCCESS)
			fprintf(stdout, "dns_rdata_totext returned %s(%d)\n",
				dns_result_totext(result), result);
		else
			fprintf(stdout, "\"%.*s\"\n",
				(int)tbuf.used, (char*)tbuf.base);
		fflush(stdout);
		if (lasttype == type) {
			fprintf(stdout, "dns_rdata_compare = %d\n",
				dns_rdata_compare(&rdata, &last));

		}
		if (!first) {
			free(last.data);
		}
		dns_rdata_init(&last);
		region.base = malloc(region.length = rdata.length);
		if (region.base) {
			memcpy(region.base, rdata.data, rdata.length);
			dns_rdata_fromregion(&last, class, type, &region);
			lasttype = type;
			first = 0;
		} else
			first = 1;

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
