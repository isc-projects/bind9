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
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/region.h>

#include <dns/types.h>
#include <dns/result.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/compress.h>
#include <dns/message.h>

dns_decompress_t dctx;

dns_result_t printmessage(dns_message_t *message);

static inline void
CHECKRESULT(dns_result_t result, char *msg)
{
	if (result != DNS_R_SUCCESS) {
		printf("%s: %s\n", msg, dns_result_totext(result));

		exit(1);
	}
}


#ifdef NOISY
static void
print_wirename(isc_region_t *name) {
	unsigned char *ccurr, *cend;
		
	ccurr = name->base;
	cend = ccurr + name->length;
	while (ccurr != cend)
		printf("%02x ", *ccurr++);
	printf("\n");
}
#endif

#ifndef NOMAIN
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
	/* NOTREACHED */
}
#endif

static char *opcodetext[] = {
	"QUERY",
	"IQUERY",
	"STATUS",
	"RESERVED3",
	"NOTIFY",
	"UPDATE",
	"RESERVED6",
	"RESERVED7",
	"RESERVED8",
	"RESERVED9",
	"RESERVED10",
	"RESERVED11",
	"RESERVED12",
	"RESERVED13",
	"RESERVED14",
	"RESERVED15"
};

static char *rcodetext[] = {
	"NOERROR",
	"FORMERR",
	"SERVFAIL",
	"NXDOMAIN",
	"NOTIMPL",
	"REFUSED",
	"YXDOMAIN",
	"YXRRSET",
	"NXRRSET",
	"NOTAUTH",
	"NOTZONE",
	"RESERVED11",
	"RESERVED12",
	"RESERVED13",
	"RESERVED14",
	"RESERVED15"
};

static dns_result_t
printsection(dns_message_t *msg, dns_section_t sectionid, char *section_name)
{
	dns_name_t *name, *print_name;
	dns_rdataset_t *rdataset;
	isc_buffer_t target;
	dns_result_t result;
	isc_region_t r;
	dns_name_t empty_name;
	char t[1000];
	isc_boolean_t first;
	isc_boolean_t no_rdata;

	if (sectionid == DNS_SECTION_QUESTION)
		no_rdata = ISC_TRUE;
	else
		no_rdata = ISC_FALSE;

	printf("\n;; %s SECTION:\n", section_name);

	dns_name_init(&empty_name, NULL);

	result = dns_message_firstname(msg, sectionid);
	if (result == DNS_R_NOMORE)
		return (DNS_R_SUCCESS);
	else if (result != DNS_R_SUCCESS)
		return (result);

	for (;;) {
		name = NULL;
		dns_message_currentname(msg, sectionid, &name);

		isc_buffer_init(&target, t, sizeof t, ISC_BUFFERTYPE_TEXT);
		first = ISC_TRUE;
		print_name = name;

		for (rdataset = ISC_LIST_HEAD(name->list);
		     rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link)) {
			result = dns_rdataset_totext(rdataset, print_name,
						     ISC_FALSE, &target,
						     no_rdata);
			if (result != DNS_R_SUCCESS)
				return (result);
#ifdef USEINITALWS
			if (first) {
				print_name = &empty_name;
				first = ISC_FALSE;
			}
#endif
		}
		isc_buffer_used(&target, &r);
		printf("%.*s", (int)r.length, (char *)r.base);

		result = dns_message_nextname(msg, sectionid);
		if (result == DNS_R_NOMORE)
			break;
		else if (result != DNS_R_SUCCESS)
			return (result);
	}
	
	return (DNS_R_SUCCESS);
}

dns_result_t
printmessage(dns_message_t *msg) {
	isc_boolean_t did_flag = ISC_FALSE;
	dns_result_t result;

	result = DNS_R_UNEXPECTED;

	printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n",
	       opcodetext[msg->opcode], rcodetext[msg->rcode], msg->id);

	printf(";; flags: ");
	if ((msg->flags & DNS_MESSAGEFLAG_QR) != 0) {
		printf("qr");
		did_flag = ISC_TRUE;
	}
	if ((msg->flags & DNS_MESSAGEFLAG_AA) != 0) {
		printf("%saa", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((msg->flags & DNS_MESSAGEFLAG_TC) != 0) {
		printf("%stc", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((msg->flags & DNS_MESSAGEFLAG_RD) != 0) {
		printf("%srd", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((msg->flags & DNS_MESSAGEFLAG_RA) != 0) {
		printf("%sra", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	printf("; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
	       msg->counts[DNS_SECTION_QUESTION],
	       msg->counts[DNS_SECTION_ANSWER],
	       msg->counts[DNS_SECTION_AUTHORITY],
	       msg->counts[DNS_SECTION_ADDITIONAL]);
	printf("; PSEUDOSECTIONS: OPT: %u, TSIG: %u\n",
	       msg->counts[DNS_SECTION_OPT],
	       msg->counts[DNS_SECTION_TSIG]);

	result = printsection(msg, DNS_SECTION_QUESTION, "QUESTION");
	if (result != DNS_R_SUCCESS)
		return (result);
	result = printsection(msg, DNS_SECTION_ANSWER, "ANSWER");
	if (result != DNS_R_SUCCESS)
		return (result);
	result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY");
	if (result != DNS_R_SUCCESS)
		return (result);
	result = printsection(msg, DNS_SECTION_ADDITIONAL, "ADDITIONAL");
	if (result != DNS_R_SUCCESS)
		return (result);
	result = printsection(msg, DNS_SECTION_OPT, "PSEUDOSECTION OPT");
	if (result != DNS_R_SUCCESS)
		return (result);
	result = printsection(msg, DNS_SECTION_TSIG, "PSEUDOSECTION TSIG");
	if (result != DNS_R_SUCCESS)
		return (result);

	return (result);
}

#ifndef NOMAIN
int
main(int argc, char *argv[]) {
	char *rp, *wp;
	unsigned char *bp;
	isc_buffer_t source;
	size_t len, i;
	int n;
	FILE *f;
	isc_boolean_t need_close = ISC_FALSE;
	unsigned char b[1000];
	char s[1000];
	dns_message_t *message;
	dns_result_t result;
	isc_mem_t *mctx;

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);
	
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
		rp = s;
		wp = s;
		len = 0;
		while (*rp != '\0') {
			if (*rp != ' ' && *rp != '\t' &&
			    *rp != '\r' && *rp != '\n') {
				*wp++ = *rp;
				len++;
			}
			rp++;
		}
		if (len == 0)
			break;
		if (len % 2 != 0) {
			printf("bad input format: %d\n", len);
			exit(1);
		}
		if (len > (sizeof b) * 2) {
			printf("input too long\n");
			exit(2);
		}
		rp = s;
		for (i = 0; i < len; i += 2) {
			n = fromhex(*rp++);
			n *= 16;
			n += fromhex(*rp++);
			*bp++ = n;
		}
	}

	if (need_close)
		fclose(f);

	f = fopen("foo", "w");
	fwrite(b, bp - b, 1, f);
	fclose(f);

	isc_buffer_init(&source, b, sizeof b, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, bp - b);

	result = dns_message_create(mctx, &message, DNS_MESSAGE_INTENT_PARSE);
	CHECKRESULT(result, "dns_message_create failed");

	result = dns_message_parse(message, &source);
	CHECKRESULT(result, "dns_message_parse failed");

	result = printmessage(message);
	CHECKRESULT(result, "printmessage() failed");

	dns_message_destroy(&message);

	isc_mem_stats(mctx, stdout);
	isc_mem_destroy(&mctx);

	return (0);
}
#endif /* !NOMAIN */
