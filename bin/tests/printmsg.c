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

#include "printmsg.h"

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
	"RESERVED15",
	"BADVERS"
};

static isc_result_t
printsection(dns_message_t *msg, dns_section_t sectionid, char *section_name)
{
	dns_name_t *name, *print_name;
	dns_rdataset_t *rdataset;
	isc_buffer_t target;
	isc_result_t result;
	isc_region_t r;
	dns_name_t empty_name;
	char t[4096];
	isc_boolean_t first;
	isc_boolean_t no_rdata;
	
	if (sectionid == DNS_SECTION_QUESTION)
		no_rdata = ISC_TRUE;
	else
		no_rdata = ISC_FALSE;

	printf(";; %s SECTION:\n", section_name);

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
			result = dns_rdataset_totext(rdataset,
						     print_name,
						     ISC_FALSE,
						     no_rdata,
						     &target);
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

isc_result_t
printmessage(dns_message_t *msg) {
	isc_boolean_t did_flag = ISC_FALSE;
	isc_result_t result;
	dns_rdataset_t *opt;

	result = DNS_R_SUCCESS;

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
	if ((msg->flags & DNS_MESSAGEFLAG_AD) != 0) {
		printf("%sad", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((msg->flags & DNS_MESSAGEFLAG_CD) != 0) {
		printf("%scd", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	printf("; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
	       msg->counts[DNS_SECTION_QUESTION],
	       msg->counts[DNS_SECTION_ANSWER],
	       msg->counts[DNS_SECTION_AUTHORITY],
	       msg->counts[DNS_SECTION_ADDITIONAL]);
	opt = dns_message_getopt(msg);
	if (opt != NULL)
		printf(";; EDNS: version: %u, udp=%u\n",
		       (unsigned int)((opt->ttl & 0x00ff0000) >> 16),
		       (unsigned int)opt->rdclass);

	if (msg->counts[DNS_SECTION_TSIG] > 0)
		printf(";; PSEUDOSECTIONS: TSIG: %u\n",
		       msg->counts[DNS_SECTION_TSIG]);
	if (msg->counts[DNS_SECTION_QUESTION] > 0) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_QUESTION, "QUESTION");
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	if (msg->counts[DNS_SECTION_ANSWER] > 0) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_ANSWER, "ANSWER");
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	if (msg->counts[DNS_SECTION_AUTHORITY] > 0) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_AUTHORITY, "AUTHORITY");
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	if (msg->counts[DNS_SECTION_ADDITIONAL] > 0) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_ADDITIONAL,
				      "ADDITIONAL");
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	if (msg->counts[DNS_SECTION_TSIG] > 0) {
		printf("\n");
		result = printsection(msg, DNS_SECTION_TSIG,
				      "PSEUDOSECTION TSIG");
		if (result != DNS_R_SUCCESS)
			return (result);
	}
	printf("\n");

	return (result);
}
