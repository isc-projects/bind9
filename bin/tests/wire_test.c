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
#include <dns/rdata.h>
#include <dns/compress.h>

#define DNS_FLAG_QR		0x8000U
#define DNS_FLAG_AA		0x0400U
#define DNS_FLAG_TC		0x0200U
#define DNS_FLAG_RD		0x0100U
#define DNS_FLAG_RA		0x0080U

#define DNS_OPCODE_MASK		0x7000U
#define DNS_OPCODE_SHIFT	11
#define DNS_RCODE_MASK		0x000FU

typedef struct dns_message {
	unsigned int		id;
	unsigned int		flags;
	unsigned int		qcount;
	unsigned int		ancount;
	unsigned int		aucount;
	unsigned int		adcount;
	dns_namelist_t		question;
	dns_namelist_t		answer;
	dns_namelist_t		authority;
	dns_namelist_t		additional;
} dns_message_t;

#define MAX_PREALLOCATED	100

dns_decompress_t dctx;
unsigned int rdcount, rlcount, ncount;
dns_name_t names[MAX_PREALLOCATED];
dns_rdata_t rdatas[MAX_PREALLOCATED];
dns_rdatalist_t lists[MAX_PREALLOCATED];

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

static isc_uint16_t
getshort(isc_buffer_t *buffer) {
	isc_region_t r;

	isc_buffer_remaining(buffer, &r);
	if (r.length < 2) {
		printf("not enough input\n");
		exit(5);
	}

	return (isc_buffer_getuint16(buffer));
}

static unsigned int
getname(dns_name_t *name, isc_buffer_t *source, isc_buffer_t *target) {
	unsigned char c[255];
	dns_result_t result;
	isc_buffer_t text;
	unsigned int current;
#ifdef NOISY
	isc_region_t r;
#endif

	isc_buffer_init(&text, c, 255, ISC_BUFFERTYPE_TEXT);
	dns_name_init(name, NULL);

	current = source->current;
	result = dns_name_fromwire(name, source, &dctx, ISC_FALSE, target);
				   
#ifdef NOISY
	if (result == DNS_R_SUCCESS) {
		dns_name_toregion(name, &r);
		print_wirename(&r);
		printf("%u labels, %u bytes.\n",
		       dns_name_countlabels(name),
		       r.length);
		result = dns_name_totext(name, ISC_FALSE, &text);
		if (result == DNS_R_SUCCESS) {
			isc_buffer_used(&text, &r);
			printf("%.*s\n", (int)r.length, r.base);
		} else
			printf("%s\n", dns_result_totext(result));
	} else
		printf("%s\n", dns_result_totext(result));
#else
	if (result != DNS_R_SUCCESS)
		printf("%s\n", dns_result_totext(result));
#endif

	return (source->current - current);
}

static void
getquestions(isc_buffer_t *source, dns_namelist_t *section, unsigned int count,
	     isc_buffer_t *target)
{
	unsigned int type, class;
	dns_name_t *name, *curr;
	dns_rdatalist_t *rdatalist;

	ISC_LIST_INIT(*section);
	while (count > 0) {
		count--;

		if (ncount == MAX_PREALLOCATED) {
			printf("out of names\n");
			exit(1);
		}
		name = &names[ncount++];
		(void)getname(name, source, target);
		for (curr = ISC_LIST_HEAD(*section);
		     curr != NULL;
		     curr = ISC_LIST_NEXT(curr, link)) {
			if (dns_name_compare(curr, name) == 0) {
				ncount--;
				name = curr;
				break;
			}
		}
		if (name != curr)
			ISC_LIST_APPEND(*section, name, link);
		type = getshort(source);
		class = getshort(source);
		for (rdatalist = ISC_LIST_HEAD(name->list);
		     rdatalist != NULL;
		     rdatalist = ISC_LIST_NEXT(rdatalist, link)) {
			if (rdatalist->class == class &&
			    rdatalist->type == type)
				break;
		}
		if (rdatalist == NULL) {
			if (rlcount == MAX_PREALLOCATED) {
				printf("out of rdatalists\n");
				exit(1);
			}
			rdatalist = &lists[rlcount++];
			rdatalist->class = class;
			rdatalist->type = type;
			rdatalist->ttl = 0;
			ISC_LIST_INIT(rdatalist->rdata);
			ISC_LIST_APPEND(name->list, rdatalist, link);
		} else
			printf(";; duplicate question\n");
	}
}

static void
getsection(isc_buffer_t *source, dns_namelist_t *section, unsigned int count,
	   isc_buffer_t *target)
{
	unsigned int type, class, ttl, rdlength;
	isc_region_t r;
	dns_name_t *name, *curr;
	dns_name_t rname;
	unsigned char *data, *sdata;
	dns_rdata_t *rdata;
	dns_rdatalist_t *rdatalist;

	ISC_LIST_INIT(*section);
	while (count > 0) {
		count--;
		
		if (ncount == MAX_PREALLOCATED) {
			printf("out of names\n");
			exit(1);
		}
		name = &names[ncount++];
		(void)getname(name, source, target);
		for (curr = ISC_LIST_HEAD(*section);
		     curr != NULL;
		     curr = ISC_LIST_NEXT(curr, link)) {
			if (dns_name_compare(curr, name) == 0) {
				ncount--;
				name = curr;
				break;
			}
		}
		if (name != curr)
			ISC_LIST_APPEND(*section, name, link);
		type = getshort(source);
		class = getshort(source);
		ttl = getshort(source);
		ttl *= 65536;
		ttl += getshort(source);
		rdlength = getshort(source);
		isc_buffer_remaining(source, &r);
		if (r.length < rdlength) {
			printf("unexpected end of rdata\n");
			exit(7);
		}
		data = (unsigned char *)target->base + target->used;
		/* This is also naughty. */
		if (type == 2 && class == 1) {
			if (getname(&rname, source, target) != rdlength) {
				printf("rdata length mismatch\n");
				exit(11);
			}
		} else {
			isc_region_t r;

			isc_buffer_available(target, &r);
			if (r.length < rdlength) {
				printf("no space in target\n");
				exit(12);
			}
			sdata = (unsigned char *)source->base +
				source->current;
			memcpy(data, sdata, (size_t)rdlength);
			isc_buffer_add(target, rdlength);
			isc_buffer_forward(source, rdlength);
		}
		for (rdatalist = ISC_LIST_HEAD(name->list);
		     rdatalist != NULL;
		     rdatalist = ISC_LIST_NEXT(rdatalist, link)) {
			if (rdatalist->class == class &&
			    rdatalist->type == type)
				break;
		}
		if (rdatalist == NULL) {
			if (rlcount == MAX_PREALLOCATED) {
				printf("out of rdatalists\n");
				exit(1);
			}
			rdatalist = &lists[rlcount++];
			rdatalist->class = class;
			rdatalist->type = type;
			rdatalist->ttl = ttl;
			ISC_LIST_INIT(rdatalist->rdata);
			ISC_LIST_APPEND(name->list, rdatalist, link);
		} else {
			if (ttl < rdatalist->ttl)
				rdatalist->ttl = ttl;
		}

		if (rdcount == MAX_PREALLOCATED) {
			printf("out of rdata\n");
			exit(1);
		}
		rdata = &rdatas[rdcount++];

		/* This is naughty. */
		rdata->class = class;
		rdata->type = type;
		rdata->data = data;
		rdata->length = rdlength;

		ISC_LIST_APPEND(rdatalist->rdata, rdata, link);
	}
}

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

static void
printquestions(dns_namelist_t *section) {
	dns_name_t *name;
	dns_rdatalist_t *rdatalist;
	char t[1000];
	isc_buffer_t target;
	dns_result_t result;

	printf(";; QUERY SECTION:\n");
	for (name = ISC_LIST_HEAD(*section);
	     name != NULL;
	     name = ISC_LIST_NEXT(name, link)) {
		isc_buffer_init(&target, t, sizeof t, ISC_BUFFERTYPE_TEXT);
		result = dns_name_totext(name, ISC_FALSE, &target);
		if (result != DNS_R_SUCCESS) {
			printf("%s\n", dns_result_totext(result));
			exit(15);
		}
		for (rdatalist = ISC_LIST_HEAD(name->list);
		     rdatalist != NULL;
		     rdatalist = ISC_LIST_NEXT(rdatalist, link)) {
			printf(";;\t%.*s, class = %u, type = %u\n",
			       (int)target.used,
			       (char *)target.base,
			       rdatalist->class,
			       rdatalist->type);
		}
	}
}

static void
printsection(dns_namelist_t *section, char *section_name) {
	dns_name_t *name;
	dns_rdatalist_t *rdatalist;
	dns_rdata_t *rdata;
	char t[1000];
	isc_buffer_t target;
	dns_result_t result;
	char *tabs;

	printf("\n;; %s SECTION:\n", section_name);
	for (name = ISC_LIST_HEAD(*section);
	     name != NULL;
	     name = ISC_LIST_NEXT(name, link)) {
		isc_buffer_init(&target, t, sizeof t, ISC_BUFFERTYPE_TEXT);
		result = dns_name_totext(name, ISC_FALSE, &target);
		if (result != DNS_R_SUCCESS) {
			printf("%s\n", dns_result_totext(result));
			exit(15);
		}
		for (rdatalist = ISC_LIST_HEAD(name->list);
		     rdatalist != NULL;
		     rdatalist = ISC_LIST_NEXT(rdatalist, link)) {
			for (rdata = ISC_LIST_HEAD(rdatalist->rdata);
			     rdata != NULL;
			     rdata = ISC_LIST_NEXT(rdata, link)) {
				if (target.used >= 16)
					tabs = "\t";
				else if (target.used >= 8)
					tabs = "\t\t";
				else
					tabs = "\t\t\t";
				printf("%.*s%s%u %u %u\t",
				       (int)target.used,
				       (char *)target.base,
				       tabs,
				       rdatalist->ttl,
				       rdatalist->class,
				       rdatalist->type);
				printf("\n");
			}
		}
	}
}

static void
printmessage(dns_message_t *message) {
	isc_boolean_t did_flag = ISC_FALSE;
	unsigned int opcode, rcode;

	opcode = (message->flags & DNS_OPCODE_MASK) >> DNS_OPCODE_SHIFT;
	rcode = message->flags & DNS_RCODE_MASK;
	printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n",
	       opcodetext[opcode], rcodetext[rcode], message->id);
	printf(";; flags: ");
	if ((message->flags & DNS_FLAG_QR) != 0) {
		printf("qr");
		did_flag = ISC_TRUE;
	}
	if ((message->flags & DNS_FLAG_AA) != 0) {
		printf("%saa", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((message->flags & DNS_FLAG_TC) != 0) {
		printf("%stc", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((message->flags & DNS_FLAG_RD) != 0) {
		printf("%srd", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	if ((message->flags & DNS_FLAG_RA) != 0) {
		printf("%sra", did_flag ? " " : "");
		did_flag = ISC_TRUE;
	}
	printf("; QUERY: %u ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
	       message->qcount, message->ancount, message->aucount,
	       message->adcount);
	printquestions(&message->question);
	printsection(&message->answer, "ANSWER");
	printsection(&message->authority, "AUTHORITY");
	printsection(&message->additional, "ADDITIONAL");
}

int
main(int argc, char *argv[]) {
	char *rp, *wp;
	unsigned char *bp;
	isc_buffer_t source, target;
	isc_region_t r;
	size_t len, i;
	int n;
	FILE *f;
	isc_boolean_t need_close = ISC_FALSE;
	unsigned char b[1000];
	char s[1000];
	char t[5000];
	dns_message_t message;
	
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

	rdcount = 0;
	rlcount = 0;
	ncount = 0;

	dctx.allowed = DNS_COMPRESS_GLOBAL14;
	dns_name_init(&dctx.owner_name, NULL);

	isc_buffer_init(&source, b, sizeof b, ISC_BUFFERTYPE_BINARY);
	isc_buffer_add(&source, bp - b);
	isc_buffer_init(&target, t, sizeof t, ISC_BUFFERTYPE_BINARY);

	message.id = getshort(&source);
	message.flags = getshort(&source);
	message.qcount = getshort(&source);
	message.ancount = getshort(&source);
	message.aucount = getshort(&source);
	message.adcount = getshort(&source);

	getquestions(&source, &message.question, message.qcount, &target);
	getsection(&source, &message.answer, message.ancount, &target);
	getsection(&source, &message.authority, message.aucount, &target);
	getsection(&source, &message.additional, message.adcount, &target);

	isc_buffer_remaining(&source, &r);
	if (r.length != 0)
		printf("extra data at end of packet.\n");

	printmessage(&message);

	return (0);
}
