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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>	/* XXX Naughty. */

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
#include <dns/db.h>

static void
makename(isc_mem_t *mctx, char *text, dns_name_t *name, dns_name_t *origin) {
	char b[255];
	isc_buffer_t source, target;
	size_t len;
	isc_region_t r1, r2;
	dns_result_t result;

	if (origin == NULL)
		origin = dns_rootname;
	dns_name_init(name, NULL);
	len = strlen(text);
	isc_buffer_init(&source, text, len, ISC_BUFFERTYPE_TEXT);
	isc_buffer_add(&source, len);
	isc_buffer_init(&target, b, sizeof b, ISC_BUFFERTYPE_BINARY);
	result = dns_name_fromtext(name, &source, origin, ISC_FALSE, &target);
	RUNTIME_CHECK(result == DNS_R_SUCCESS);
	dns_name_toregion(name, &r1);
	r2.base = isc_mem_get(mctx, r1.length);
	RUNTIME_CHECK(r2.base != NULL);
	r2.length = r1.length;
	memcpy(r2.base, r1.base, r1.length);
	dns_name_fromregion(name, &r2);
}

static void
freename(isc_mem_t *mctx, dns_name_t *name) {
	isc_region_t r;

	dns_name_toregion(name, &r);
	isc_mem_put(mctx, r.base, r.length);
	dns_name_invalidate(name);
}

int
main(int argc, char *argv[]) {
	isc_mem_t *mctx = NULL;
	dns_db_t *db;
	dns_dbnode_t *node;
	dns_result_t result;
	dns_name_t name, base, *origin;
	dns_offsets_t offsets;
	size_t len;
	isc_buffer_t source, target, text;
	char s[1000];
	char t[1000];
	char b[255];
	dns_rdataset_t rdataset;
	isc_region_t r;
	char basetext[1000];
	char dbtype[128];
	int ch;
	dns_rdatatype_t type = 2;

	strcpy(basetext, "");
	strcpy(dbtype, "rbt");
	while ((ch = getopt(argc, argv, "z:d:t:")) != -1) {
		switch (ch) {
		case 'z':
			strcpy(basetext, optarg);
			break;
		case 'd':
			strcpy(dbtype, optarg);
			break;
		case 't':
			type = atoi(optarg);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		fprintf(stderr, "usage: db_test filename\n");
		exit(1);
	}

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	if (strcmp(basetext, "") == 0)
		strcpy(basetext, "vix.com.");
	makename(mctx, basetext, &base, NULL);

	db = NULL;
	result = dns_db_create(mctx, dbtype, &base, ISC_FALSE, 1, 0, NULL,
			       &db);
	if (result != DNS_R_SUCCESS) {
		printf("dns_db_create(), DB type '%s', failed: %s\n",
		       dbtype, dns_result_totext(result));
		exit(1);
	}
	
	origin = &base;
	printf("loading %s\n", argv[0]);
	result = dns_db_load(db, argv[0]);
	if (result != DNS_R_SUCCESS) {
		printf("couldn't load master file: %s\n",
		       dns_result_totext(result));
		exit(1);
	}
	printf("loaded\n");

	while (gets(s) != NULL) {
		dns_name_init(&name, offsets);
		len = strlen(s);
		isc_buffer_init(&source, s, len, ISC_BUFFERTYPE_TEXT);
		isc_buffer_add(&source, len);
		isc_buffer_init(&target, b, sizeof b, ISC_BUFFERTYPE_BINARY);
		result = dns_name_fromtext(&name, &source, origin, ISC_FALSE,
					   &target);
		if (result != DNS_R_SUCCESS) {
			printf("bad name: %s\n", dns_result_totext(result));
			continue;
		}
		node = NULL;
		result = dns_db_findnode(db, &name, ISC_FALSE, &node);
		if (result == DNS_R_NOTFOUND)
			printf("not found\n");
		else if (result != DNS_R_SUCCESS)
			printf("%s\n", dns_result_totext(result));
		else {
			printf("success\n");
			dns_rdataset_init(&rdataset);
			result = dns_db_findrdataset(db, node, NULL, type,
						     &rdataset);
			if (result == DNS_R_NOTFOUND)
				printf("type %d rdataset not found\n", type);
			else if (result != DNS_R_SUCCESS)
				printf("%s\n", dns_result_totext(result));
			else {
				isc_buffer_init(&text, t, sizeof t,
						ISC_BUFFERTYPE_TEXT);
				result = dns_rdataset_totext(&rdataset,
							     &name,
							     ISC_FALSE,
							     &text);
				isc_buffer_used(&text, &r);
				if (result == DNS_R_SUCCESS)
					printf("%.*s", (int)r.length,
					       (char *)r.base);
				else
					printf("%s\n",
					       dns_result_totext(result));
				dns_rdataset_disassociate(&rdataset);
			}
			dns_db_detachnode(db, &node);
		}
	}

	dns_db_detach(&db);
	freename(mctx, &base);

	isc_mem_stats(mctx, stdout);

	return (0);
}
