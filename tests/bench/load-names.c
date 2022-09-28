/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <assert.h>
#include <stdlib.h>

#include <isc/file.h>
#include <isc/hashmap.h>
#include <isc/ht.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/qp.h>
#include <dns/rbt.h>
#include <dns/types.h>

#include "qp_p.h"

#include <tests/dns.h>
#include <tests/qp.h>

struct {
	const char *text;
	dns_fixedname_t fixed;
} item[1024 * 1024];

static void
item_check(void *ctx, void *pval, uint32_t ival) {
	UNUSED(ctx);
	assert(pval == &item[ival]);
}

static size_t
item_makekey(dns_qpkey_t key, void *ctx, void *pval, uint32_t ival) {
	UNUSED(ctx);
	assert(pval == &item[ival]);
	return (dns_qpkey_fromname(key, &item[ival].fixed.name));
}

static void
testname(void *ctx, char *buf, size_t size) {
	REQUIRE(ctx == NULL);
	strlcpy(buf, "test", size);
}

const struct dns_qpmethods qpmethods = {
	item_check,
	item_check,
	item_makekey,
	testname,
};

/*
 * hashmap
 */

static void *
new_hashmap(isc_mem_t *mem) {
	isc_hashmap_t *hashmap = NULL;
	isc_hashmap_create(mem, 16, 0, &hashmap);
	return (hashmap);
}

static isc_result_t
add_hashmap(void *hashmap, size_t count) {
	return (isc_hashmap_add(hashmap, NULL, item[count].fixed.name.ndata,
				item[count].fixed.name.length, &item[count]));
}

static void
sqz_hashmap(void *hashmap) {
	UNUSED(hashmap);
}

static isc_result_t
get_hashmap(void *hashmap, size_t count, void **pval) {
	return (isc_hashmap_find(hashmap, NULL, item[count].fixed.name.ndata,
				 item[count].fixed.name.length, pval));
}

/*
 * ht
 */

static void *
new_ht(isc_mem_t *mem) {
	isc_ht_t *ht = NULL;
	isc_ht_init(&ht, mem, 16, 0);
	return (ht);
}

static isc_result_t
add_ht(void *ht, size_t count) {
	return (isc_ht_add(ht, item[count].fixed.name.ndata,
			   item[count].fixed.name.length, &item[count]));
}

static void
sqz_ht(void *ht) {
	UNUSED(ht);
}

static isc_result_t
get_ht(void *ht, size_t count, void **pval) {
	return (isc_ht_find(ht, item[count].fixed.name.ndata,
			    item[count].fixed.name.length, pval));
}

/*
 * rbt
 */

static void *
new_rbt(isc_mem_t *mem) {
	dns_rbt_t *rbt = NULL;
	dns_rbt_create(mem, NULL, NULL, &rbt);
	return (rbt);
}

static isc_result_t
add_rbt(void *rbt, size_t count) {
	return (dns_rbt_addname(rbt, &item[count].fixed.name, &item[count]));
}

static void
sqz_rbt(void *rbt) {
	UNUSED(rbt);
}

static isc_result_t
get_rbt(void *rbt, size_t count, void **pval) {
	return (dns_rbt_findname(rbt, &item[count].fixed.name, 0, NULL, pval));
}

/*
 * qp
 */

static void *
new_qp(isc_mem_t *mem) {
	dns_qp_t *qp = NULL;
	dns_qp_create(mem, &qpmethods, NULL, &qp);
	return (qp);
}

static isc_result_t
add_qp(void *qp, size_t count) {
	return (dns_qp_insert(qp, &item[count], count));
}

static void
sqz_qp(void *qp) {
	dns_qp_compact(qp);
}

static isc_result_t
get_qp(void *qp, size_t count, void **pval) {
	uint32_t ival = 0;
	return (dns_qp_getname(qp, &item[count].fixed.name, pval, &ival));
}

/*
 * fun table
 */
static struct fun {
	const char *name;
	void *(*new)(isc_mem_t *mem);
	isc_result_t (*add)(void *map, size_t count);
	void (*sqz)(void *map);
	isc_result_t (*get)(void *map, size_t count, void **pval);
} fun_list[] = {
	{ "ht", new_ht, add_ht, sqz_ht, get_ht },
	{ "hashmap", new_hashmap, add_hashmap, sqz_hashmap, get_hashmap },
	{ "rbt", new_rbt, add_rbt, sqz_rbt, get_rbt },
	{ "qp", new_qp, add_qp, sqz_qp, get_qp },
	{ NULL, NULL, NULL, NULL, NULL },
};

#define CHECK(result)                                                       \
	do {                                                                \
		if (result != ISC_R_SUCCESS) {                              \
			fprintf(stderr, "%s\n", isc_result_totext(result)); \
			exit(1);                                            \
		}                                                           \
	} while (0)

#define FILE_CHECK(check, msg)                                                 \
	do {                                                                   \
		if (!(check)) {                                                \
			fprintf(stderr, "%s:%zu: %s\n", filename, count, msg); \
			exit(1);                                               \
		}                                                              \
	} while (0)

int
main(int argc, char *argv[]) {
	isc_result_t result;

	isc_mem_create(&mctx);

	if (argc != 2) {
		fprintf(stderr, "usage: load-names <filename.csv>\n");
		exit(1);
	}

	const char *filename = argv[1];
	off_t fileoff;
	result = isc_file_getsize(filename, &fileoff);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "stat(%s): %s\n", filename,
			isc_result_totext(result));
		exit(1);
	}
	size_t filesize = (size_t)fileoff;

	char *filetext = isc_mem_get(mctx, filesize + 1);
	FILE *fp = fopen(filename, "r");
	if (fp == NULL || fread(filetext, 1, filesize, fp) < filesize) {
		fprintf(stderr, "read(%s): %s\n", filename, strerror(errno));
		exit(1);
	}
	fclose(fp);
	filetext[filesize] = '\0';

	size_t count = 0;
	size_t wirebytes = 0;
	size_t labels = 0;

	char *pos = filetext;
	char *file_end = pos + filesize;
	while (pos < file_end) {
		FILE_CHECK(count < ARRAY_SIZE(item), "too many lines");
		pos += strspn(pos, "0123456789");

		FILE_CHECK(*pos++ == ',', "missing comma");

		char *domain = pos;
		pos += strcspn(pos, "\r\n");
		FILE_CHECK(*pos != '\0', "missing newline");
		char *newline = pos;
		pos += strspn(pos, "\r\n");
		size_t len = newline - domain;

		item[count].text = domain;
		domain[len] = '\0';

		dns_name_t *name = dns_fixedname_initname(&item[count].fixed);
		isc_buffer_t buffer;
		isc_buffer_init(&buffer, domain, len);
		isc_buffer_add(&buffer, len);
		result = dns_name_fromtext(name, &buffer, dns_rootname, 0,
					   NULL);
		FILE_CHECK(result == ISC_R_SUCCESS, isc_result_totext(result));

		wirebytes += name->length;
		labels += name->labels;
		count++;
	}

	printf("names %g MB labels %g MB\n", (double)wirebytes / 1048576.0,
	       (double)labels / 1048576.0);

	size_t lines = count;

	for (struct fun *fun = fun_list; fun->name != NULL; fun++) {
		isc_time_t t0;
		isc_time_now_hires(&t0);

		isc_mem_t *mem = NULL;
		isc_mem_create(&mem);
		void *map = fun->new (mem);

		for (count = 0; count < lines; count++) {
			result = fun->add(map, count);
			CHECK(result);
		}
		fun->sqz(map);

		isc_time_t t1;
		isc_time_now_hires(&t1);

		for (count = 0; count < lines; count++) {
			void *pval = NULL;
			result = fun->get(map, count, &pval);
			CHECK(result);
			assert(pval == &item[count]);
		}

		isc_time_t t2;
		isc_time_now_hires(&t2);

		printf("%f sec to load %s\n",
		       (double)isc_time_microdiff(&t1, &t0) / (1000.0 * 1000.0),
		       fun->name);
		printf("%f sec to query %s\n",
		       (double)isc_time_microdiff(&t2, &t1) / (1000.0 * 1000.0),
		       fun->name);
		printf("%g MB used by %s\n",
		       (double)isc_mem_inuse(mem) / (1024.0 * 1024.0),
		       fun->name);
	}
}
