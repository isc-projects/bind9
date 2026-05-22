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

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/lib.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/diff.h>
#include <dns/fixedname.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>

static uint8_t
minimal_hashbits(size_t count) {
	uint8_t bits = 4;

	while (bits < 24 && count > ((size_t)1 << bits)) {
		bits++;
	}

	return bits;
}

static uint32_t
minimal_hash(const dns_difftuple_t *tuple) {
	isc_hash32_t hash;

	isc_hash32_init(&hash);
	dns_name_hash_ex(&hash, &tuple->name);
	isc_hash32_hash(&hash, &tuple->rdata.rdclass,
			sizeof(tuple->rdata.rdclass), true);
	isc_hash32_hash(&hash, &tuple->rdata.type, sizeof(tuple->rdata.type),
			true);
	isc_hash32_hash(&hash, tuple->rdata.data, tuple->rdata.length, false);
	isc_hash32_hash(&hash, &tuple->ttl, sizeof(tuple->ttl), true);

	return isc_hash32_finalize(&hash);
}

static bool
minimal_match(void *node, const void *key) {
	const dns_difftuple_t *a = node;
	const dns_difftuple_t *b = key;

	return dns_name_caseequal(&a->name, &b->name) &&
	       dns_rdata_compare(&a->rdata, &b->rdata) == 0 && a->ttl == b->ttl;
}

/*
 * This is a copy of dns_diff_appendlistminimal(), with an explicit size hint
 * so that the benchmark can compare different hint strategies.
 */
static void
appendlistminimal(dns_diff_t *diff, dns_diff_t *source, size_t size_hint) {
	isc_hashmap_t *index = NULL;
	isc_result_t result;

	REQUIRE(DNS_DIFF_VALID(diff));
	REQUIRE(DNS_DIFF_VALID(source));
	REQUIRE(diff != source);

	dns_diff_appendlist(diff, source);

	isc_hashmap_create(diff->mctx, minimal_hashbits(size_hint), &index);

	ISC_LIST_FOREACH(diff->tuples, tuple, link) {
		dns_difftuple_t *found = NULL;
		uint32_t hashval = minimal_hash(tuple);

		result = isc_hashmap_add(index, hashval, minimal_match, tuple,
					 tuple, (void **)&found);

		switch (result) {
		case ISC_R_SUCCESS:
			break;

		case ISC_R_EXISTS:
			INSIST(found != NULL);

			if (found->op == tuple->op) {
				UNEXPECTED_ERROR("unexpected non-minimal diff");
				dns_diff_unlink(diff, tuple);
				dns_difftuple_free(&tuple);
			} else {
				result = isc_hashmap_delete(
					index, minimal_hash(found),
					minimal_match, found);
				INSIST(result == ISC_R_SUCCESS);

				dns_diff_unlink(diff, found);
				dns_diff_unlink(diff, tuple);

				dns_difftuple_free(&found);
				dns_difftuple_free(&tuple);
			}
			break;

		default:
			UNREACHABLE();
		}
	}

	isc_hashmap_destroy(&index);
}

static void
append_tuple(dns_diff_t *diff, const dns_name_t *name, uint32_t value) {
	unsigned char data[4] = {
		(unsigned char)(value >> 24),
		(unsigned char)(value >> 16),
		(unsigned char)(value >> 8),
		(unsigned char)value,
	};
	isc_region_t region = { .base = data, .length = sizeof(data) };
	dns_rdata_t rdata = DNS_RDATA_INIT;
	dns_difftuple_t *tuple = NULL;

	dns_rdata_fromregion(&rdata, dns_rdataclass_in, dns_rdatatype_a,
			     &region);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_ADD, name, 300, &rdata,
			     &tuple);
	dns_diff_append(diff, &tuple);
}

static void
file_error(const char *filename, size_t line, const char *message) {
	fprintf(stderr, "%s:%zu: %s\n", filename, line, message);
	exit(EXIT_FAILURE);
}

static size_t
load_tuples(const char *filename, size_t limit, dns_diff_t *diff,
	    dns_diff_t *source) {
	isc_result_t result;
	off_t fileoff;
	FILE *fp = NULL;
	char *filetext = NULL;
	char *pos = NULL;
	char *file_end = NULL;
	size_t filesize;
	size_t tuples = 0;

	result = isc_file_getsize(filename, &fileoff);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "stat(%s): %s\n", filename,
			isc_result_totext(result));
		exit(EXIT_FAILURE);
	}
	filesize = (size_t)fileoff;

	filetext = isc_mem_get(isc_g_mctx, filesize + 1);
	fp = fopen(filename, "r");
	if (fp == NULL || fread(filetext, 1, filesize, fp) < filesize) {
		fprintf(stderr, "read(%s): %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}
	fclose(fp);
	filetext[filesize] = '\0';

	pos = filetext;
	file_end = pos + filesize;
	while (pos < file_end && tuples < limit) {
		char *domain = NULL;
		char *newline = NULL;
		size_t len;

		pos += strspn(pos, "0123456789");
		if (*pos++ != ',') {
			file_error(filename, tuples + 1, "missing comma");
		}

		domain = pos;
		pos += strcspn(pos, "\r\n");
		newline = pos;
		pos += strspn(pos, "\r\n");
		len = (size_t)(newline - domain);
		*newline = '\0';

		dns_fixedname_t fixed;
		dns_name_t *name = dns_fixedname_initname(&fixed);
		isc_buffer_t buffer;
		isc_buffer_init(&buffer, domain, len);
		isc_buffer_add(&buffer, len);
		result = dns_name_fromtext(name, &buffer, dns_rootname, 0);
		if (result != ISC_R_SUCCESS) {
			file_error(filename, tuples + 1,
				   isc_result_totext(result));
		}

		append_tuple((tuples & 1) == 0 ? diff : source, name,
			     (uint32_t)tuples);
		tuples++;
	}

	isc_mem_put(isc_g_mctx, filetext, filesize + 1);
	return tuples;
}

typedef enum {
	hint_scaled_sum,
	hint_simple_sum,
	hint_zero,
} hint_strategy_t;

static void
run_benchmark(const char *filename, size_t limit, hint_strategy_t strategy) {
	dns_diff_t diff, source;
	const char *label = NULL;
	size_t size_hint;

	dns_diff_init(isc_g_mctx, &diff);
	dns_diff_init(isc_g_mctx, &source);

	size_t tuple_count = load_tuples(filename, limit, &diff, &source);
	size_t sum = diff.size + source.size;

	switch (strategy) {
	case hint_scaled_sum:
		label = "sum * 10 / 9";
		size_hint = sum * 10 / 9;
		break;
	case hint_simple_sum:
		label = "simple sum";
		size_hint = sum;
		break;
	case hint_zero:
		label = "zero hint";
		size_hint = 0;
		break;
	default:
		UNREACHABLE();
	}

	isc_nanosecs_t start = isc_time_monotonic();
	appendlistminimal(&diff, &source, size_hint);
	isc_nanosecs_t elapsed = isc_time_monotonic() - start;

	INSIST(dns_diff_size(&diff) == tuple_count);
	INSIST(dns_diff_size(&source) == 0);

	printf("%-14s %zu tuples (%u bits): %.6f seconds\n", label, tuple_count,
	       minimal_hashbits(size_hint), (double)elapsed / NS_PER_SEC);

	dns_diff_clear(&source);
	dns_diff_clear(&diff);
}

static size_t
parse_limit(const char *arg) {
	char *end = NULL;

	errno = 0;
	uintmax_t count = strtoumax(arg, &end, 10);
	if (errno != 0 || end == arg || *end != '\0' || count > UINT32_MAX) {
		fprintf(stderr, "invalid name limit: %s\n", arg);
		exit(EXIT_FAILURE);
	}

	return (size_t)count;
}

int
main(int argc, char **argv) {
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s <names.csv> [name-limit]\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	size_t limit = argc == 3 ? parse_limit(argv[2]) : UINT32_MAX;

	run_benchmark(argv[1], limit, hint_scaled_sum);
	run_benchmark(argv[1], limit, hint_simple_sum);
	run_benchmark(argv[1], limit, hint_zero);

	return EXIT_SUCCESS;
}
