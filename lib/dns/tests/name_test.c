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

#if HAVE_CMOCKA

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/print.h>
#include <isc/thread.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdataset.h>

#include "dnstest.h"

/* Set to true (or use -v option) for verbose output */
static bool verbose = false;

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = dns_test_begin(NULL, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	dns_test_end();

	return (0);
}

/* dns_name_fullcompare test */
static void
fullcompare_test(void **state) {
	dns_fixedname_t fixed1;
	dns_fixedname_t fixed2;
	dns_name_t *name1;
	dns_name_t *name2;
	dns_namereln_t relation;
	int i;
	isc_result_t result;
	struct {
		const char *name1;
		const char *name2;
		dns_namereln_t relation;
		int order;
		unsigned int nlabels;
	} data[] = {
		/* relative */
		{ "", "", dns_namereln_equal, 0, 0 },
		{ "foo", "", dns_namereln_subdomain, 1, 0 },
		{ "", "foo", dns_namereln_contains, -1, 0 },
		{ "foo", "bar", dns_namereln_none, 4, 0 },
		{ "bar", "foo", dns_namereln_none, -4, 0 },
		{ "bar.foo", "foo", dns_namereln_subdomain, 1, 1 },
		{ "foo", "bar.foo", dns_namereln_contains, -1, 1 },
		{ "baz.bar.foo", "bar.foo", dns_namereln_subdomain, 1, 2 },
		{ "bar.foo", "baz.bar.foo", dns_namereln_contains, -1, 2 },
		{ "foo.example", "bar.example", dns_namereln_commonancestor, 4,
		  1 },

		/* absolute */
		{ ".", ".", dns_namereln_equal, 0, 1 },
		{ "foo.", "bar.", dns_namereln_commonancestor, 4, 1 },
		{ "bar.", "foo.", dns_namereln_commonancestor, -4, 1 },
		{ "foo.example.", "bar.example.", dns_namereln_commonancestor,
		  4, 2 },
		{ "bar.foo.", "foo.", dns_namereln_subdomain, 1, 2 },
		{ "foo.", "bar.foo.", dns_namereln_contains, -1, 2 },
		{ "baz.bar.foo.", "bar.foo.", dns_namereln_subdomain, 1, 3 },
		{ "bar.foo.", "baz.bar.foo.", dns_namereln_contains, -1, 3 },
		{ NULL, NULL, dns_namereln_none, 0, 0 }
	};

	UNUSED(state);

	name1 = dns_fixedname_initname(&fixed1);
	name2 = dns_fixedname_initname(&fixed2);
	for (i = 0; data[i].name1 != NULL; i++) {
		int order = 3000;
		unsigned int nlabels = 3000;

		if (data[i].name1[0] == 0) {
			dns_fixedname_init(&fixed1);
		} else {
			result = dns_name_fromstring2(name1, data[i].name1,
						      NULL, 0, NULL);
			assert_int_equal(result, ISC_R_SUCCESS);
		}
		if (data[i].name2[0] == 0) {
			dns_fixedname_init(&fixed2);
		} else {
			result = dns_name_fromstring2(name2, data[i].name2,
						      NULL, 0, NULL);
			assert_int_equal(result, ISC_R_SUCCESS);
		}
		relation = dns_name_fullcompare(name1, name1, &order, &nlabels);
		assert_int_equal(relation, dns_namereln_equal);
		assert_int_equal(order, 0);
		assert_int_equal(nlabels, name1->labels);

		/* Some random initializer */
		order = 3001;
		nlabels = 3001;

		relation = dns_name_fullcompare(name1, name2, &order, &nlabels);
		assert_int_equal(relation, data[i].relation);
		assert_int_equal(order, data[i].order);
		assert_int_equal(nlabels, data[i].nlabels);
	}
}

static void
compress_test(dns_name_t *name1, dns_name_t *name2, dns_name_t *name3,
	      unsigned char *expected, unsigned int length,
	      dns_compress_t *cctx, dns_decompress_t *dctx) {
	isc_buffer_t source;
	isc_buffer_t target;
	dns_name_t name;
	unsigned char buf1[1024];
	unsigned char buf2[1024];

	isc_buffer_init(&source, buf1, sizeof(buf1));
	isc_buffer_init(&target, buf2, sizeof(buf2));

	assert_int_equal(dns_name_towire(name1, cctx, &source), ISC_R_SUCCESS);

	assert_int_equal(dns_name_towire(name2, cctx, &source), ISC_R_SUCCESS);
	assert_int_equal(dns_name_towire(name2, cctx, &source), ISC_R_SUCCESS);
	assert_int_equal(dns_name_towire(name3, cctx, &source), ISC_R_SUCCESS);

	isc_buffer_setactive(&source, source.used);

	dns_name_init(&name, NULL);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, 0, &target) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, 0, &target) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, 0, &target) ==
		      ISC_R_SUCCESS);
	RUNTIME_CHECK(dns_name_fromwire(&name, &source, dctx, 0, &target) ==
		      ISC_R_SUCCESS);
	dns_decompress_invalidate(dctx);

	assert_int_equal(target.used, length);
	assert_true(memcmp(target.base, expected, target.used) == 0);
}

/* name compression test */
static void
compression_test(void **state) {
	unsigned int allowed;
	dns_compress_t cctx;
	dns_decompress_t dctx;
	dns_name_t name1;
	dns_name_t name2;
	dns_name_t name3;
	isc_region_t r;
	unsigned char plain1[] = "\003yyy\003foo";
	unsigned char plain2[] = "\003bar\003yyy\003foo";
	unsigned char plain3[] = "\003xxx\003bar\003foo";
	unsigned char plain[] = "\003yyy\003foo\0\003bar\003yyy\003foo\0\003"
				"bar\003yyy\003foo\0\003xxx\003bar\003foo";

	UNUSED(state);

	dns_name_init(&name1, NULL);
	r.base = plain1;
	r.length = sizeof(plain1);
	dns_name_fromregion(&name1, &r);

	dns_name_init(&name2, NULL);
	r.base = plain2;
	r.length = sizeof(plain2);
	dns_name_fromregion(&name2, &r);

	dns_name_init(&name3, NULL);
	r.base = plain3;
	r.length = sizeof(plain3);
	dns_name_fromregion(&name3, &r);

	/* Test 1: NONE */
	allowed = DNS_COMPRESS_NONE;
	assert_int_equal(dns_compress_init(&cctx, -1, dt_mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain), &cctx,
		      &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test2: GLOBAL14 */
	allowed = DNS_COMPRESS_GLOBAL14;
	assert_int_equal(dns_compress_init(&cctx, -1, dt_mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain), &cctx,
		      &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test3: ALL */
	allowed = DNS_COMPRESS_ALL;
	assert_int_equal(dns_compress_init(&cctx, -1, dt_mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain), &cctx,
		      &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test4: NONE disabled */
	allowed = DNS_COMPRESS_NONE;
	assert_int_equal(dns_compress_init(&cctx, -1, dt_mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_compress_disable(&cctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain), &cctx,
		      &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test5: GLOBAL14 disabled */
	allowed = DNS_COMPRESS_GLOBAL14;
	assert_int_equal(dns_compress_init(&cctx, -1, dt_mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_compress_disable(&cctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain), &cctx,
		      &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);

	/* Test6: ALL disabled */
	allowed = DNS_COMPRESS_ALL;
	assert_int_equal(dns_compress_init(&cctx, -1, dt_mctx), ISC_R_SUCCESS);
	dns_compress_setmethods(&cctx, allowed);
	dns_compress_disable(&cctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, allowed);

	compress_test(&name1, &name2, &name3, plain, sizeof(plain), &cctx,
		      &dctx);

	dns_compress_rollback(&cctx, 0);
	dns_compress_invalidate(&cctx);
}

/*
 * Lay out a chain of compression pointers in 'buf', ending with a name
 * that is a single pointer into it, and return the total wire length.
 * '*name_offset' receives the offset that name starts at.
 *
 * The chain terminates at a root label at offset zero and each node points
 * at the node before it, so decompressing the name follows exactly
 * 'follows' pointers. A labelled chain puts a one octet label in front of
 * every pointer, the way a conforming encoder's output does, so the name
 * gains a label per hop; an unlabelled chain is pointers only and always
 * decompresses to the root.
 */
static size_t
build_ptr_chain(uint8_t *buf, size_t size, unsigned int follows, bool labelled,
		size_t *name_offset) {
	unsigned int nodes = follows - 1;
	size_t stride = labelled ? 4 : 2;
	size_t target;
	size_t p = 0;

	REQUIRE(follows > 0);
	REQUIRE(1 + stride * nodes + 2 <= size);

	buf[p++] = 0x00;

	for (unsigned int node = 0; node < nodes; node++) {
		target = (node == 0) ? 0 : 1 + stride * (node - 1);
		if (labelled) {
			buf[p++] = 1;
			buf[p++] = 'a';
		}
		buf[p++] = 0xC0 | (target >> 8);
		buf[p++] = target & 0xFF;
	}

	*name_offset = p;
	target = (nodes == 0) ? 0 : 1 + stride * (nodes - 1);
	buf[p++] = 0xC0 | (target >> 8);
	buf[p++] = target & 0xFF;

	return (p);
}

static isc_result_t
fromwire_ptr_chain(dns_name_t *name, uint8_t *buf, size_t size,
		   unsigned int follows, bool labelled,
		   dns_decompress_t *dctx) {
	isc_buffer_t b;
	size_t name_offset;
	size_t len = build_ptr_chain(buf, size, follows, labelled,
				     &name_offset);

	isc_buffer_init(&b, buf, len);
	isc_buffer_add(&b, len);
	isc_buffer_forward(&b, name_offset);
	isc_buffer_setactive(&b, len - name_offset);

	return (dns_name_fromwire(name, &b, dctx, 0, NULL));
}

/* the hop limit must admit the longest name a conforming encoder can emit */
static void
fromwire_hops_floor_test(void **state) {
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);
	uint8_t buf[1024];
	dns_decompress_t dctx;

	UNUSED(state);

	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_ANY);
	dns_decompress_setmethods(&dctx, DNS_COMPRESS_GLOBAL14);

	/*
	 * The interop floor: a chain that gains a label per hop builds a
	 * perfectly legal 255 octet, 128 label name in DNS_NAME_MAXHOPS
	 * hops, and our own encoder emits chains of exactly this shape.
	 * Lowering the limit would reject conforming names.
	 */
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXHOPS, true, &dctx),
			 ISC_R_SUCCESS);
	assert_int_equal(name->length, DNS_NAME_MAXWIRE);
	assert_int_equal(dns_name_countlabels(name), DNS_NAME_MAXLABELS);

	/*
	 * Which is also why the hop limit sits where it does: one hop
	 * further and a labelled chain has already overrun the name length
	 * limit, so the two limits meet rather than overlap.
	 */
	name = dns_fixedname_initname(&fixed);
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXHOPS + 1, true, &dctx),
			 DNS_R_NAMETOOLONG);

	/* refusing to decompress at all still takes precedence */
	name = dns_fixedname_initname(&fixed);
	dns_decompress_invalidate(&dctx);
	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_NONE);
	dns_decompress_setmethods(&dctx, DNS_COMPRESS_GLOBAL14);
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXHOPS + 1, false, &dctx),
			 DNS_R_DISALLOWED);

	dns_decompress_invalidate(&dctx);
}

/*
 * Lay out a chain in which every node spends one label but three hops:
 * the label is followed by a pointer to a pointer to a pointer to the
 * previous node's label. That keeps each run of indirection within
 * DNS_NAME_MAXINDIRECTS while letting the hop count grow three times as
 * fast as the label count, so it reaches DNS_NAME_MAXHOPS long before the
 * name reaches 255 octets. The name itself is a single pointer at the end
 * of the chain, as in build_ptr_chain().
 *
 * Node k occupies 8 octets at 1 + 8k:
 *
 *	+0  pointer to the previous node's label (or the root at 0)
 *	+2  pointer to +0
 *	+4  the label "a"
 *	+6  pointer to +2
 *
 * Decompressing the name follows 1 + 3 * nodes pointers and yields a
 * name of 'nodes' labels.
 */
static size_t
build_indirect_chain(uint8_t *buf, size_t size, unsigned int nodes,
		     size_t *name_offset) {
	size_t p = 0;

	REQUIRE(1 + 8 * (size_t)nodes + 2 <= size);

	buf[p++] = 0x00;

	for (unsigned int node = 0; node < nodes; node++) {
		size_t base = p;
		size_t prev_label = (node == 0) ? 0 : base - 4;

		buf[p++] = 0xC0 | (prev_label >> 8); /* +0 */
		buf[p++] = prev_label & 0xFF;
		buf[p++] = 0xC0 | (base >> 8); /* +2 */
		buf[p++] = base & 0xFF;
		buf[p++] = 1; /* +4 */
		buf[p++] = 'a';
		buf[p++] = 0xC0 | ((base + 2) >> 8); /* +6 */
		buf[p++] = (base + 2) & 0xFF;
	}

	*name_offset = p;
	size_t last_label = (nodes == 0) ? 0 : p - 4;
	buf[p++] = 0xC0 | (last_label >> 8);
	buf[p++] = last_label & 0xFF;

	return (p);
}

static isc_result_t
fromwire_indirect_chain(dns_name_t *name, uint8_t *buf, size_t size,
			unsigned int nodes, dns_decompress_t *dctx) {
	isc_buffer_t b;
	size_t name_offset;
	size_t len = build_indirect_chain(buf, size, nodes, &name_offset);

	isc_buffer_init(&b, buf, len);
	isc_buffer_add(&b, len);
	isc_buffer_forward(&b, name_offset);
	isc_buffer_setactive(&b, len - name_offset);

	return (dns_name_fromwire(name, &b, dctx, 0, NULL));
}

/*
 * The per-name hop limit itself. fromwire_hops_floor never reaches it: a
 * labelled chain of DNS_NAME_MAXHOPS + 1 hops has already overrun the name
 * length limit, and an unlabelled chain is stopped by DNS_NAME_MAXINDIRECTS
 * first. Only a chain that follows several pointers per label can exceed
 * DNS_NAME_MAXHOPS while staying inside both of those, and that is what
 * this test builds.
 */
static void
fromwire_hops_limit_test(void **state) {
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	uint8_t buf[2048];
	dns_decompress_t dctx;
	/* 1 + 3 * nodes hops: the most nodes that stay at or under the limit */
	const unsigned int under = (DNS_NAME_MAXHOPS - 1) / 3;

	UNUSED(state);

	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_ANY);
	dns_decompress_setmethods(&dctx, DNS_COMPRESS_GLOBAL14);

	/* 1 + 3 * under <= DNS_NAME_MAXHOPS: accepted, well short of 255 */
	name = dns_fixedname_initname(&fixed);
	assert_int_equal(
		fromwire_indirect_chain(name, buf, sizeof(buf), under, &dctx),
		ISC_R_SUCCESS);
	assert_int_equal(dns_name_countlabels(name), under + 1);
	assert_true(name->length < DNS_NAME_MAXWIRE);

	/*
	 * One more node pushes the count past DNS_NAME_MAXHOPS while the
	 * name is still short and no run of indirection is any longer than
	 * before, so the hop limit is the only thing that can refuse it.
	 */
	name = dns_fixedname_initname(&fixed);
	assert_int_equal(fromwire_indirect_chain(name, buf, sizeof(buf),
						 under + 1, &dctx),
			 DNS_R_BADPOINTER);

	/*
	 * And it is a per-name limit: a fresh name walking the accepted
	 * chain is charged from zero again.
	 */
	name = dns_fixedname_initname(&fixed);
	assert_int_equal(
		fromwire_indirect_chain(name, buf, sizeof(buf), under, &dctx),
		ISC_R_SUCCESS);

	dns_decompress_invalidate(&dctx);
}

/* a pointer may lead straight to another only so many times over */
static void
fromwire_indirects_test(void **state) {
	dns_fixedname_t fixed;
	dns_name_t *name = dns_fixedname_initname(&fixed);
	uint8_t buf[1024];
	dns_decompress_t dctx;

	UNUSED(state);

	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_ANY);
	dns_decompress_setmethods(&dctx, DNS_COMPRESS_GLOBAL14);

	/*
	 * A pointer only chain is nothing but indirection, so its length is
	 * exactly what this limit counts.
	 */
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXINDIRECTS + 1, false,
					    &dctx),
			 ISC_R_SUCCESS);
	assert_true(dns_name_equal(name, dns_rootname));

	name = dns_fixedname_initname(&fixed);
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXINDIRECTS + 2, false,
					    &dctx),
			 DNS_R_BADPOINTER);

	/*
	 * A label between two pointers resets the count, which is why this
	 * limit does not bound a chain that spends one per hop - see
	 * fromwire_budget for what does.
	 */
	name = dns_fixedname_initname(&fixed);
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXHOPS, true, &dctx),
			 ISC_R_SUCCESS);
	assert_int_equal(name->length, DNS_NAME_MAXWIRE);

	dns_decompress_invalidate(&dctx);
}

/* names sharing one chain are also bounded together, not just apart */
static void
fromwire_budget_test(void **state) {
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	uint8_t buf[1024];
	dns_decompress_t dctx;

	UNUSED(state);

	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_ANY);
	dns_decompress_setmethods(&dctx, DNS_COMPRESS_GLOBAL14);

	/* The default budget accommodates repeated standalone names. */
	assert_int_equal(dctx.budget, UINT32_MAX);
	for (int i = 0; i < 4; i++) {
		name = dns_fixedname_initname(&fixed);
		assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
						    DNS_NAME_MAXHOPS, true,
						    &dctx),
				 ISC_R_SUCCESS);
	}
	assert_int_equal(dctx.budget, UINT32_MAX - 4 * DNS_NAME_MAXHOPS);

	/*
	 * A budget of one name's worth of hops buys exactly one such name.
	 * The second is refused even though it is within the per-name limit,
	 * which is the whole point: that limit cannot see how many names
	 * are walking the same chain.
	 */
	dctx.budget = DNS_NAME_MAXHOPS;

	name = dns_fixedname_initname(&fixed);
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXHOPS, true, &dctx),
			 ISC_R_SUCCESS);
	assert_int_equal(dctx.budget, 0);

	name = dns_fixedname_initname(&fixed);
	assert_int_equal(fromwire_ptr_chain(name, buf, sizeof(buf),
					    DNS_NAME_MAXHOPS, true, &dctx),
			 DNS_R_BADPOINTER);

	dns_decompress_invalidate(&dctx);
}

/* The legacy parser must still honor DNS_NAME_DOWNCASE. */
static void
fromwire_downcase_test(void **state) {
	const unsigned char wire[] = { 7,   'E', 'x', 'A',  'm', 'P',
				       'l', 'E', 0,   0xc0, 0 };
	const unsigned char lower[] = {
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0
	};

	UNUSED(state);

	for (unsigned int i = 0; i < 2; i++) {
		dns_fixedname_t fixed;
		dns_name_t *name = dns_fixedname_initname(&fixed);
		dns_decompress_t dctx;
		isc_buffer_t source;
		isc_result_t result;

		dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_ANY);
		dns_decompress_setmethods(&dctx, DNS_COMPRESS_GLOBAL14);
		dctx.budget = 1;
		isc_buffer_constinit(&source, wire, sizeof(wire));
		isc_buffer_add(&source, sizeof(wire));
		isc_buffer_forward(&source, sizeof(lower));
		isc_buffer_setactive(&source, 2);
		result = dns_name_fromwire(name, &source, &dctx,
					   i == 0 ? 0 : DNS_NAME_DOWNCASE,
					   NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(name->length, sizeof(lower));
		assert_memory_equal(name->ndata, i == 0 ? wire : lower,
				    sizeof(lower));
		assert_int_equal(isc_buffer_remaininglength(&source), 0);
		assert_int_equal(dctx.budget, 0);
		dns_decompress_invalidate(&dctx);
	}
}

/*
 * Ordinary compressed MX records fill several scratch buffers. Retrying a
 * name or RDATA in a fresh buffer must still produce the full answer.
 */
static void
parse_decompression_retry_test(void **state) {
	unsigned char wirebuf[4096];
	isc_buffer_t wire;
	dns_message_t *msg = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	dns_rdataset_t *rdataset;
	isc_region_t region;
	const unsigned int records = 100;
	isc_result_t result;

	UNUSED(state);

	isc_buffer_init(&wire, wirebuf, sizeof(wirebuf));
	isc_buffer_putuint16(&wire, 0x1234);
	isc_buffer_putuint16(&wire, DNS_MESSAGEFLAG_QR);
	isc_buffer_putuint16(&wire, 1);	      /* QDCOUNT */
	isc_buffer_putuint16(&wire, records); /* ANCOUNT */
	isc_buffer_putuint16(&wire, 0);	      /* NSCOUNT */
	isc_buffer_putuint16(&wire, 0);	      /* ARCOUNT */
	dns_test_namefromstring("retry.example.", &fixed);
	dns_name_toregion(dns_fixedname_name(&fixed), &region);
	isc_buffer_putmem(&wire, region.base, region.length);
	isc_buffer_putuint16(&wire, dns_rdatatype_mx);
	isc_buffer_putuint16(&wire, dns_rdataclass_in);
	for (unsigned int i = 0; i < records; i++) {
		isc_buffer_putuint16(&wire, 0xc000 | DNS_MESSAGE_HEADERLEN);
		isc_buffer_putuint16(&wire, dns_rdatatype_mx);
		isc_buffer_putuint16(&wire, dns_rdataclass_in);
		isc_buffer_putuint32(&wire, 300);
		isc_buffer_putuint16(&wire, 4);
		isc_buffer_putuint16(&wire, i);
		isc_buffer_putuint16(&wire, 0xc000 | DNS_MESSAGE_HEADERLEN);
	}

	dns_message_create(dt_mctx, DNS_MESSAGE_INTENTPARSE, &msg);
	result = dns_message_parse(msg, &wire, 0);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_ptr_not_equal(ISC_LIST_HEAD(msg->scratchpad),
			     ISC_LIST_TAIL(msg->scratchpad));
	result = dns_message_firstname(msg, DNS_SECTION_ANSWER);
	assert_int_equal(result, ISC_R_SUCCESS);
	dns_message_currentname(msg, DNS_SECTION_ANSWER, &name);
	assert_true(dns_name_equal(name, dns_fixedname_name(&fixed)));
	rdataset = ISC_LIST_HEAD(name->list);
	assert_non_null(rdataset);
	assert_int_equal(rdataset->type, dns_rdatatype_mx);
	assert_int_equal(dns_rdataset_count(rdataset), records);
	dns_message_detach(&msg);
}

/* is trust-anchor-telemetry test */
static void
istat_test(void **state) {
	dns_fixedname_t fixed;
	dns_name_t *name;
	isc_result_t result;
	size_t i;
	struct {
		const char *name;
		bool istat;
	} data[] = { { ".", false },
		     { "_ta-", false },
		     { "_ta-1234", true },
		     { "_TA-1234", true },
		     { "+TA-1234", false },
		     { "_fa-1234", false },
		     { "_td-1234", false },
		     { "_ta_1234", false },
		     { "_ta-g234", false },
		     { "_ta-1h34", false },
		     { "_ta-12i4", false },
		     { "_ta-123j", false },
		     { "_ta-1234-abcf", true },
		     { "_ta-1234-abcf-ED89", true },
		     { "_ta-12345-abcf-ED89", false },
		     { "_ta-.example", false },
		     { "_ta-1234.example", true },
		     { "_ta-1234-abcf.example", true },
		     { "_ta-1234-abcf-ED89.example", true },
		     { "_ta-12345-abcf-ED89.example", false },
		     { "_ta-1234-abcfe-ED89.example", false },
		     { "_ta-1234-abcf-EcD89.example", false } };

	UNUSED(state);

	name = dns_fixedname_initname(&fixed);

	for (i = 0; i < (sizeof(data) / sizeof(data[0])); i++) {
		result = dns_name_fromstring(name, data[i].name, 0, NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		assert_int_equal(dns_name_istat(name), data[i].istat);
	}
}

/* dns_nane_init */
static void
init_test(void **state) {
	dns_name_t name;
	unsigned char offsets[1];

	UNUSED(state);

	dns_name_init(&name, offsets);

	assert_null(name.ndata);
	assert_int_equal(name.length, 0);
	assert_int_equal(name.labels, 0);
	assert_int_equal(name.attributes, 0);
	assert_ptr_equal(name.offsets, offsets);
	assert_null(name.buffer);
}

/* dns_nane_invalidate */
static void
invalidate_test(void **state) {
	dns_name_t name;
	unsigned char offsets[1];

	UNUSED(state);

	dns_name_init(&name, offsets);
	dns_name_invalidate(&name);

	assert_null(name.ndata);
	assert_int_equal(name.length, 0);
	assert_int_equal(name.labels, 0);
	assert_int_equal(name.attributes, 0);
	assert_null(name.offsets);
	assert_null(name.buffer);
}

/* dns_nane_setbuffer/hasbuffer */
static void
buffer_test(void **state) {
	dns_name_t name;
	unsigned char buf[BUFSIZ];
	isc_buffer_t b;

	UNUSED(state);

	isc_buffer_init(&b, buf, BUFSIZ);
	dns_name_init(&name, NULL);
	dns_name_setbuffer(&name, &b);
	assert_ptr_equal(name.buffer, &b);
	assert_true(dns_name_hasbuffer(&name));
}

/* dns_nane_isabsolute */
static void
isabsolute_test(void **state) {
	struct {
		const char *namestr;
		bool expect;
	} testcases[] = { { "x", false },
			  { "a.b.c.d.", true },
			  { "x.z", false } };
	unsigned int i;

	UNUSED(state);

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		isc_result_t result;
		dns_name_t name;
		unsigned char data[BUFSIZ];
		isc_buffer_t b, nb;
		size_t len;

		len = strlen(testcases[i].namestr);
		isc_buffer_constinit(&b, testcases[i].namestr, len);
		isc_buffer_add(&b, len);

		dns_name_init(&name, NULL);
		isc_buffer_init(&nb, data, BUFSIZ);
		dns_name_setbuffer(&name, &nb);
		result = dns_name_fromtext(&name, &b, NULL, 0, NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		assert_int_equal(dns_name_isabsolute(&name),
				 testcases[i].expect);
	}
}

/* dns_nane_hash */
static void
hash_test(void **state) {
	struct {
		const char *name1;
		const char *name2;
		bool expect;
		bool expecti;
	} testcases[] = {
		{ "a.b.c.d", "A.B.C.D", true, false },
		{ "a.b.c.d.", "A.B.C.D.", true, false },
		{ "a.b.c.d", "a.b.c.d", true, true },
		{ "A.B.C.D.", "A.B.C.D.", true, false },
		{ "x.y.z.w", "a.b.c.d", false, false },
		{ "x.y.z.w.", "a.b.c.d.", false, false },
	};
	unsigned int i;

	UNUSED(state);

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		isc_result_t result;
		dns_fixedname_t f1, f2;
		dns_name_t *n1, *n2;
		unsigned int h1, h2;

		n1 = dns_fixedname_initname(&f1);
		n2 = dns_fixedname_initname(&f2);

		result = dns_name_fromstring2(n1, testcases[i].name1, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dns_name_fromstring2(n2, testcases[i].name2, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		/* Check case-insensitive hashing first */
		h1 = dns_name_hash(n1, false);
		h2 = dns_name_hash(n2, false);

		if (verbose) {
			print_message("# %s hashes to %u, "
				      "%s to %u, case insensitive\n",
				      testcases[i].name1, h1,
				      testcases[i].name2, h2);
		}

		assert_int_equal((h1 == h2), testcases[i].expect);

		/* Now case-sensitive */
		h1 = dns_name_hash(n1, false);
		h2 = dns_name_hash(n2, false);

		if (verbose) {
			print_message("# %s hashes to %u, "
				      "%s to %u, case sensitive\n",
				      testcases[i].name1, h1,
				      testcases[i].name2, h2);
		}

		assert_int_equal((h1 == h2), testcases[i].expect);
	}
}

/* dns_nane_issubdomain */
static void
issubdomain_test(void **state) {
	struct {
		const char *name1;
		const char *name2;
		bool expect;
	} testcases[] = {
		{ "c.d", "a.b.c.d", false }, { "c.d.", "a.b.c.d.", false },
		{ "b.c.d", "c.d", true },    { "a.b.c.d.", "c.d.", true },
		{ "a.b.c", "a.b.c", true },  { "a.b.c.", "a.b.c.", true },
		{ "x.y.z", "a.b.c", false }
	};
	unsigned int i;

	UNUSED(state);

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		isc_result_t result;
		dns_fixedname_t f1, f2;
		dns_name_t *n1, *n2;

		n1 = dns_fixedname_initname(&f1);
		n2 = dns_fixedname_initname(&f2);

		result = dns_name_fromstring2(n1, testcases[i].name1, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dns_name_fromstring2(n2, testcases[i].name2, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		if (verbose) {
			print_message("# check: %s %s a subdomain of %s\n",
				      testcases[i].name1,
				      testcases[i].expect ? "is" : "is not",
				      testcases[i].name2);
		}

		assert_int_equal(dns_name_issubdomain(n1, n2),
				 testcases[i].expect);
	}
}

/* dns_nane_countlabels */
static void
countlabels_test(void **state) {
	struct {
		const char *namestr;
		unsigned int expect;
	} testcases[] = {
		{ "c.d", 2 },	  { "c.d.", 3 },  { "a.b.c.d.", 5 },
		{ "a.b.c.d", 4 }, { "a.b.c", 3 }, { ".", 1 },
	};
	unsigned int i;

	UNUSED(state);

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		isc_result_t result;
		dns_fixedname_t fname;
		dns_name_t *name;

		name = dns_fixedname_initname(&fname);

		result = dns_name_fromstring2(name, testcases[i].namestr, NULL,
					      0, NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		if (verbose) {
			print_message("# %s: expect %u labels\n",
				      testcases[i].namestr,
				      testcases[i].expect);
		}

		assert_int_equal(dns_name_countlabels(name),
				 testcases[i].expect);
	}
}

/* dns_nane_getlabel */
static void
getlabel_test(void **state) {
	struct {
		const char *name1;
		unsigned int pos1;
		const char *name2;
		unsigned int pos2;
	} testcases[] = {
		{ "c.d", 1, "a.b.c.d", 3 },
		{ "a.b.c.d", 3, "c.d", 1 },
		{ "a.b.c.", 3, "A.B.C.", 3 },
	};
	unsigned int i;

	UNUSED(state);

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		isc_result_t result;
		dns_fixedname_t f1, f2;
		dns_name_t *n1, *n2;
		dns_label_t l1, l2;
		unsigned int j;

		n1 = dns_fixedname_initname(&f1);
		n2 = dns_fixedname_initname(&f2);

		result = dns_name_fromstring2(n1, testcases[i].name1, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dns_name_fromstring2(n2, testcases[i].name2, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		dns_name_getlabel(n1, testcases[i].pos1, &l1);
		dns_name_getlabel(n2, testcases[i].pos2, &l2);
		assert_int_equal(l1.length, l2.length);

		for (j = 0; j < l1.length; j++) {
			assert_int_equal(l1.base[j], l2.base[j]);
		}
	}
}

/* dns_nane_getlabelsequence */
static void
getlabelsequence_test(void **state) {
	struct {
		const char *name1;
		unsigned int pos1;
		const char *name2;
		unsigned int pos2;
		unsigned int range;
	} testcases[] = {
		{ "c.d", 1, "a.b.c.d", 3, 1 },
		{ "a.b.c.d.e", 2, "c.d", 0, 2 },
		{ "a.b.c", 0, "a.b.c", 0, 3 },
	};
	unsigned int i;

	UNUSED(state);

	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); i++) {
		isc_result_t result;
		dns_name_t t1, t2;
		dns_fixedname_t f1, f2;
		dns_name_t *n1, *n2;

		/* target names */
		dns_name_init(&t1, NULL);
		dns_name_init(&t2, NULL);

		/* source names */
		n1 = dns_fixedname_initname(&f1);
		n2 = dns_fixedname_initname(&f2);

		result = dns_name_fromstring2(n1, testcases[i].name1, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);
		result = dns_name_fromstring2(n2, testcases[i].name2, NULL, 0,
					      NULL);
		assert_int_equal(result, ISC_R_SUCCESS);

		dns_name_getlabelsequence(n1, testcases[i].pos1,
					  testcases[i].range, &t1);
		dns_name_getlabelsequence(n2, testcases[i].pos2,
					  testcases[i].range, &t2);

		assert_true(dns_name_equal(&t1, &t2));
	}
}

#ifdef DNS_BENCHMARK_TESTS

/*
 * XXXMUKS: Don't delete this code. It is useful in benchmarking the
 * name parser, but we don't require it as part of the unit test runs.
 */

/* Benchmark dns_name_fromwire() implementation */

static void *
fromwire_thread(void *arg) {
	unsigned int maxval = 32000000;
	uint8_t data[] = { 3,	'w', 'w', 'w', 7,   'e', 'x',
			   'a', 'm', 'p', 'l', 'e', 7,	 'i',
			   'n', 'v', 'a', 'l', 'i', 'd', 0 };
	unsigned char output_data[DNS_NAME_MAXWIRE];
	isc_buffer_t source, target;
	unsigned int i;
	dns_decompress_t dctx;

	UNUSED(arg);

	dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_STRICT);
	dns_decompress_setmethods(&dctx, DNS_COMPRESS_NONE);

	isc_buffer_init(&source, data, sizeof(data));
	isc_buffer_add(&source, sizeof(data));
	isc_buffer_init(&target, output_data, sizeof(output_data));

	/* Parse 32 million names in each thread */
	for (i = 0; i < maxval; i++) {
		dns_name_t name;

		isc_buffer_clear(&source);
		isc_buffer_clear(&target);
		isc_buffer_add(&source, sizeof(data));
		isc_buffer_setactive(&source, sizeof(data));

		dns_name_init(&name, NULL);
		(void)dns_name_fromwire(&name, &source, &dctx, 0, &target);
	}

	return (NULL);
}

static void
benchmark_test(void **state) {
	isc_result_t result;
	unsigned int i;
	isc_time_t ts1, ts2;
	double t;
	unsigned int nthreads;
	isc_thread_t threads[32];

	UNUSED(state);

	debug_mem_record = false;

	result = isc_time_now(&ts1);
	assert_int_equal(result, ISC_R_SUCCESS);

	nthreads = ISC_MIN(isc_os_ncpus(), 32);
	nthreads = ISC_MAX(nthreads, 1);
	for (i = 0; i < nthreads; i++) {
		isc_thread_create(fromwire_thread, NULL, &threads[i]);
	}

	for (i = 0; i < nthreads; i++) {
		isc_thread_join(threads[i], NULL);
	}

	result = isc_time_now(&ts2);
	assert_int_equal(result, ISC_R_SUCCESS);

	t = isc_time_microdiff(&ts2, &ts1);

	printf("%u dns_name_fromwire() calls, %f seconds, %f calls/second\n",
	       nthreads * 32000000, t / 1000000.0,
	       (nthreads * 32000000) / (t / 1000000.0));
}

#endif /* DNS_BENCHMARK_TESTS */

int
main(int argc, char **argv) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(fullcompare_test),
		cmocka_unit_test_setup_teardown(compression_test, _setup,
						_teardown),
		cmocka_unit_test(fromwire_hops_floor_test),
		cmocka_unit_test(fromwire_hops_limit_test),
		cmocka_unit_test(fromwire_indirects_test),
		cmocka_unit_test(fromwire_budget_test),
		cmocka_unit_test(fromwire_downcase_test),
		cmocka_unit_test_setup_teardown(parse_decompression_retry_test,
						_setup, _teardown),
		cmocka_unit_test(istat_test),
		cmocka_unit_test(init_test),
		cmocka_unit_test(invalidate_test),
		cmocka_unit_test(buffer_test),
		cmocka_unit_test(isabsolute_test),
		cmocka_unit_test(hash_test),
		cmocka_unit_test(issubdomain_test),
		cmocka_unit_test(countlabels_test),
		cmocka_unit_test(getlabel_test),
		cmocka_unit_test(getlabelsequence_test),
#ifdef DNS_BENCHMARK_TESTS
		cmocka_unit_test_setup_teardown(benchmark_test, _setup,
						_teardown),
#endif /* DNS_BENCHMARK_TESTS */
	};
	int c;

	while ((c = isc_commandline_parse(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = true;
			break;
		default:
			break;
		}
	}

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
