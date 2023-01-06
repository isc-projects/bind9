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
#include <stdint.h>
#include <stdio.h>

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/refcount.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/qp.h>
#include <dns/types.h>

#include "qp_p.h"

#include <tests/qp.h>

/***********************************************************************
 *
 *  key reverse conversions
 */

uint8_t
qp_test_bittoascii(qp_shift_t bit) {
	uint8_t byte = dns_qp_byte_for_bit[bit];
	if (bit == SHIFT_NOBYTE) {
		return ('.');
	} else if (qp_common_character(byte)) {
		return (byte);
	} else if (byte < '-') {
		return ('#');
	} else if (byte < '_') {
		return ('@');
	} else {
		return ('~' - SHIFT_OFFSET + bit);
	}
}

const char *
qp_test_keytoascii(dns_qpkey_t key, size_t len) {
	for (size_t offset = 0; offset < len; offset++) {
		key[offset] = qp_test_bittoascii(key[offset]);
	}
	key[len] = '\0';
	return ((const char *)key);
}

void
qp_test_keytoname(const dns_qpkey_t key, dns_name_t *name) {
	size_t locs[128];
	size_t loc = 0, opos = 0;
	size_t offset;

	REQUIRE(ISC_MAGIC_VALID(name, DNS_NAME_MAGIC));
	REQUIRE(name->buffer != NULL);
	REQUIRE(name->offsets != NULL);

	isc_buffer_clear(name->buffer);

	/* Scan the key looking for label boundaries */
	for (offset = 0; offset < 512; offset++) {
		INSIST(key[offset] >= SHIFT_NOBYTE &&
		       key[offset] < SHIFT_OFFSET);
		INSIST(loc < 128);
		if (key[offset] == SHIFT_NOBYTE) {
			if (key[offset + 1] == SHIFT_NOBYTE) {
				locs[loc] = offset + 1;
				break;
			}
			locs[loc++] = offset + 1;
		} else if (offset == 0) {
			/* This happens for a relative name */
			locs[loc++] = offset;
		}
	}

	/*
	 * In the key the labels are encoded in reverse order, so
	 * we step backward through the label boundaries, then forward
	 * through the labels, to create the DNS wire format data.
	 */
	name->labels = loc;
	while (loc-- > 0) {
		uint8_t len = 0, *lenp = NULL;

		/* Add a length byte to the name data and set an offset */
		lenp = isc_buffer_used(name->buffer);
		isc_buffer_putuint8(name->buffer, 0);
		name->offsets[opos++] = name->length++;

		/* Convert from escaped byte ranges to ASCII */
		for (offset = locs[loc]; offset < locs[loc + 1] - 1; offset++) {
			uint8_t byte = dns_qp_byte_for_bit[key[offset]];
			if (qp_common_character(byte)) {
				isc_buffer_putuint8(name->buffer, byte);
			} else {
				byte += key[++offset] - SHIFT_BITMAP;
				isc_buffer_putuint8(name->buffer, byte);
			}
			len++;
		}

		name->length += len;
		*lenp = len;
	}

	/* Add a root label for absolute names */
	if (key[0] == SHIFT_NOBYTE) {
		name->attributes.absolute = true;
		isc_buffer_putuint8(name->buffer, 0);
		name->length++;
		name->labels++;
	}

	name->ndata = isc_buffer_base(name->buffer);
}

/***********************************************************************
 *
 *  trie properties
 */

static size_t
getheight(dns_qp_t *qp, qp_node_t *n) {
	if (!is_branch(n)) {
		return (0);
	}
	size_t max_height = 0;
	qp_weight_t size = branch_twigs_size(n);
	qp_node_t *twigs = branch_twigs_vector(qp, n);
	for (qp_weight_t pos = 0; pos < size; pos++) {
		size_t height = getheight(qp, &twigs[pos]);
		max_height = ISC_MAX(max_height, height);
	}
	return (max_height + 1);
}

size_t
qp_test_getheight(dns_qp_t *qp) {
	return (getheight(qp, &qp->root));
}

static size_t
maxkeylen(dns_qp_t *qp, qp_node_t *n) {
	if (!is_branch(n)) {
		if (leaf_pval(n) == NULL) {
			return (0);
		} else {
			dns_qpkey_t key;
			return (leaf_qpkey(qp, n, key));
		}
	}
	size_t max_len = 0;
	qp_weight_t size = branch_twigs_size(n);
	qp_node_t *twigs = branch_twigs_vector(qp, n);
	for (qp_weight_t pos = 0; pos < size; pos++) {
		size_t len = maxkeylen(qp, &twigs[pos]);
		max_len = ISC_MAX(max_len, len);
	}
	return (max_len);
}

size_t
qp_test_maxkeylen(dns_qp_t *qp) {
	return (maxkeylen(qp, &qp->root));
}

/***********************************************************************
 *
 *  dump to stdout
 */

static void
dumpread(dns_qpreadable_t qpr, const char *type, const char *tail) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	printf("%s %p root %p base %p methods %p%s", type, qp, &qp->root,
	       qp->base, qp->methods, tail);
}

static void
dumpqp(dns_qp_t *qp, const char *type) {
	dumpread(qp, type, " mctx ");
	printf("%p\n", qp->mctx);
	printf("%s %p usage %p generation %u "
	       "chunk_max %u bump %u fender %u\n",
	       type, qp, qp->usage, qp->generation, qp->chunk_max, qp->bump,
	       qp->fender);
	printf("%s %p leaf %u live %u used %u free %u hold %u\n", type, qp,
	       qp->leaf_count, qp->used_count - qp->free_count, qp->used_count,
	       qp->free_count, qp->hold_count);
	printf("%s %p compact_all=%d shared_arrays=%d"
	       " transaction_mode=%d write_protect=%d\n",
	       type, qp, qp->compact_all, qp->shared_arrays,
	       qp->transaction_mode, qp->write_protect);
}

void
qp_test_dumpread(dns_qpreadable_t qp) {
	dumpread(qp, "qpread", "\n");
	fflush(stdout);
}

void
qp_test_dumpsnap(dns_qpsnap_t *qp) {
	dumpread(qp, "qpsnap", " whence ");
	printf("%p\n", qp->whence);
	fflush(stdout);
}

void
qp_test_dumpqp(dns_qp_t *qp) {
	dumpqp(qp, "qp");
	fflush(stdout);
}

void
qp_test_dumpmulti(dns_qpmulti_t *multi) {
	dumpqp(&multi->phase[0], "qpmulti->phase[0]");
	dumpqp(&multi->phase[1], "qpmulti->phase[1]");
	printf("qpmulti %p read %p snapshots %u\n", &multi, multi->read,
	       multi->snapshots);
	fflush(stdout);
}

void
qp_test_dumpchunks(dns_qp_t *qp) {
	qp_cell_t used = 0;
	qp_cell_t free = 0;
	dumpqp(qp, "qp");
	for (qp_chunk_t c = 0; c < qp->chunk_max; c++) {
		printf("qp %p chunk %u base %p used %u free %u generation %u\n",
		       qp, c, qp->base[c], qp->usage[c].used, qp->usage[c].free,
		       qp->usage[c].generation);
		used += qp->usage[c].used;
		free += qp->usage[c].free;
	}
	printf("qp %p total used %u free %u\n", qp, used, free);
	fflush(stdout);
}

void
qp_test_dumptrie(dns_qpreadable_t qpr) {
	dns_qpread_t *qp = dns_qpreadable_cast(qpr);
	struct {
		qp_ref_t ref;
		qp_shift_t max, pos;
	} stack[512];
	size_t sp = 0;
	qp_cell_t leaf_count = 0;

	/*
	 * fake up a sentinel stack entry corresponding to the root
	 * node; the ref is deliberately out of bounds, and pos == max
	 * so we will immediately stop scanning it
	 */
	stack[sp].ref = ~0U;
	stack[sp].max = 0;
	stack[sp].pos = 0;
	qp_node_t *n = &qp->root;
	printf("%p ROOT\n", n);

	for (;;) {
		if (is_branch(n)) {
			qp_ref_t ref = branch_twigs_ref(n);
			qp_weight_t max = branch_twigs_size(n);
			qp_node_t *twigs = ref_ptr(qp, ref);

			/* brief list of twigs */
			dns_qpkey_t bits;
			size_t len = 0;
			for (qp_shift_t bit = SHIFT_NOBYTE; bit < SHIFT_OFFSET;
			     bit++)
			{
				if (branch_has_twig(n, bit)) {
					bits[len++] = bit;
				}
			}
			assert(len == max);
			qp_test_keytoascii(bits, len);
			printf("%*s%p BRANCH %p %d %zu %s\n", (int)sp * 2, "",
			       n, twigs, ref, branch_key_offset(n), bits);

			++sp;
			stack[sp].ref = ref;
			stack[sp].max = max;
			stack[sp].pos = 0;
		} else {
			if (leaf_pval(n) != NULL) {
				dns_qpkey_t key;
				qp_test_keytoascii(key, leaf_qpkey(qp, n, key));
				printf("%*s%p LEAF %p %d %s\n", (int)sp * 2, "",
				       n, leaf_pval(n), leaf_ival(n), key);
				leaf_count++;
			} else {
				assert(n == &qp->root);
				assert(leaf_count == 0);
				printf("%p EMPTY", n);
			}
		}

		while (stack[sp].pos == stack[sp].max) {
			if (sp == 0) {
				printf("LEAVES %d\n", leaf_count);
				fflush(stdout);
				return;
			}
			--sp;
		}

		n = ref_ptr(qp, stack[sp].ref) + stack[sp].pos;
		stack[sp].pos++;
	}
}

static void
dumpdot_name(qp_node_t *n) {
	if (is_branch(n)) {
		qp_ref_t ref = branch_twigs_ref(n);
		printf("c%dn%d", ref_chunk(ref), ref_cell(ref));
	} else {
		printf("v%p", leaf_pval(n));
	}
}

static void
dumpdot_twig(dns_qp_t *qp, qp_node_t *n) {
	if (is_branch(n)) {
		dumpdot_name(n);
		printf(" [shape=record, label=\"{ \\N\\noff %zu | ",
		       branch_key_offset(n));
		char sep = '{';
		for (qp_shift_t bit = SHIFT_NOBYTE; bit < SHIFT_OFFSET; bit++) {
			if (branch_has_twig(n, bit)) {
				printf("%c <t%d> %c ", sep,
				       branch_twig_pos(n, bit),
				       qp_test_bittoascii(bit));
				sep = '|';
			}
		}
		printf("}}\"];\n");

		qp_weight_t size = branch_twigs_size(n);
		qp_node_t *twigs = branch_twigs_vector(qp, n);

		for (qp_weight_t pos = 0; pos < size; pos++) {
			dumpdot_name(n);
			printf(":t%d:e -> ", pos);
			dumpdot_name(&twigs[pos]);
			printf(":w;\n");
		}

		for (qp_weight_t pos = 0; pos < size; pos++) {
			dumpdot_twig(qp, &twigs[pos]);
		}

	} else {
		dns_qpkey_t key;
		const char *str;
		if (leaf_pval(n) == NULL) {
			str = "EMPTY";
		} else {
			str = qp_test_keytoascii(key, leaf_qpkey(qp, n, key));
		}
		printf("v%p [shape=oval, label=\"\\N ival %d\\n%s\"];\n",
		       leaf_pval(n), leaf_ival(n), str);
	}
}

void
qp_test_dumpdot(dns_qp_t *qp) {
	REQUIRE(QP_VALID(qp));
	qp_node_t *n = &qp->root;
	printf("strict digraph {\nrankdir = \"LR\"; ranksep = 1.0;\n");
	printf("ROOT [shape=point]; ROOT -> ");
	dumpdot_name(n);
	printf(":w;\n");
	dumpdot_twig(qp, n);
	printf("}\n");
}

/**********************************************************************/
