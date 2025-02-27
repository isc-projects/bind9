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

/*! \file */

#include <stdbool.h>

#include <isc/ascii.h>
#include <isc/fxhash.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/symtab.h>
#include <isc/util.h>

typedef struct elt {
	void *key;
	size_t size;
	unsigned int type;
	isc_symvalue_t value;
} elt_t;

/* 4 bits means 16 entries at creation, which matches the common use of
 * symtab */
#define ISC_SYMTAB_INIT_HASH_BITS 4
#define SYMTAB_MAGIC		  ISC_MAGIC('S', 'y', 'm', 'T')
#define VALID_SYMTAB(st)	  ISC_MAGIC_VALID(st, SYMTAB_MAGIC)

struct isc_symtab {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	isc_symtabaction_t undefine_action;
	void *undefine_arg;

	isc_hashmap_t *hashmap;
	bool case_sensitive;
};

static void
elt_destroy(isc_symtab_t *symtab, elt_t *elt) {
	if (symtab->undefine_action != NULL) {
		(symtab->undefine_action)(elt->key, elt->type, elt->value,
					  symtab->undefine_arg);
	}
	isc_mem_put(symtab->mctx, elt, sizeof(*elt));
}

void
isc_symtab_create(isc_mem_t *mctx, isc_symtabaction_t undefine_action,
		  void *undefine_arg, bool case_sensitive,
		  isc_symtab_t **symtabp) {
	REQUIRE(mctx != NULL);
	REQUIRE(symtabp != NULL && *symtabp == NULL);

	isc_symtab_t *symtab = isc_mem_get(mctx, sizeof(*symtab));
	*symtab = (isc_symtab_t){
		.undefine_action = undefine_action,
		.undefine_arg = undefine_arg,
		.case_sensitive = case_sensitive,
		.magic = SYMTAB_MAGIC,
	};

	isc_mem_attach(mctx, &symtab->mctx);
	isc_hashmap_create(symtab->mctx, ISC_SYMTAB_INIT_HASH_BITS,
			   &symtab->hashmap);

	*symtabp = symtab;
}

void
isc_symtab_destroy(isc_symtab_t **symtabp) {
	REQUIRE(symtabp != NULL && VALID_SYMTAB(*symtabp));

	isc_result_t result;
	isc_hashmap_iter_t *it = NULL;
	isc_symtab_t *symtab = *symtabp;
	*symtabp = NULL;

	symtab->magic = 0;

	isc_hashmap_iter_create(symtab->hashmap, &it);
	for (result = isc_hashmap_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_delcurrent_next(it))
	{
		elt_t *elt = NULL;
		isc_hashmap_iter_current(it, (void **)&elt);
		elt_destroy(symtab, elt);
	}
	INSIST(result == ISC_R_NOMORE);
	isc_hashmap_iter_destroy(&it);

	isc_hashmap_destroy(&symtab->hashmap);

	isc_mem_putanddetach(&symtab->mctx, symtab, sizeof(*symtab));
}

static bool
elt__match(void *node, const void *key0, bool case_sensitive) {
	const elt_t *elt = node;
	const elt_t *key = key0;

	if (elt->size != key->size) {
		return false;
	}

	if (elt->type != key->type) {
		return false;
	}

	if (case_sensitive) {
		return memcmp(elt->key, key->key, key->size) == 0;
	} else {
		return isc_ascii_lowerequal(elt->key, key->key, key->size);
	}
}

static bool
elt_match_case(void *node, const void *key) {
	return elt__match(node, key, true);
}

static bool
elt_match_nocase(void *node, const void *key) {
	return elt__match(node, key, false);
}

static inline uint32_t
elt_hash(elt_t *restrict elt, bool case_sensitive) {
	const uint8_t *ptr = elt->key;
	size_t len = elt->size;
	return fx_hash_bytes(0, ptr, len, case_sensitive);
}

isc_result_t
isc_symtab_lookup(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t *valuep) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(key != NULL);
	REQUIRE(type != 0);

	elt_t *found = NULL;
	elt_t elt = {
		.key = UNCONST(key),
		.size = strlen(key),
		.type = type,
	};
	uint32_t elt_hashval = elt_hash(&elt, symtab->case_sensitive);
	isc_hashmap_match_fn elt_match = symtab->case_sensitive
						 ? elt_match_case
						 : elt_match_nocase;
	isc_result_t result = isc_hashmap_find(
		symtab->hashmap, elt_hashval, elt_match, &elt, (void **)&found);

	if (result == ISC_R_SUCCESS) {
		SET_IF_NOT_NULL(valuep, found->value);
	}

	return result;
}

isc_result_t
isc_symtab_define(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t value, isc_symexists_t exists_policy) {
	return isc_symtab_define_and_return(symtab, key, type, value,
					    exists_policy, NULL);
}

isc_result_t
isc_symtab_define_and_return(isc_symtab_t *symtab, const char *key,
			     unsigned int type, isc_symvalue_t value,
			     isc_symexists_t exists_policy,
			     isc_symvalue_t *valuep) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(key != NULL);
	REQUIRE(type != 0);

	isc_result_t result;
	elt_t *found = NULL;
	elt_t *elt = isc_mem_get(symtab->mctx, sizeof(*elt));
	*elt = (elt_t){
		.key = UNCONST(key),
		.size = strlen(key),
		.type = type,
		.value = value,
	};
	uint32_t elt_hashval = elt_hash(elt, symtab->case_sensitive);
	isc_hashmap_match_fn elt_match = symtab->case_sensitive
						 ? elt_match_case
						 : elt_match_nocase;
again:
	result = isc_hashmap_add(symtab->hashmap, elt_hashval, elt_match, elt,
				 (void *)elt, (void *)&found);

	if (result == ISC_R_SUCCESS) {
		SET_IF_NOT_NULL(valuep, elt->value);
		return ISC_R_SUCCESS;
	}

	switch (exists_policy) {
	case isc_symexists_reject:
		SET_IF_NOT_NULL(valuep, found->value);
		isc_mem_put(symtab->mctx, elt, sizeof(*elt));
		return ISC_R_EXISTS;
	case isc_symexists_replace:
		result = isc_hashmap_delete(symtab->hashmap, elt_hashval,
					    elt_match, elt);
		INSIST(result == ISC_R_SUCCESS);
		elt_destroy(symtab, found);
		goto again;
	default:
		UNREACHABLE();
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_symtab_undefine(isc_symtab_t *symtab, const char *key, unsigned int type) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(key != NULL);
	REQUIRE(type != 0);

	elt_t *found = NULL;
	elt_t elt = {
		.key = UNCONST(key),
		.size = strlen(key),
		.type = type,
	};
	uint32_t elt_hashval = elt_hash(&elt, symtab->case_sensitive);
	isc_hashmap_match_fn elt_match = symtab->case_sensitive
						 ? elt_match_case
						 : elt_match_nocase;

	isc_result_t result = isc_hashmap_find(
		symtab->hashmap, elt_hashval, elt_match, &elt, (void **)&found);

	if (result == ISC_R_NOTFOUND) {
		return ISC_R_NOTFOUND;
	}

	result = isc_hashmap_delete(symtab->hashmap, elt_hashval, elt_match,
				    &elt);
	INSIST(result == ISC_R_SUCCESS);

	elt_destroy(symtab, found);

	return ISC_R_SUCCESS;
}

unsigned int
isc_symtab_count(isc_symtab_t *symtab) {
	REQUIRE(VALID_SYMTAB(symtab));

	return isc_hashmap_count(symtab->hashmap);
}

void
isc_symtab_foreach(isc_symtab_t *symtab, isc_symtabforeachaction_t action,
		   void *arg) {
	REQUIRE(VALID_SYMTAB(symtab));
	REQUIRE(action != NULL);

	isc_result_t result;
	isc_hashmap_iter_t *it = NULL;

	isc_hashmap_iter_create(symtab->hashmap, &it);
	for (result = isc_hashmap_iter_first(it); result == ISC_R_SUCCESS;) {
		elt_t *elt = NULL;
		isc_hashmap_iter_current(it, (void **)&elt);
		if ((action)(elt->key, elt->type, elt->value, arg)) {
			elt_destroy(symtab, elt);
			result = isc_hashmap_iter_delcurrent_next(it);
		} else {
			result = isc_hashmap_iter_next(it);
		}
	}
	INSIST(result == ISC_R_NOMORE);
	isc_hashmap_iter_destroy(&it);
}
