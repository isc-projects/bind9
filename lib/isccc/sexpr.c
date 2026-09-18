/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0 AND ISC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Copyright (C) 2001 Nominum, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NOMINUM DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file */

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <isc/assertions.h>

#include <isccc/sexpr.h>
#include <isccc/util.h>

static isccc_sexpr_t sexpr_t = { ISCCC_SEXPRTYPE_T, { NULL } };

#define CAR(s)	  (s)->value.as_dottedpair.car
#define CDR(s)	  (s)->value.as_dottedpair.cdr
#define PARENT(s) (s)->value.as_dottedpair.parent

static void
set_parent(isccc_sexpr_t *child, isccc_sexpr_t *parent) {
	if (child != NULL && child->type == ISCCC_SEXPRTYPE_DOTTEDPAIR) {
		PARENT(child) = parent;
	}
}

isccc_sexpr_t *
isccc_sexpr_cons(isccc_sexpr_t *car, isccc_sexpr_t *cdr) {
	isccc_sexpr_t *sexpr;

	sexpr = malloc(sizeof(*sexpr));
	if (sexpr == NULL) {
		return NULL;
	}
	sexpr->type = ISCCC_SEXPRTYPE_DOTTEDPAIR;
	CAR(sexpr) = car;
	CDR(sexpr) = cdr;
	PARENT(sexpr) = NULL;
	set_parent(car, sexpr);
	set_parent(cdr, sexpr);

	return sexpr;
}

isccc_sexpr_t *
isccc_sexpr_tconst(void) {
	return &sexpr_t;
}

isccc_sexpr_t *
isccc_sexpr_fromstring(const char *str) {
	isccc_sexpr_t *sexpr;

	REQUIRE(str != NULL);

	sexpr = malloc(sizeof(*sexpr));
	if (sexpr == NULL) {
		return NULL;
	}
	sexpr->type = ISCCC_SEXPRTYPE_STRING;
	sexpr->value.as_string = strdup(str);
	if (sexpr->value.as_string == NULL) {
		free(sexpr);
		return NULL;
	}

	return sexpr;
}

isccc_sexpr_t *
isccc_sexpr_frombinary(const isccc_region_t *region) {
	isccc_sexpr_t *sexpr;
	unsigned int region_size;

	REQUIRE(region != NULL);

	sexpr = malloc(sizeof(*sexpr));
	if (sexpr == NULL) {
		return NULL;
	}
	sexpr->type = ISCCC_SEXPRTYPE_BINARY;
	region_size = REGION_SIZE(*region);
	/*
	 * We add an extra byte when we malloc so we can NUL terminate
	 * the binary data.  This allows the caller to use it as a C
	 * string.  It's up to the caller to ensure this is safe.  We don't
	 * add 1 to the length of the binary region, because the NUL is
	 * not part of the binary data.
	 */
	sexpr->value.as_region.rstart = malloc(region_size + 1);
	if (sexpr->value.as_region.rstart == NULL) {
		free(sexpr);
		return NULL;
	}
	sexpr->value.as_region.rend = sexpr->value.as_region.rstart +
				      region_size;
	memmove(sexpr->value.as_region.rstart, region->rstart, region_size);
	/*
	 * NUL terminate.
	 */
	sexpr->value.as_region.rstart[region_size] = '\0';

	return sexpr;
}

void
isccc_sexpr_free(isccc_sexpr_t **sexprp) {
	isccc_sexpr_t *root = NULL;
	isccc_sexpr_t *child, *sexpr, *parent;

	REQUIRE(sexprp != NULL);

	sexpr = *sexprp;
	*sexprp = NULL;
	if (sexpr == NULL) {
		return;
	}

	switch (sexpr->type) {
	case ISCCC_SEXPRTYPE_STRING:
		free(sexpr->value.as_string);
		break;
	case ISCCC_SEXPRTYPE_DOTTEDPAIR:
		root = sexpr;
		/* Iterative post-order depth-first traversal. */
		for (;;) {
			child = CAR(sexpr) != NULL ? CAR(sexpr) : CDR(sexpr);
			/* Descend into pair, free leaf. */
			if (child != NULL) {
				if (child->type == ISCCC_SEXPRTYPE_DOTTEDPAIR) {
					INSIST(PARENT(child) == sexpr);
					sexpr = child;
				} else if (CAR(sexpr) == child) {
					isccc_sexpr_free(&CAR(sexpr));
				} else {
					isccc_sexpr_free(&CDR(sexpr));
				}
				continue;
			}

			/* No children left. */
			if (sexpr == root) {
				break;
			}

			/* Free empty node, go up. */
			parent = PARENT(sexpr);
			if (CAR(parent) == sexpr) {
				CAR(parent) = NULL;
			} else {
				INSIST(CDR(parent) == sexpr);
				CDR(parent) = NULL;
			}
			free(sexpr);
			sexpr = parent;
		}
		break;
	case ISCCC_SEXPRTYPE_BINARY:
		free(sexpr->value.as_region.rstart);
		break;
	}
	free(sexpr);
}

static bool
printable(const isccc_region_t *r) {
	unsigned char *curr;

	curr = r->rstart;
	while (curr != r->rend) {
		if (!isprint(*curr)) {
			return false;
		}
		curr++;
	}

	return true;
}

void
isccc_sexpr_print(const isccc_sexpr_t *sexpr, FILE *stream) {
	const isccc_sexpr_t *root, *car, *cdr;
	unsigned int size, i;
	unsigned char *curr;

	REQUIRE(stream != NULL);

	if (sexpr == NULL) {
		fprintf(stream, "nil");
		return;
	}

	switch (sexpr->type) {
	case ISCCC_SEXPRTYPE_T:
		fprintf(stream, "t");
		break;
	case ISCCC_SEXPRTYPE_STRING:
		fprintf(stream, "\"%s\"", sexpr->value.as_string);
		break;
	case ISCCC_SEXPRTYPE_DOTTEDPAIR:
		root = sexpr;
		fprintf(stream, "(");
		while (sexpr != NULL) {
			car = CAR(sexpr);
			if (car != NULL &&
			    car->type == ISCCC_SEXPRTYPE_DOTTEDPAIR)
			{
				fprintf(stream, "(");
				sexpr = car;
				continue;
			}
			isccc_sexpr_print(car, stream);

			/*
			 * Print cdr; at list end, close it and ascend to
			 * enclosing cell.
			 */
			for (;;) {
				cdr = CDR(sexpr);
				if (cdr != NULL &&
				    cdr->type == ISCCC_SEXPRTYPE_DOTTEDPAIR)
				{
					fprintf(stream, " ");
					break;
				}
				if (cdr != NULL) {
					fprintf(stream, " . ");
					isccc_sexpr_print(cdr, stream);
				}
				fprintf(stream, ")");
				while (sexpr != root &&
				       CDR(PARENT(sexpr)) == sexpr)
				{
					sexpr = PARENT(sexpr);
				}
				if (sexpr == root) {
					cdr = NULL;
					break;
				}
				sexpr = PARENT(sexpr);
			}
			sexpr = cdr;
		}
		break;
	case ISCCC_SEXPRTYPE_BINARY:
		size = REGION_SIZE(sexpr->value.as_region);
		curr = sexpr->value.as_region.rstart;
		if (printable(&sexpr->value.as_region)) {
			fprintf(stream, "'%.*s'", (int)size, curr);
		} else {
			fprintf(stream, "0x");
			for (i = 0; i < size; i++) {
				fprintf(stream, "%02x", *curr++);
			}
		}
		break;
	default:
		UNREACHABLE();
	}
}

isccc_sexpr_t *
isccc_sexpr_car(isccc_sexpr_t *list) {
	REQUIRE(list != NULL && list->type == ISCCC_SEXPRTYPE_DOTTEDPAIR);

	return CAR(list);
}

isccc_sexpr_t *
isccc_sexpr_cdr(isccc_sexpr_t *list) {
	REQUIRE(list != NULL && list->type == ISCCC_SEXPRTYPE_DOTTEDPAIR);

	return CDR(list);
}

void
isccc_sexpr_setcar(isccc_sexpr_t *pair, isccc_sexpr_t *car) {
	REQUIRE(pair != NULL && pair->type == ISCCC_SEXPRTYPE_DOTTEDPAIR);

	CAR(pair) = car;
	set_parent(car, pair);
}

void
isccc_sexpr_setcdr(isccc_sexpr_t *pair, isccc_sexpr_t *cdr) {
	REQUIRE(pair != NULL && pair->type == ISCCC_SEXPRTYPE_DOTTEDPAIR);

	CDR(pair) = cdr;
	set_parent(cdr, pair);
}

isccc_sexpr_t *
isccc_sexpr_addtolist(isccc_sexpr_t **l1p, isccc_sexpr_t *l2) {
	isccc_sexpr_t *last, *elt, *l1;

	REQUIRE(l1p != NULL);
	l1 = *l1p;
	REQUIRE(l1 == NULL || l1->type == ISCCC_SEXPRTYPE_DOTTEDPAIR);

	elt = isccc_sexpr_cons(l2, NULL);
	if (elt == NULL) {
		return NULL;
	}
	if (l1 == NULL) {
		*l1p = elt;
		return elt;
	}
	for (last = l1; CDR(last) != NULL; last = CDR(last)) {
		/* Nothing */
	}
	CDR(last) = elt;
	PARENT(elt) = last;

	return elt;
}

bool
isccc_sexpr_listp(isccc_sexpr_t *sexpr) {
	if (sexpr == NULL || sexpr->type == ISCCC_SEXPRTYPE_DOTTEDPAIR) {
		return true;
	}
	return false;
}

bool
isccc_sexpr_emptyp(isccc_sexpr_t *sexpr) {
	if (sexpr == NULL) {
		return true;
	}
	return false;
}

bool
isccc_sexpr_stringp(isccc_sexpr_t *sexpr) {
	if (sexpr != NULL && sexpr->type == ISCCC_SEXPRTYPE_STRING) {
		return true;
	}
	return false;
}

bool
isccc_sexpr_binaryp(isccc_sexpr_t *sexpr) {
	if (sexpr != NULL && sexpr->type == ISCCC_SEXPRTYPE_BINARY) {
		return true;
	}
	return false;
}

char *
isccc_sexpr_tostring(isccc_sexpr_t *sexpr) {
	REQUIRE(sexpr != NULL && (sexpr->type == ISCCC_SEXPRTYPE_STRING ||
				  sexpr->type == ISCCC_SEXPRTYPE_BINARY));

	if (sexpr->type == ISCCC_SEXPRTYPE_BINARY) {
		return (char *)sexpr->value.as_region.rstart;
	}
	return sexpr->value.as_string;
}

isccc_region_t *
isccc_sexpr_tobinary(isccc_sexpr_t *sexpr) {
	REQUIRE(sexpr != NULL && sexpr->type == ISCCC_SEXPRTYPE_BINARY);
	return &sexpr->value.as_region;
}
