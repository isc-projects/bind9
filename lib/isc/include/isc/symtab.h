/*
 * Copyright (C) 1996, 1997, 1998  Internet Software Consortium.
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

#ifndef ISC_SYMBOL_H
#define ISC_SYMBOL_H 1

#include <isc/mem.h>
#include <isc/result.h>

typedef union isc_symvalue {
	void *				as_pointer;
	int				as_integer;
	unsigned int			as_uinteger;
} isc_symvalue_t;

typedef void (*isc_symtabaction_t)(char *key, unsigned int type,
				   isc_symvalue_t value);

typedef struct isc_symtab		isc_symtab_t;

isc_result_t
isc_symtab_create(isc_mem_t *mctx, unsigned int size,
		  isc_symtabaction_t undefine_action,
		  isc_symtab_t **symtabp);

void
isc_symtab_destroy(isc_symtab_t **symtabp);

isc_result_t
isc_symtab_lookup(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t *value);

isc_result_t
isc_symtab_define(isc_symtab_t *symtab, char *key, unsigned int type,
		  isc_symvalue_t value);

isc_result_t
isc_symtab_undefine(isc_symtab_t *symtab, char *key, unsigned int type);

#endif /* ISC_SYMBOL_H */
