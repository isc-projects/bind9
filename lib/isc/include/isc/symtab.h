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

#pragma once

/*****
***** Module Info
*****/

/*! \file isc/symtab.h
 * \brief Provides a simple memory-based symbol table.
 *
 * Keys are C strings, and key comparisons are either case-insensitive or
 * case-sensitive (decided when the symtab is created).  A type must be
 * specified when looking up, defining, or undefining.
 *
 * It's possible that a client will attempt to define a <key, type, value>
 * tuple when a tuple with the given key and type already exists in the table.
 * What to do in this case is specified by the client.  Possible policies are:
 *
 *\li	#isc_symexists_reject	Disallow the define, returning #ISC_R_EXISTS
 *\li	#isc_symexists_replace	Replace the old value with the new.  The
 *				undefine action (if provided) will be called
 *				with the old <key, type, value> tuple.
 *
 * The symbol table library does not make a copy the key field, so the caller
 * must ensure that any key it passes to isc_symtab_define() will not change
 * or become undefined until it calls isc_symtab_undefine()
 * or isc_symtab_destroy().
 *
 * A user-specified action will be called (if provided) when a symbol is
 * undefined.  It can be used to free memory associated with keys and/or
 * values.
 *
 * A symbol table is implemented as a isc_hashmap; the bits of the
 * hashmap is set by the 'size' parameter to isc_symtbl_create().
 */

/***
 *** Imports.
 ***/

#include <inttypes.h>
#include <stdbool.h>

#include <isc/types.h>

/*
 *** Symbol Tables.
 ***/
/*% Symbol table value. */
typedef union isc_symvalue {
	void	   *as_pointer;
	const void *as_cpointer;
	intmax_t    as_integer;
	uintmax_t   as_uinteger;
} isc_symvalue_t;

typedef void (*isc_symtabaction_t)(char *key, unsigned int type,
				   isc_symvalue_t value, void *userarg);

typedef bool (*isc_symtabforeachaction_t)(char *key, unsigned int type,
					  isc_symvalue_t value, void *userarg);

/*% Symbol table exists. */
typedef enum {
	isc_symexists_reject = 0,  /*%< Disallow the define */
	isc_symexists_replace = 1, /*%< Replace the old value with the new */
} isc_symexists_t;

void
isc_symtab_create(isc_mem_t *mctx, isc_symtabaction_t undefine_action,
		  void *undefine_arg, bool case_sensitive,
		  isc_symtab_t **symtabp);
/*!<
 * \brief Create a symbol table.
 *
 * Requires:
 * \li	'mctx' is valid memory context
 * \li	'symtabp' is not NULL, `*symtabp' is NULL
 */

void
isc_symtab_destroy(isc_symtab_t **symtabp);
/*!<
 * \brief Destroy a symbol table.
 *
 * Requires:
 * \li	'*symtabp' is a valid symbol table
 */

isc_result_t
isc_symtab_lookup(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t *found);
/*!<
 * \brief Lookup a symbol table.
 *
 * Requires:
 * \li	'symtab' is a valid symbol table
 * \li	'key' is a valid C-string
 * \li	'type' is not 0
 * \li	'found' is either NULL or a pointer to isc_symvalue_t
 *
 * Returns:
 * \li	#ISC_R_SUCCESS	Symbol has been deleted from the symbol table
 * \li	#ISC_R_NOTFOUND	Symbol not found in the symbol table
 *
 * Note:
 * \li	On success, if '*found' is not-NULL, it will be filled with value found
 */

isc_result_t
isc_symtab_define(isc_symtab_t *symtab, const char *key, unsigned int type,
		  isc_symvalue_t value, isc_symexists_t exists_policy);

isc_result_t
isc_symtab_define_and_return(isc_symtab_t *symtab, const char *key,
			     unsigned int type, isc_symvalue_t value,
			     isc_symexists_t exists_policy,
			     isc_symvalue_t *found);
/*!<
 * \brief Define a symbol table.
 *
 * Requires:
 * \li	'symtab' is a valid symbol table
 * \li	'key' is a valid C-string
 * \li	'type' is not 0
 * \li	'exists_policy' is valid isc_symexist_t value
 * \li	'found' is either NULL or a pointer to isc_symvalue_t
 *
 * Returns:
 * \li	#ISC_R_SUCCESS	Symbol added to the symbol table
 * \li	#ISC_R_EXISTS	Symbol already defined in the symbol table
 *
 * Note:
 * \li	On success, if '*found' is not-NULL, it will be filled with value added
 * \li	On exists, if '*found' is not-NULL, it will be fileed with value found
 */

isc_result_t
isc_symtab_undefine(isc_symtab_t *symtab, const char *key, unsigned int type);
/*!<
 * \brief Undefine a symbol table.
 *
 * Requires:
 * \li	'symtab' is a valid symbol table
 * \li	'key' is a valid C-string
 * \li	'type' is not 0
 *
 * Returns:
 * \li	#ISC_R_SUCCESS	Symbol has been deleted from the symbol table
 * \li	#ISC_R_NOTFOUND	Symbol not found in the symbol table
 */

unsigned int
isc_symtab_count(isc_symtab_t *symtab);
/*!<
 * \brief Return the number of items in a symbol table.
 *
 * Requires:
 * \li	'symtab' is a valid symbol table
 *
 * Returns:
 * \li	number of items in a symbol table
 */

void
isc_symtab_foreach(isc_symtab_t *symtab, isc_symtabforeachaction_t action,
		   void *arg);
