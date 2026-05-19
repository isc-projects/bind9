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

/*! \file isccfg/cfg.h
 * \brief
 * This is the new, table-driven, YACC-free configuration file parser.
 */

/***
 *** Imports
 ***/

#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

#include <isc/formatcheck.h>
#include <isc/list.h>
#include <isc/refcount.h>
#include <isc/types.h>

/***
 *** Types
 ***/

typedef struct cfg_aclconfctx cfg_aclconfctx_t;

/*%
 * A configuration parser.
 */
typedef struct cfg_parser cfg_parser_t;

/*%
 * A configuration type definition object.  There is a single
 * static cfg_type_t object for each data type supported by
 * the configuration parser.
 */
typedef struct cfg_type cfg_type_t;

/*%
 * A configuration object.  This is the basic building block of the
 * configuration parse tree.  It contains a value (which may be
 * of one of several types) and information identifying the file
 * and line number the value came from, for printing error
 * messages.
 */
typedef struct cfg_obj cfg_obj_t;

/*%
 * A configuration object list element.
 */
typedef struct cfg_listelt cfg_listelt_t;

/*%
 * A configuration clause definition.
 */
typedef struct cfg_clausedef cfg_clausedef_t;

/*%
 * A callback function to be called when parsing an option
 * that needs to be interpreted at parsing time, like
 * "directory".
 */
typedef isc_result_t (*cfg_parsecallback_t)(const char	    *clausename,
					    const cfg_obj_t *obj, void *arg);

//* clang-format off */
#define CFG_LIST_FOREACH(listobj, elt)                                        \
	for (const cfg_listelt_t *elt = cfg_list_first(listobj); elt != NULL; \
	     elt = cfg_list_next(elt))
//* clang-format on */

/***
 *** Functions
 ***/

isc_result_t
cfg_parse_file(const char *file, const cfg_type_t *type, unsigned int flags,
	       cfg_obj_t **ret);

isc_result_t
cfg_parse_buffer(isc_buffer_t *buffer, const char *file, unsigned int line,
		 const cfg_type_t *type, unsigned int flags, cfg_obj_t **ret);
/*%<
 * Read a configuration containing data of type 'type'
 * and make '*ret' point to its parse tree.
 *
 * The configuration is read from the file 'filename'
 * (isc_parse_file()) or the buffer 'buffer'
 * (isc_parse_buffer()).
 *
 * If 'file' is not NULL, it is the name of the file, or a name to use
 * for the buffer in place of the filename, when logging errors.
 *
 * If 'line' is not 0, then it is the beginning line number to report
 * when logging errors. This is useful when passing text that has been
 * read from the middle of a file.
 *
 * Returns an error if the file or buffer does not parse correctly.
 *
 * Requires:
 *\li 	"file" is valid.
 *\li   "buffer" is valid.
 *\li 	"mctx" is valid.
 *\li	"type" is valid.
 *\li 	"cfg" is non-NULL and "*cfg" is NULL.
 *\li   "flags" be one or more of CFG_PCTX_NODEPRECATED or zero.
 *
 * Returns:
 *     \li #ISC_R_SUCCESS                 - success
 *\li      #ISC_R_INVALIDFILE             - file doesn't exist or is unreadable
 *\li      others	                      - file contains errors
 */

cfg_obj_t *
cfg_parser_currentfile(cfg_parser_t *pctx);
/*%<
 * Returns the current file of a parser (as an cfg_obj_t qstring). NULL is non
 * existent.
 */

isc_result_t
cfg_map_addclone(cfg_obj_t *map, const cfg_obj_t *obj,
		 const cfg_clausedef_t *clause);
/*%<
 * Add a clone of 'obj' to the specified clause in mapbody 'mapobj'.
 * If the clause is tagged with CFG_CLAUSEFLAG_MULTI, the function expects
 * that 'obj' is a list and will clone each element and sequentially add them
 * (preserving the order), instead of adding a list as single element of
 * map[clausename].
 *
 * Require:
 * \li     'obj' is a valid cfg_obj_t.
 * \li     'mapobj' is a valid cfg_obj_t of type map.
 * \li     'clause' is a valid clause definition.
 */

void
cfg_list_addclone(cfg_obj_t *dst, const cfg_obj_t *src, bool prepend);
/*%<
 * Clone each `src` element and add them into the existing list `dst`. If
 * `prepend` is set, the `src` elements will be added at the beginning of
 * `src`, and the order of `src` is preserved.
 *
 * Both `dst` and `src` must be valid pointers to cfg objects of type list.
 */

void
cfg_obj_clone(const cfg_obj_t *source, cfg_obj_t **target);
/*%<
 * Allocate a new configuration object and copy the value from the `source`
 * object into the newly allocated object. The copy is a "deep" copy, i.e. if
 * `source` is a list, map, tuple, etc, it recursively clones the children
 * and copies their values as well. The cloned node is attached to the
 * memory context of the source node.
 *
 * Require:
 * \li     'source' is a valid cfg_obj_t with copy function set.
 * \li     'target' is non-NULL and '*target' is NULL.
 *
 * Ensures:
 * \li     'target' contains the cloned object.
 */

bool
cfg_obj_isvoid(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of void type (e.g., an optional
 * value not specified).
 */

bool
cfg_obj_ismap(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of a map type.
 */

bool
cfg_obj_isfixedpoint(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of a fixedpoint type.
 */

bool
cfg_obj_ispercentage(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of a percentage type.
 */

isc_result_t
cfg_map_get(const cfg_obj_t *mapobj, const char *name, const cfg_obj_t **obj);
/*%<
 * Extract an element from a configuration object, which
 * must be of a map type.
 *
 * Requires:
 * \li     'mapobj' points to a valid configuration object of a map type.
 * \li     'name' points to a null-terminated string.
 * \li	'obj' is non-NULL and '*obj' is NULL.
 *
 * Returns:
 * \li     #ISC_R_SUCCESS                  - success
 * \li     #ISC_R_NOTFOUND                 - name not found in map
 */

const cfg_obj_t *
cfg_map_getname(const cfg_obj_t *mapobj);
/*%<
 * Get the name of a named map object, like a server "key" clause.
 *
 * Requires:
 *    \li  'mapobj' points to a valid configuration object of a map type.
 *
 * Returns:
 * \li     A pointer to a configuration object naming the map object,
 *	or NULL if the map object does not have a name.
 */

unsigned int
cfg_map_count(const cfg_obj_t *mapobj);
/*%<
 * Get the number of elements defined in the symbol table of a map object.
 *
 * Requires:
 *    \li  'mapobj' points to a valid configuration object of a map type.
 *
 * Returns:
 * \li     The number of elements in the map object.
 */

bool
cfg_obj_istuple(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of a map type.
 */

const cfg_obj_t *
cfg_tuple_get(const cfg_obj_t *tupleobj, const char *name);
/*%<
 * Extract an element from a configuration object, which
 * must be of a tuple type.
 *
 * Requires:
 * \li     'tupleobj' points to a valid configuration object of a tuple type.
 * \li     'name' points to a null-terminated string naming one of the
 *\li	fields of said tuple type.
 */

bool
cfg_obj_isuint32(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of integer type.
 */

uint32_t
cfg_obj_asuint32(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of 32-bit integer type.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of 32-bit integer type.
 *
 * Returns:
 * \li     A 32-bit unsigned integer.
 */

bool
cfg_obj_isuint64(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of integer type.
 */

uint64_t
cfg_obj_asuint64(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of 64-bit integer type.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of 64-bit integer type.
 *
 * Returns:
 * \li     A 64-bit unsigned integer.
 */

uint32_t
cfg_obj_asfixedpoint(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of fixed point number.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of fixed point type.
 *
 * Returns:
 * \li     A 32-bit unsigned integer.
 */

uint32_t
cfg_obj_aspercentage(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of percentage
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of percentage type.
 *
 * Returns:
 * \li     A 32-bit unsigned integer.
 */

bool
cfg_obj_isduration(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of duration type.
 */

uint32_t
cfg_obj_asduration(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of duration
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of duration type.
 *
 * Returns:
 * \li     A duration in seconds.
 */

bool
cfg_obj_isstring(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of string type.
 */

const char *
cfg_obj_asstring(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of a string type
 * as a null-terminated string.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of a string type.
 *
 * Returns:
 * \li     A pointer to a null terminated string.
 */

bool
cfg_obj_isboolean(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of a boolean type.
 */

bool
cfg_obj_asboolean(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object of a boolean type.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of a boolean type.
 *
 * Returns:
 * \li     A boolean value.
 */

bool
cfg_obj_issockaddr(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is a socket address.
 */

bool
cfg_obj_issockaddrtls(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is a socket address with an optional tls configuration.
 */

const isc_sockaddr_t *
cfg_obj_assockaddr(const cfg_obj_t *obj);
/*%<
 * Returns the value of a configuration object representing a socket address.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of a socket address
 * type, or of a socket address type with an optional tls configuration.
 *
 * Returns:
 * \li     A pointer to a sockaddr.  The sockaddr must be copied by the caller
 *      if necessary.
 */

const char *
cfg_obj_getsockaddrtls(const cfg_obj_t *obj);
/*%<
 * Returns the TLS value of a configuration object representing a
 * socket address.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of a
 *         socket address type.
 *
 * Returns:
 * \li     TLS value associated with a sockaddr, or NULL.
 */

bool
cfg_obj_isnetprefix(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is a network prefix.
 */

void
cfg_obj_asnetprefix(const cfg_obj_t *obj, isc_netaddr_t *netaddr,
		    unsigned int *prefixlen);
/*%<
 * Gets the value of a configuration object representing a network
 * prefix.  The network address is returned through 'netaddr' and the
 * prefix length in bits through 'prefixlen'.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of network prefix type.
 *\li	'netaddr' and 'prefixlen' are non-NULL.
 */

bool
cfg_obj_islist(const cfg_obj_t *obj);
/*%<
 * Return true iff 'obj' is of list type.
 */

const cfg_listelt_t *
cfg_list_first(const cfg_obj_t *obj);
/*%<
 * Returns the first list element in a configuration object of a list type.
 *
 * Requires:
 * \li     'obj' points to a valid configuration object of a list type or NULL.
 *
 * Returns:
 *   \li   A pointer to a cfg_listelt_t representing the first list element,
 * 	or NULL if the list is empty or nonexistent.
 */

const cfg_listelt_t *
cfg_list_next(const cfg_listelt_t *elt);
/*%<
 * Returns the next element of a list of configuration objects.
 *
 * Requires:
 * \li     'elt' points to cfg_listelt_t obtained from cfg_list_first() or
 *	a previous call to cfg_list_next().
 *
 * Returns:
 * \li     A pointer to a cfg_listelt_t representing the next element,
 * 	or NULL if there are no more elements.
 */

unsigned int
cfg_list_length(const cfg_obj_t *obj, bool recurse);
/*%<
 * Returns the length of a list of configure objects.  If obj is
 * not a list, returns 0.  If recurse is true, add in the length of
 * all contained lists.
 */

void
cfg_list_unlink(cfg_obj_t *list, cfg_listelt_t *elt);
/*%<
 * Unlink 'elt' from the list object 'list', and free the memory associated
 * with 'elt'.
 */

cfg_obj_t *
cfg_listelt_value(const cfg_listelt_t *elt);
/*%<
 * Returns the configuration object associated with cfg_listelt_t.
 *
 * Requires:
 * \li     'elt' points to cfg_listelt_t obtained from cfg_list_first() or
 *	cfg_list_next().
 *
 * Returns:
 * \li     A non-NULL pointer to a configuration object.
 */

void
cfg_print(const cfg_obj_t *obj,
	  void (*f)(void *closure, const char *text, int textlen),
	  void *closure);
void
cfg_printx(const cfg_obj_t *obj, unsigned int flags,
	   void (*f)(void *closure, const char *text, int textlen),
	   void *closure);

#define CFG_PRINTER_XKEY    0x1 /* '?' out shared keys. */
#define CFG_PRINTER_ONELINE 0x2 /* print config as a single line */
#define CFG_PRINTER_ACTIVEONLY                 \
	0x4 /* print only active configuration \
	     * options, omitting ancient,      \
	     * obsolete, nonimplemented,       \
	     * and test-only options. */

/*%<
 * Print the configuration object 'obj' by repeatedly calling the
 * function 'f', passing 'closure' and a region of text starting
 * at 'text' and comprising 'textlen' characters.
 *
 * If CFG_PRINTER_XKEY the contents of shared keys will be obscured
 * by replacing them with question marks ('?')
 */

void
cfg_print_grammar(const cfg_type_t *type, unsigned int flags,
		  void (*f)(void *closure, const char *text, int textlen),
		  void *closure);
/*%<
 * Print a summary of the grammar of the configuration type 'type'.
 */

bool
cfg_obj_istype(const cfg_obj_t *obj, const cfg_type_t *type);
/*%<
 * Return true iff 'obj' is of type 'type'.
 */

void
cfg_obj_log(const cfg_obj_t *obj, int level, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);
/*%<
 * Log a message concerning configuration object 'obj' to the logging
 * channel of 'pctx', at log level 'level'.  The message will be prefixed
 * with the file name(s) and line number where 'obj' was defined.
 */

const char *
cfg_obj_file(const cfg_obj_t *obj);
/*%<
 * Return the file that defined this object.
 */

unsigned int
cfg_obj_line(const cfg_obj_t *obj);
/*%<
 * Return the line in file where this object was defined.
 */

const cfg_clausedef_t *
cfg_map_firstclause(const cfg_type_t *map, const void **clauses,
		    unsigned int *idx);

const cfg_clausedef_t *
cfg_map_nextclause(const cfg_type_t *map, const void **clauses,
		   unsigned int *idx);

const cfg_clausedef_t *
cfg_map_findclause(const cfg_type_t *map, const char *name);

typedef isc_result_t(pluginlist_cb_t)(
	const cfg_obj_t *config, const cfg_obj_t *obj, cfg_aclconfctx_t *aclctx,
	const char *plugin_path, const char *parameters, void *callback_data);
/*%<
 * Function prototype for the callback used with cfg_pluginlist_foreach().
 * Called once for each element of the list passed to cfg_pluginlist_foreach().
 * If this callback returns anything else than #ISC_R_SUCCESS, no further list
 * elements will be processed.
 *
 * \li 'config' - the 'config' object passed to cfg_pluginlist_foreach()
 * \li 'obj' - object representing the specific "plugin" stanza to be processed
 * \li 'plugin_path' - path to the shared object with plugin code
 * \li 'parameters' - configuration text for the plugin
 * \li 'callback_data' - the pointer passed to cfg_pluginlist_foreach()
 */

isc_result_t
cfg_pluginlist_foreach(const cfg_obj_t *config, const cfg_obj_t *list,
		       cfg_aclconfctx_t *aclctx, pluginlist_cb_t *callback,
		       void *callback_data);
/*%<
 * For every "plugin" stanza present in 'list' (which in turn is a part of
 * 'config'), invoke the given 'callback', passing 'callback_data' to it along
 * with a fixed set of arguments (see the definition of the #pluginlist_cb_t
 * type).  Interrupt processing if 'callback' returns something else than
 * #ISC_R_SUCCESS for any element of 'list'.
 *
 * Requires:
 *
 * \li 'config' is not NULL
 * \li 'callback' is not NULL
 *
 * Returns:
 *
 * \li #ISC_R_SUCCESS if 'callback' returned #ISC_R_SUCCESS for all elements of
 *     'list'
 * \li first 'callback' return value which was not #ISC_R_SUCCESS otherwise
 */

ISC_REFCOUNT_DECL(cfg_obj);
