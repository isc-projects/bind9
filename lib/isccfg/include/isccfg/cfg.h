/*
 * Copyright (C) 2000, 2001 Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: cfg.h,v 1.3 2001/02/15 18:53:03 gson Exp $ */

#ifndef DNS_CFG_H
#define DNS_CFG_H 1

/*****
 ***** Module Info
 *****/

/*
 * This is the new, table-driven, YACC-free configuration file parser.
 */


/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/types.h>
#include <isc/list.h>


/***
 *** Types
 ***/

typedef struct cfg_parser cfg_parser_t;
/*
 * A configuration parser.
 */

/*
 * A configuration type definition object.  There is a single
 * static cfg_type_t object for each data type supported by
 * the configuration parser.
 */
typedef struct cfg_type cfg_type_t;

/*
 * A configuration object.  This is the basic building block of the
 * configuration parse tree.  It contains a value (which may be
 * of one of several types) and information identifying the file
 * and line number the value came from, for printing error
 * messages.
 */
typedef struct cfg_obj cfg_obj_t;

/*
 * A configuration object list element.
 */
typedef struct cfg_listelt cfg_listelt_t;

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
cfg_parser_create(isc_mem_t *mctx, isc_log_t *lctx, cfg_parser_t **ret);
/*
 * Create a configuration file parser.  Any warning and error
 * messages will be logged to 'lctx'.
 */

isc_result_t
cfg_parse_file(cfg_parser_t *pctx, char *filename,
	       cfg_type_t *type, cfg_obj_t **ret);
/*
 * Read in a configuration file containing data of type 'type'
 * and make '*ret' point to its parse tree.
 * Returns an error if the file does not parse correctly.
 * 
 * Requires:
 *      "filename" is valid.
 *      "mem" is valid.
 *	"type" is valid.
 *      "cfg" is non-NULL and "*cfg" is NULL.
 *
 * Returns:
 *      ISC_R_SUCCESS                 - success
 *      ISC_R_NOMEMORY                - no memory available
 *      ISC_R_INVALIDFILE             - file doesn't exist or is unreadable
 *      others	                      - file contains errors
 */

void
cfg_parser_destroy(cfg_parser_t **pctxp);
/*
 * Destroy a configuration parser.
 */

isc_result_t
cfg_map_get(cfg_obj_t *mapobj, const char* name, cfg_obj_t **obj);
/*
 * Extract an element from a configuration object, which
 * must be of a map type.
 *
 * Requires:
 *      'mapobj' ponts to a valid configuraration object of a map type.
 *      'name' points to a null-terminated string.
 * 	'obj' is non-NULL and '*obj' is NULL.
 *
 * Returns:
 *      ISC_R_SUCCESS                  - success
 *      ISC_R_NOTFOUND                 - name not found in map
 */

cfg_obj_t *
cfg_map_getname(cfg_obj_t *mapobj);
/*
 * Get the name of a named map object, like a server "key" clause.
 *
 * Requires:
 *      'mapobj' ponts to a valid configuraration object of a map type.
 *
 * Returns:
 *      A pointer to a configuration object naming the map object,
 *	or NULL if the map object does not have a name.
 */

isc_uint32_t
cfg_obj_asuint32(cfg_obj_t *obj);
/*
 * Returns the value of a configuration object of integer type.
 *
 * Requires:
 *      'obj' points to a valid configuration object of integer type.
 *
 * Returns:
 *      A 32-bit unsigned integer.
 */

char *
cfg_obj_asstring(cfg_obj_t *obj);
/*
 * Returns the value of a configuration object of a string type
 * as a null-terminated string.
 *
 * Requires:
 *      'obj' points to a valid configuration object of a string type.
 *
 * Returns:
 *      A pointer to a null terminated string.
 */

cfg_listelt_t *
cfg_list_first(cfg_obj_t *obj);
/*
 * Returns the first list element in a configuration object of a list type.
 *
 * Requires:
 *      'obj' points to a valid configuration object of a list type.
 *
 * Returns:
 *      A pointer to a cfg_listelt_t representing the first list element,
 * 	or NULL if the list is empty.
 */

cfg_listelt_t *
cfg_list_next(cfg_listelt_t *elt);
/*
 * Returns the next element of a list of configuration objects.
 *
 * Requires:
 *      'elt' points to cfg_listelt_t obtained from cfg_list_first() or
 *	a previous call to cfg_list_next().
 *
 * Returns:
 *      A pointer to a cfg_listelt_t representing the next element,
 * 	or NULL if there are no more elements.
 */

cfg_obj_t *
cfg_listelt_value(cfg_listelt_t *elt);
/*
 * Returns the configuration object associated with cfg_listelt_t.
 *
 * Requires:
 *      'elt' points to cfg_listelt_t obtained from cfg_list_first() or
 *	cfg_list_next().
 *
 * Returns:
 *      A non-NULL pointer to a configuration object.
 */

void
cfg_print(cfg_obj_t *obj,
	  void (*f)(void *closure, const char *text, int textlen),
	  void *closure);
/*
 * Print the configuration object 'obj' by repeatedly calling the
 * function 'f', passing 'closure' and a region of text starting
 * at 'text' and comprising 'textlen' characters.
 */

void cfg_obj_destroy(cfg_parser_t *pctx, cfg_obj_t **obj);
/*
 * Destroy a configuration object.
 */

/*
 * Configuration object types.
 */
extern cfg_type_t cfg_type_namedconf; /* A complete named.conf file. */
extern cfg_type_t cfg_type_rndcconf; /* A complete rndc.conf file. */

ISC_LANG_ENDDECLS

#endif /* DNS_CFG_H */
