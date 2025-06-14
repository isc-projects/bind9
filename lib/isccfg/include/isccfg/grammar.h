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

/*! \file isccfg/grammar.h */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/lex.h>
#include <isc/netaddr.h>
#include <isc/region.h>
#include <isc/sockaddr.h>
#include <isc/types.h>

#include <isccfg/cfg.h>
#include <isccfg/duration.h>

/*
 * Definitions shared between the configuration parser
 * and the grammars; not visible to users of the parser.
 */
enum {
	/*% A configuration option that was not configured at compile time. */
	CFG_CLAUSEFLAG_NOTCONFIGURED = 1 << 0,

	/*%
	 * A configuration option that *is* configured, but could be
	 * disabled at compile time in some builds.
	 */
	CFG_CLAUSEFLAG_OPTIONAL = 1 << 1,

	/*% Clause may occur multiple times (e.g., "zone") */
	CFG_CLAUSEFLAG_MULTI = 1 << 2,

	/*% Clause is obsolete (logs a warning, but is not a fatal error) */
	CFG_CLAUSEFLAG_OBSOLETE = 1 << 3,

	/*%
	 * Clause needs to be interpreted during parsing by calling a
	 * callback function, like the "directory" option.
	 */
	CFG_CLAUSEFLAG_CALLBACK = 1 << 4,

	/*% Clause that is only used in testing. */
	CFG_CLAUSEFLAG_TESTONLY = 1 << 5,

	/*% An option for an experimental feature. */
	CFG_CLAUSEFLAG_EXPERIMENTAL = 1 << 6,

	/*% An option that should be omited from the documentation */
	CFG_CLAUSEFLAG_NODOC = 1 << 7,

	/*% Clause will be obsolete in a future release (logs a warning) */
	CFG_CLAUSEFLAG_DEPRECATED = 1 << 8,

	/*% Clause has been obsolete so long that it's now a fatal error */
	CFG_CLAUSEFLAG_ANCIENT = 1 << 9,
};

/*%
 * Zone types for which a clause is valid:
 * These share space with CFG_CLAUSEFLAG values, but count
 * down from the most significant bit, instead of up from
 * the least.
 */
enum {
	CFG_ZONE_PRIMARY = 1 << 31,
	CFG_ZONE_SECONDARY = 1 << 30,
	CFG_ZONE_STUB = 1 << 29,
	CFG_ZONE_HINT = 1 << 28,
	CFG_ZONE_FORWARD = 1 << 27,
	CFG_ZONE_STATICSTUB = 1 << 26,
	CFG_ZONE_REDIRECT = 1 << 25,
	CFG_ZONE_INVIEW = 1 << 24,
	CFG_ZONE_MIRROR = 1 << 23,
};

typedef struct cfg_clausedef	 cfg_clausedef_t;
typedef struct cfg_tuplefielddef cfg_tuplefielddef_t;
typedef struct cfg_printer	 cfg_printer_t;
typedef ISC_LIST(cfg_listelt_t) cfg_list_t;
typedef struct cfg_map cfg_map_t;
typedef struct cfg_rep cfg_rep_t;

/*
 * Function types for configuration object methods
 */

typedef isc_result_t (*cfg_parsefunc_t)(cfg_parser_t *, const cfg_type_t *type,
					cfg_obj_t **);
typedef void (*cfg_printfunc_t)(cfg_printer_t *, const cfg_obj_t *);
typedef void (*cfg_docfunc_t)(cfg_printer_t *, const cfg_type_t *);
typedef void (*cfg_freefunc_t)(cfg_parser_t *, cfg_obj_t *);

/*
 * Structure definitions
 */

/*%
 * A configuration printer object.  This is an abstract
 * interface to a destination to which text can be printed
 * by calling the function 'f'.
 */
struct cfg_printer {
	void (*f)(void *closure, const char *text, int textlen);
	void *closure;
	int   indent;
	int   flags;
};

/*% A clause definition. */
struct cfg_clausedef {
	const char  *name;
	cfg_type_t  *type;
	unsigned int flags;
};

/*% A tuple field definition. */
struct cfg_tuplefielddef {
	const char  *name;
	cfg_type_t  *type;
	unsigned int flags;
};

/*% A configuration object type definition. */
struct cfg_type {
	const char     *name; /*%< For debugging purposes only */
	cfg_parsefunc_t parse;
	cfg_printfunc_t print;
	cfg_docfunc_t	doc; /*%< Print grammar description */
	cfg_rep_t      *rep; /*%< Data representation */
	const void     *of;  /*%< Additional data for meta-types */
};

/*% A keyword-type definition, for things like "port <integer>". */
typedef struct {
	const char	 *name;
	const cfg_type_t *type;
} keyword_type_t;

struct cfg_map {
	cfg_obj_t *id; /*%< Used for 'named maps' like
			* keys, zones, &c */
	const cfg_clausedef_t *const *clausesets; /*%< The clauses that
						   * can occur in this map;
						   * used for printing */
	isc_symtab_t *symtab;
};

typedef struct cfg_netprefix cfg_netprefix_t;

struct cfg_netprefix {
	isc_netaddr_t address; /* IP4/IP6 */
	unsigned int  prefixlen;
};

/*%
 * A configuration data representation.
 */
struct cfg_rep {
	const char    *name; /*%< For debugging only */
	cfg_freefunc_t free; /*%< How to free this kind of data. */
};

/*%
 * A configuration object.  This is the main building block
 * of the configuration parse tree.
 */

struct cfg_obj {
	const cfg_type_t *type;
	union {
		uint32_t	 uint32;
		uint64_t	 uint64;
		isc_textregion_t string; /*%< null terminated, too */
		bool		 boolean;
		cfg_map_t	 map;
		cfg_list_t	 list;
		cfg_obj_t      **tuple;
		isc_sockaddr_t	 sockaddr;
		struct {
			isc_sockaddr_t	 sockaddr;
			isc_textregion_t tls;
		} sockaddrtls;
		cfg_netprefix_t	  netprefix;
		isccfg_duration_t duration;
	} value;
	isc_refcount_t references; /*%< reference counter */
	const char    *file;
	unsigned int   line;
	cfg_parser_t  *pctx;
};

/*% A list element. */
struct cfg_listelt {
	cfg_obj_t *obj;
	ISC_LINK(cfg_listelt_t) link;
};

/*% The parser object. */
struct cfg_parser {
	isc_mem_t   *mctx;
	isc_lex_t   *lexer;
	unsigned int errors;
	unsigned int warnings;
	isc_token_t  token;

	/*% We are at the end of all input. */
	bool seen_eof;

	/*% The current token has been pushed back. */
	bool ungotten;

	/*%
	 * The stack of currently active files, represented
	 * as a configuration list of configuration strings.
	 * The head is the top-level file, subsequent elements
	 * (if any) are the nested include files, and the
	 * last element is the file currently being parsed.
	 */
	cfg_obj_t *open_files;

	/*%
	 * Names of files that we have parsed and closed
	 * and were previously on the open_file list.
	 * We keep these objects around after closing
	 * the files because the file names may still be
	 * referenced from other configuration objects
	 * for use in reporting semantic errors after
	 * parsing is complete.
	 */
	cfg_obj_t *closed_files;

	/*%
	 * Name of a buffer being parsed; used only for
	 * logging.
	 */
	char const *buf_name;

	/*%
	 * Current line number.  We maintain our own
	 * copy of this so that it is available even
	 * when a file has just been closed.
	 */
	unsigned int line;

	/*%
	 * Parser context flags, used for maintaining state
	 * from one token to the next.
	 */
	unsigned int flags;

	/*%< Reference counter */
	isc_refcount_t references;

	cfg_parsecallback_t callback;
	void		   *callbackarg;
};

/* Parser context flags */
#define CFG_PCTX_SKIP		(1 << 0)
#define CFG_PCTX_NODEPRECATED	(1 << 1)
#define CFG_PCTX_NOOBSOLETE	(1 << 2)
#define CFG_PCTX_NOEXPERIMENTAL (1 << 3)
#define CFG_PCTX_ALLCONFIGS	(1 << 4)

/*@{*/
/*%
 * Flags defining whether to accept certain types of network addresses.
 */
#define CFG_ADDR_V4OK	    0x00000001
#define CFG_ADDR_V4PREFIXOK 0x00000002
#define CFG_ADDR_V6OK	    0x00000004
#define CFG_ADDR_WILDOK	    0x00000008
#define CFG_ADDR_PORTOK	    0x00000010
#define CFG_ADDR_TLSOK	    0x00000020
#define CFG_ADDR_TRAILINGOK 0x00000040
#define CFG_ADDR_MASK	    (CFG_ADDR_V6OK | CFG_ADDR_V4OK)
/*@}*/

/*@{*/
/*%
 * Predefined data representation types.
 */
extern cfg_rep_t cfg_rep_uint32;
extern cfg_rep_t cfg_rep_uint64;
extern cfg_rep_t cfg_rep_string;
extern cfg_rep_t cfg_rep_boolean;
extern cfg_rep_t cfg_rep_map;
extern cfg_rep_t cfg_rep_list;
extern cfg_rep_t cfg_rep_tuple;
extern cfg_rep_t cfg_rep_sockaddr;
extern cfg_rep_t cfg_rep_sockaddrtls;
extern cfg_rep_t cfg_rep_netprefix;
extern cfg_rep_t cfg_rep_void;
extern cfg_rep_t cfg_rep_fixedpoint;
extern cfg_rep_t cfg_rep_percentage;
extern cfg_rep_t cfg_rep_duration;
/*@}*/

/*@{*/
/*%
 * Predefined configuration object types.
 */
extern cfg_type_t cfg_type_boolean;
extern cfg_type_t cfg_type_uint32;
extern cfg_type_t cfg_type_uint64;
extern cfg_type_t cfg_type_qstring;
extern cfg_type_t cfg_type_astring;
extern cfg_type_t cfg_type_ustring;
extern cfg_type_t cfg_type_sstring;
extern cfg_type_t cfg_type_bracketed_aml;
extern cfg_type_t cfg_type_bracketed_text;
extern cfg_type_t cfg_type_optional_bracketed_text;
extern cfg_type_t cfg_type_keyref;
extern cfg_type_t cfg_type_sockaddr;
extern cfg_type_t cfg_type_sockaddrtls;
extern cfg_type_t cfg_type_netaddr;
extern cfg_type_t cfg_type_netaddr4;
extern cfg_type_t cfg_type_netaddr4wild;
extern cfg_type_t cfg_type_netaddr6;
extern cfg_type_t cfg_type_netaddr6wild;
extern cfg_type_t cfg_type_netprefix;
extern cfg_type_t cfg_type_void;
extern cfg_type_t cfg_type_token;
extern cfg_type_t cfg_type_unsupported;
extern cfg_type_t cfg_type_fixedpoint;
extern cfg_type_t cfg_type_percentage;
extern cfg_type_t cfg_type_duration;
extern cfg_type_t cfg_type_duration_or_unlimited;
/*@}*/

isc_result_t
cfg_gettoken(cfg_parser_t *pctx, int options);

isc_result_t
cfg_peektoken(cfg_parser_t *pctx, int options);

void
cfg_ungettoken(cfg_parser_t *pctx);

#define CFG_LEXOPT_QSTRING (ISC_LEXOPT_QSTRING | ISC_LEXOPT_QSTRINGMULTILINE)

isc_result_t
cfg_create_obj(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **objp);

void
cfg_print_rawuint(cfg_printer_t *pctx, unsigned int u);

isc_result_t
cfg_parse_uint32(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_uint32(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_print_uint64(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_qstring(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_ustring(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_astring(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

isc_result_t
cfg_parse_sstring(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

isc_result_t
cfg_parse_rawaddr(cfg_parser_t *pctx, unsigned int flags, isc_netaddr_t *na);

void
cfg_print_rawaddr(cfg_printer_t *pctx, const isc_netaddr_t *na);

bool
cfg_lookingat_netaddr(cfg_parser_t *pctx, unsigned int flags);

isc_result_t
cfg_parse_rawport(cfg_parser_t *pctx, unsigned int flags, in_port_t *port);

isc_result_t
cfg_parse_sockaddr_generic(cfg_parser_t *pctx, cfg_type_t *klass,
			   const cfg_type_t *type, cfg_obj_t **ret);
isc_result_t
cfg_parse_sockaddr(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

isc_result_t
cfg_parse_sockaddrtls(cfg_parser_t *pctx, const cfg_type_t *type,
		      cfg_obj_t **ret);

isc_result_t
cfg_parse_boolean(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_sockaddr(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_print_boolean(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_sockaddr(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_parse_netprefix(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret);

isc_result_t
cfg_parse_special(cfg_parser_t *pctx, int special);
/*%< Parse a required special character 'special'. */

isc_result_t
cfg_create_tuple(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **objp);

isc_result_t
cfg_parse_tuple(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_tuple(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_tuple(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_create_list(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **objp);

isc_result_t
cfg_parse_listelt(cfg_parser_t *pctx, const cfg_type_t *elttype,
		  cfg_listelt_t **ret);

isc_result_t
cfg_parse_bracketed_list(cfg_parser_t *pctx, const cfg_type_t *type,
			 cfg_obj_t **ret);

void
cfg_print_bracketed_list(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_bracketed_list(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_parse_spacelist(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret);

void
cfg_print_spacelist(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_enum(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_doc_enum(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_parse_enum_or_other(cfg_parser_t *pctx, const cfg_type_t *enumtype,
			const cfg_type_t *othertype, cfg_obj_t **ret);

void
cfg_doc_enum_or_other(cfg_printer_t *pctx, const cfg_type_t *enumtype,
		      const cfg_type_t *othertype);

void
cfg_print_chars(cfg_printer_t *pctx, const char *text, int len);
/*%< Print 'len' characters at 'text' */

void
cfg_print_cstr(cfg_printer_t *pctx, const char *s);
/*%< Print the null-terminated string 's' */

isc_result_t
cfg_parse_map(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

isc_result_t
cfg_parse_named_map(cfg_parser_t *pctx, const cfg_type_t *type,
		    cfg_obj_t **ret);

isc_result_t
cfg_parse_addressed_map(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret);

isc_result_t
cfg_parse_netprefix_map(cfg_parser_t *pctx, const cfg_type_t *type,
			cfg_obj_t **ret);

void
cfg_print_map(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_map(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_parse_mapbody(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_mapbody(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_mapbody(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_parse_void(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_void(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_void(cfg_printer_t *pctx, const cfg_type_t *type);

isc_result_t
cfg_parse_fixedpoint(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret);

void
cfg_print_fixedpoint(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_percentage(cfg_parser_t *pctx, const cfg_type_t *type,
		     cfg_obj_t **ret);

void
cfg_print_percentage(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_duration(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_duration(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_duration_or_unlimited(cfg_parser_t *pctx, const cfg_type_t *type,
				cfg_obj_t **ret);

void
cfg_print_duration_or_unlimited(cfg_printer_t *pctx, const cfg_obj_t *obj);

isc_result_t
cfg_parse_obj(cfg_parser_t *pctx, const cfg_type_t *type, cfg_obj_t **ret);

void
cfg_print_obj(cfg_printer_t *pctx, const cfg_obj_t *obj);

void
cfg_doc_obj(cfg_printer_t *pctx, const cfg_type_t *type);
/*%<
 * Print a description of the grammar of an arbitrary configuration
 * type 'type'
 */

void
cfg_doc_terminal(cfg_printer_t *pctx, const cfg_type_t *type);
/*%<
 * Document the type 'type' as a terminal by printing its
 * name in angle brackets, e.g., &lt;uint32>.
 */

void
cfg_parser_error(cfg_parser_t *pctx, unsigned int flags, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);
/*!
 * Pass one of these flags to cfg_parser_error() to include the
 * token text in log message.
 */
#define CFG_LOG_NEAR   0x00000001 /*%< Say "near <token>" */
#define CFG_LOG_BEFORE 0x00000002 /*%< Say "before <token>" */
#define CFG_LOG_NOPREP 0x00000004 /*%< Say just "<token>" */

void
cfg_parser_warning(cfg_parser_t *pctx, unsigned int flags, const char *fmt, ...)
	ISC_FORMAT_PRINTF(3, 4);

bool
cfg_is_enum(const char *s, const char *const *enums);
/*%< Return true iff the string 's' is one of the strings in 'enums' */

bool
cfg_clause_validforzone(const char *name, unsigned int ztype);
/*%<
 * Check whether an option is legal for the specified zone type.
 */

void
cfg_print_zonegrammar(const unsigned int zonetype, unsigned int flags,
		      void (*f)(void *closure, const char *text, int textlen),
		      void *closure);
/*%<
 * Print a summary of the grammar of the zone type represented by
 * 'zonetype'.
 */

void
cfg_print_clauseflags(cfg_printer_t *pctx, unsigned int flags);
/*%<
 * Print clause flags (e.g. "obsolete", "not implemented", etc) in
 * human readable form
 */

void
cfg_print_indent(cfg_printer_t *pctx);
/*%<
 * Print the necessary indent required by the current settings of 'pctx'.
 */
