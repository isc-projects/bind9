/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
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

/* $Id: confcommon.h,v 1.31.4.1.10.1 2003/09/17 07:19:50 tale Exp $ */

#ifndef DNS_CONFCOMMON_H
#define DNS_CONFCOMMON_H 1

/*****
 ***** Module Info
 *****/

/*
 * Various declarations of types and functions that are used by multiple
 * headers in the config file module (put here to avoid circular include
 * dependencies).
 *
 * Also some memory debugging aids that should eventually get moved to
 * isc/mem.h or removed.
 */

/*
 * MP:
 *
 *	N/A
 *
 * Reliability:
 *
 * 	No problems known.
 *
 * Resources:
 *
 *	N/A
 *
 * Security:
 *
 *	N/A
 */

/***
 *** Imports
 ***/

#include <stdio.h>

#include <isc/lang.h>

#include <dns/types.h>

/*
 * Constants used in the defintions of default logging channels and
 * categories.
 */
#define DNS_C_DEFAULT_SYSLOG "default_syslog"
#define DNS_C_DEFAULT_DEBUG "default_debug"
#define DNS_C_DEFAULT_DEBUG_PATH "named.run"
#define DNS_C_NULL "null"
#define DNS_C_DEFAULT_STDERR  "default_stderr"
#define DNS_C_STDERR_PATH " <stderr> "	/* not really a path */

/*
 * The value we use in config files if the user doesn't specify the port or
 * in some statements.
 */
#define DNS_C_DEFAULTPORT	53	/* XXX this should be imported */

/*
 * What an 'unlimited' value for a size_spec is stored as internally.
 */
#define DNS_C_SIZE_SPEC_UNLIM (~((isc_uint32_t) 0x0))

/*
 * What a 'default' value for a size_spec is stored as internally.
 */
#define DNS_C_SIZE_SPEC_DEFAULT (DNS_C_SIZE_SPEC_UNLIM - 1)

/*
 * What 'unlimited' is stored as internally for logging file versions
 */
#define DNS_C_UNLIM_VERSIONS	DNS_C_SIZE_SPEC_UNLIM

/*
 * The default ordering given to rrset-order statements when the type given
 * is illegal (so parsing can continue).
 */
#define DNS_DEFAULT_ORDERING 	dns_c_ordering_fixed

/***
 *** Types
 ***/

/* Value of a 'forward' statement */
typedef enum {
	dns_c_forw_only,
	dns_c_forw_first,
	dns_c_forw_noanswer,
	dns_c_forw_nodomain
} dns_c_forw_t;

/* Value of a 'check-names' type. */
typedef enum {
	dns_trans_primary,
	dns_trans_secondary,
	dns_trans_response
} dns_c_trans_t;
#define DNS_C_TRANSCOUNT 3	  /* number of items in dns_c_trans_t enum */


/* The tag values for the different types of control channels */
typedef enum {
	dns_c_inet_control,
	dns_c_unix_control
} dns_c_control_t;


/* The possible rrset-order ordering values. */
typedef enum {
	dns_c_ordering_fixed,
	dns_c_ordering_random,
	dns_c_ordering_cyclic
} dns_c_ordering_t;


/* Possible zone types */
typedef enum {
	dns_c_zone_master,
	dns_c_zone_slave,
	dns_c_zone_hint,
	dns_c_zone_stub,
	dns_c_zone_forward,
	dns_c_zone_delegationonly
} dns_c_zonetype_t;


/* Possible address-match-element types */
typedef enum {
	dns_c_ipmatch_pattern,
	dns_c_ipmatch_indirect,
	dns_c_ipmatch_localhost,
	dns_c_ipmatch_localnets,
	dns_c_ipmatch_key,
	dns_c_ipmatch_acl,
	dns_c_ipmatch_any,
	dns_c_ipmatch_none
} dns_c_ipmatch_type_t;


/* Tag values for the different types of log channel */
typedef enum {
	dns_c_logchan_file,
	dns_c_logchan_syslog,
	dns_c_logchan_null,
        dns_c_logchan_stderr
} dns_c_logchantype_t;


/* Possible logging severity values */
typedef enum {
	dns_c_log_critical,
	dns_c_log_error,
	dns_c_log_warn,
	dns_c_log_notice,
	dns_c_log_info,
	dns_c_log_debug,
	dns_c_log_dynamic,
	dns_c_log_no_severity
} dns_c_logseverity_t;


/* Type of additional-data field */
typedef enum {
	dns_c_ad_minimal,
	dns_c_ad_maximal,
	dns_c_ad_internal
} dns_c_addata_t;


/* Type of the bit sets used in various structures. Macros in confpvt.h
 * depending on this being an integer type, and some structures need more
 * than 32 bits.
 */
typedef isc_int64_t	dns_c_setbits_t;

typedef isc_sockaddr_t dns_c_addr_t;


typedef struct dns_c_view		dns_c_view_t;
typedef struct dns_c_zone_list		dns_c_zonelist_t;


/*
 * Set this variable to a true value to get output by the wrapper
 * functions (if the memory debugging hack is compiled in--it isn't by
 * default
 */

extern isc_boolean_t debug_mem_print;
extern FILE *debug_mem_print_stream;	/* NULL means stderr */

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

/* The following dns_c_xxx2string() functions convert the first argument into
 * a string value and returns that value. If the first argument is not a
 * legal value, then NULL is returned, unless PRINTABLE is true, in which
 * case an ugly, but safe-to-pass-to-printf string is returned.
 *
 * e.g. dns_c_ordering2string(dns_c_ordering_cyclic,ISC_FALSE) returns the
 * string "cyclic", but
 * dns_c_ordering2string((dns_c_ordering_t)0xffff,ISC_TRUE) returns the
 * value "UNKNOWN_ORDERING"
 */
const char *
dns_c_ordering2string(dns_c_ordering_t ordering, isc_boolean_t printable);

const char *
dns_c_logseverity2string(dns_c_logseverity_t level, isc_boolean_t printable);

const char *
dns_c_facility2string(int facility, isc_boolean_t printable);

const char *
dns_c_transformat2string(dns_transfer_format_t tform, isc_boolean_t printable);

const char *
dns_c_transport2string(dns_c_trans_t transport, isc_boolean_t printable);

const char *
dns_c_nameseverity2string(dns_severity_t severity, isc_boolean_t printable);

const char *
dns_c_forward2string(dns_c_forw_t forw, isc_boolean_t printable);

const char *
dns_c_addata2string(dns_c_addata_t addata, isc_boolean_t printable);

/*
 * The following dns_c_string2xxx() functions will look up the string
 * argument in a table of values and will return the appropriate enum/integer
 * through the second argument and ISC_R_SUCCESS is returned. If the string
 * doesn't match a valid value then ISC_R_FAILURE is returned.
 */
isc_result_t
dns_c_string2ordering(char *name, dns_c_ordering_t *ordering);

isc_result_t
dns_c_string2logseverity(const char *string, dns_c_logseverity_t *result);

isc_result_t
dns_c_string2facility(const char *string, int *res);

int
dns_c_isanyaddr(isc_sockaddr_t *inaddr);

void
dns_c_print_ipaddr(FILE *fp, isc_sockaddr_t *addr);

isc_boolean_t
dns_c_need_quote(const char *string);

void
dns_c_printtabs(FILE *fp, int count);

void
dns_c_printinunits(FILE *fp, isc_uint32_t val);

void
dns_c_dataclass_tostream(FILE *fp, dns_rdataclass_t rclass);

void
dns_c_datatype_tostream(FILE *fp, dns_rdatatype_t rtype);

isc_boolean_t
dns_c_netaddrisanyaddr(isc_netaddr_t *inaddr);

void
dns_c_netaddrprint(FILE *fp, isc_netaddr_t *inaddr);

isc_result_t
dns_c_charptoname(isc_mem_t *mem, const char *keyval, dns_name_t **name);

void
dns_c_peer_print(FILE *fp, int indent, dns_peer_t *peer);

void
dns_c_peerlist_print(FILE *fp, int indent, dns_peerlist_t *peers);

isc_result_t
dns_c_nameprint(dns_name_t *name, FILE *stream);

void
dns_c_ssutable_print(FILE *fp, int indent, dns_ssutable_t *ssutable);

isc_result_t
dns_c_checkcategory(const char *name);

isc_result_t
dns_c_checkmodule(const char *name);
/*
 * Checks the argument is a known category or module name.
 *
 * Returns:
 *	ISC_R_SUCCESS if the category is known.
 *	ISC_R_FAILURE if it isn't.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_CONFCOMMON_H */
