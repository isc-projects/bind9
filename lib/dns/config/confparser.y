%{
/*
 * Copyright (c) 1996-2000 by Internet Software Consortium.
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

/* $Id: confparser.y,v 1.54 2000/03/23 19:35:14 halley Exp $ */

#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h> 
#include <limits.h>
#include <string.h>
#include <sys/types.h> 

#include <syslog.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mutex.h>
#include <isc/lex.h>
#include <isc/symtab.h>
#include <isc/error.h>
#include <isc/once.h>
#include <isc/dir.h>
#include <isc/net.h>

#include <dns/confparser.h>
#include <dns/confctx.h>
#include <dns/log.h>
#include <dns/name.h> 
 
#include <dns/result.h>
#include <dns/rdatatype.h>
#include <dns/rdataclass.h>
#include <dns/ssu.h> 

#include <dns/types.h>

#include <dns/confcommon.h>


/* Type keys for symtab lookup */
#define KEYWORD_SYM_TYPE 0x1
#define CLASS_SYM_TYPE 0x2
#define ACL_SYM_TYPE 0x3

 
static isc_mutex_t yacc_mutex;

/* used for holding a list of dns_rdatatype_t on the stack */
struct confrdtype_s {
	dns_rdatatype_t types[256];
	isc_uint32_t idx;
};
 
/* used for holding ssu data on the stack */
struct confssu_s {
	isc_boolean_t grant;
	dns_name_t *ident;
	unsigned int matchtype;
	dns_name_t *name;
	struct confrdtype_s rdatatypes;
};


/* All these statics are protected by the above yacc_mutex */
static dns_c_ctx_t	       *currcfg;
static isc_mem_t	       *memctx; /* used for internal allocations */
static isc_lex_t	       *mylexer;
static isc_symtab_t	       *keywords;
static dns_c_cbks_t	       *callbacks;
static isc_lexspecials_t	specials;

#define CONF_MAX_IDENT 1024

/* This should be sufficient to permit multiple parsers and lexers if needed */
#define yyparse dns_yyparse

#define YYDEBUG 1 

static isc_result_t	tmpres;
static int		debug_lexer;
 
static int		yylex(void);
static int		yyparse(void);
static void             parser_error(isc_boolean_t lasttoken,
                                     const char *fmt, ...);
static void             parser_warning(isc_boolean_t lasttoken,
                                       const char *fmt, ...);
static void             parser_complain(isc_boolean_t is_warning,
                                        isc_boolean_t last_token,
                                        const char *format, va_list args);
static isc_boolean_t    unit_to_uint32(char *in, isc_uint32_t *out);
static char *		token_to_keyword(int token);
static void             yyerror(const char *);

/* returns true if (base * mult) would be too big.*/
static isc_boolean_t	int_too_big(isc_uint32_t base, isc_uint32_t mult);
 
%}

%union {
	char		       *text;
	int			number;
	isc_int32_t		l_int;
	isc_uint32_t		ul_int;
	isc_uint16_t		port_int;
	dns_c_zonetype_t	ztype;
	struct in_addr		ip4_addr;
	struct in6_addr		ip6_addr;
	isc_sockaddr_t		ipaddress;

	struct confssu_s	ssu;
	struct confrdtype_s	rdatatypelist;
	dns_rdatatype_t		rdatatype;
	
	isc_boolean_t		boolean;
	dns_rdataclass_t	rrclass;
	dns_severity_t	      	severity;
	dns_c_trans_t		transport;
	dns_transfer_format_t	tformat;
	
	dns_c_ipmatchelement_t	*ime;
	dns_c_ipmatchlist_t	*iml;

	dns_c_forw_t		forward;
	dns_c_rrso_t	       *rrorder;
	dns_c_rrsolist_t      *rrolist;
	dns_rdatatype_t		ordertype;
	dns_rdataclass_t	orderclass;
	dns_c_ordering_t	ordering;
	dns_c_iplist_t	       *iplist;
}

/* Misc */
%token <text>		L_STRING
%token <text>		L_QSTRING
%token <l_int>		L_INTEGER
%token <ip4_addr>	L_IP4ADDR
%token <ip6_addr>	L_IP6ADDR

%token		L_LBRACE
%token		L_RBRACE
%token		L_EOS
%token		L_SLASH
%token		L_BANG
%token		L_QUOTE

%token		L_MASTER
%token		L_SLAVE
%token		L_SORTLIST
%token		L_HINT
%token		L_STUB
%token		L_FORWARD

%token		L_INCLUDE
%token		L_END_INCLUDE

%token		L_OPTIONS
%token		L_DIRECTORY
%token		L_PIDFILE
%token		L_NAMED_XFER
%token		L_TKEY_DOMAIN
%token		L_TKEY_DHKEY
%token		L_DUMP_FILE
%token		L_STATS_FILE
%token		L_MEMSTATS_FILE
%token		L_FAKE_IQUERY
%token		L_RECURSION
%token		L_FETCH_GLUE
%token		L_QUERY_SOURCE
%token		L_QUERY_SOURCE_V6
%token		L_LISTEN_ON
%token		L_PORT
%token		L_ACL
%token		L_ADDRESS
%token		L_ALGID
%token		L_ALLOW_QUERY
%token		L_ALLOW_TRANSFER
%token		L_ALLOW_UPDATE
%token		L_ALLOW_UPDATE_FORWARDING
%token		L_ALLOW_RECURSION
%token		L_ALSO_NOTIFY
%token		L_BLACKHOLE
%token		L_BOGUS
%token		L_CATEGORY
%token		L_CHANNEL
%token		L_CHECK_NAMES
%token		L_DEBUG
%token		L_DIALUP
%token		L_DYNAMIC
%token		L_FAIL
%token		L_FIRST
%token		L_FORWARDERS
%token		L_IF_NO_ANSWER
%token		L_IF_NO_DOMAIN
%token		L_IGNORE
%token		L_FILE_IXFR
%token		L_IXFR_TMP
%token		L_SEC_KEY
%token		L_KEYS
%token		L_LOGGING
%token		L_MASTERS
%token		L_NULL_OUTPUT
%token		L_ONLY
%token		L_PRINT_CATEGORY
%token		L_PRINT_SEVERITY
%token		L_PRINT_TIME
%token		L_PUBKEY
%token		L_RESPONSE
%token		L_SECRET
%token		L_SERVER
%token		L_SEVERITY
%token		L_SIZE
%token		L_SUPPORT_IXFR
%token		L_SYSLOG
%token		L_TOPOLOGY
%token		L_TRANSFER_SOURCE
%token		L_TRANSFER_SOURCE_V6
%token		L_TRANSFERS
%token		L_TRUSTED_KEYS
%token		L_VERSIONS
%token		L_WARN
%token		L_RRSET_ORDER
%token		L_ORDER
%token		L_NAME
%token		L_CLASS
%token		L_CONTROLS
%token		L_INET
%token		L_UNIX
%token		L_PERM
%token		L_OWNER
%token		L_GROUP
%token		L_ALLOW
%token		L_DATASIZE
%token		L_STACKSIZE
%token		L_CORESIZE
%token		L_DEFAULT
%token		L_UNLIMITED
%token		L_FILES
%token		L_VERSION
%token		L_HOSTSTATS
%token		L_DEALLOC_ON_EXIT
%token		L_TRANSFERS_IN
%token		L_TRANSFERS_OUT
%token		L_TRANSFERS_PER_NS
%token		L_TRANSFER_FORMAT
%token		L_MAX_TRANSFER_TIME_IN
%token		L_MAX_TRANSFER_TIME_OUT
%token		L_MAX_TRANSFER_IDLE_IN
%token		L_MAX_TRANSFER_IDLE_OUT
%token		L_TCP_CLIENTS
%token		L_RECURSIVE_CLIENTS
%token		L_ONE_ANSWER
%token		L_MANY_ANSWERS
%token		L_NOTIFY
%token		L_AUTH_NXDOMAIN
%token		L_MULTIPLE_CNAMES
%token		L_USE_IXFR
%token		L_MAINTAIN_IXFR_BASE
%token		L_CLEAN_INTERVAL
%token		L_INTERFACE_INTERVAL
%token		L_STATS_INTERVAL
%token		L_MAX_LOG_SIZE_IXFR
%token		L_HEARTBEAT
%token		L_USE_ID_POOL
%token		L_MAX_NCACHE_TTL
%token		L_HAS_OLD_CLIENTS
%token		L_EXPERT_MODE
%token		L_ZONE
%token		L_TYPE
%token		L_FILE
%token		L_YES
%token		L_TRUE
%token		L_NO
%token		L_FALSE
%token		L_VIEW
%token		L_RFC2308_TYPE1
%token		L_PROVIDE_IXFR
%token		L_REQUEST_IXFR

%token		L_GRANT
%token		L_DENY
%token		L_SUBDOMAIN
%token		L_DOMAIN
%token		L_SELF
%token		L_WILDCARD

%type <ssu>		grant_stmt
%type <ul_int>		grant_match_type
%type <rdatatypelist>	rdatatype_list
%type <rdatatype>	rdatatype
%type <boolean>		grantp
%type <boolean>		yea_or_nay

%type <forward>		forward_opt
%type <forward>		zone_forward_opt

%type <ime>		address_match_element
%type <ime>		address_match_simple
%type <ime>		address_name

%type <iml>		address_match_list

%type <ipaddress>	in_addr_elem
%type <ipaddress>	ip4_address
%type <ipaddress>	ip6_address
%type <ipaddress>	ip_address
%type <ipaddress>	maybe_wild_addr 
%type <ipaddress>	maybe_wild_ip4_only_addr 
%type <ipaddress>	maybe_wild_ip6_only_addr
%type <ipaddress>	query_source_v6
%type <ipaddress>	query_source_v4

%type <iplist>		in_addr_list
%type <iplist>		master_in_addr_list
%type <iplist>		notify_in_addr_list
%type <iplist>		opt_in_addr_list
%type <iplist>		opt_zone_forwarders_list

%type <text>		category_name

%type <number>		facility_name
%type <number>		maybe_syslog_facility

%type <orderclass>	ordering_class

%type <ordertype>	ordering_type

%type <port_int>	in_port
%type <port_int>	maybe_port
%type <port_int>	maybe_wild_port
%type <port_int>	maybe_zero_port

%type <rrclass>		class_name
%type <rrclass>		optional_class

%type <severity>	check_names_opt;

/* %type <text>		optional_string */
%type <text>		algorithm_id
%type <text>		any_string
%type <text>		channel_name
%type <text>		domain_name
%type <text>		ordering_name
%type <text>		secret
%type <text>		key_value

%type <tformat>		transfer_format

%type <transport>	check_names_type;

%type <ul_int>		size_spec

%type <ztype>		zone_type

/* Miscellaneous items (used in several places): */

%%

config_file: statement_list
	;

statement_list: statement
	| statement_list statement
	;

statement: include_stmt L_EOS
	| options_stmt L_EOS
	| controls_stmt L_EOS
	| logging_stmt L_EOS
	| server_stmt L_EOS
	| zone_stmt L_EOS
	| trusted_keys_stmt L_EOS
	| acl_stmt L_EOS
	| key_stmt L_EOS
	| view_stmt L_EOS
	| L_END_INCLUDE
	;


include_stmt: L_INCLUDE L_QSTRING
	{
		if (isc_lex_openfile(mylexer, $2) != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE ,"can't open file %s", $2);
			YYABORT;
		}

		isc_mem_free(memctx, $2);
	}
	;

options_stmt: L_OPTIONS
	{
		dns_c_options_t *options;

		tmpres = dns_c_ctx_getoptions(currcfg, &options);
		if (tmpres == ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "cannot redefine options");

			/*
			 * Clean out options so rest of config won't fail
			 * or issue extra error messages
			 */
			dns_c_ctx_optionsdelete(&currcfg->options);
		}

		tmpres = dns_c_ctx_optionsnew(currcfg->mem, &currcfg->options);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create options structure: %s",
				     isc_result_totext(tmpres));
			YYABORT;
		}
		
	} L_LBRACE options L_RBRACE {
		if (callbacks != NULL && callbacks->optscbk != NULL) {
			tmpres = callbacks->optscbk(currcfg,
						    callbacks->optscbkuap);
			if (tmpres != ISC_R_SUCCESS) {
				isc_log_write(dns_lctx,
					      DNS_LOGCATEGORY_CONFIG,
					      DNS_LOGMODULE_CONFIG,
					      ISC_LOG_ERROR,
				      "options configuration failed: %s",
					      isc_result_totext(tmpres));
				YYABORT;
			}
		}
	}
	;

options: option L_EOS
	| options option L_EOS
	;


option: /* Empty */
	| L_VERSION L_QSTRING
	{
		tmpres = dns_c_ctx_setversion(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining version.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "set version error %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_DIRECTORY L_QSTRING
	{
		tmpres = dns_c_ctx_setdirectory(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining directory");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting directory: %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_NAMED_XFER L_QSTRING
	{
		tmpres = dns_c_ctx_setnamedxfer(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining named-xfer");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set named-xfer error: %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_TKEY_DOMAIN L_QSTRING
	{
		tmpres = dns_c_ctx_settkeydomain(currcfg, $2);
		
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining tkey-domain");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "set tkey-domain error: %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_TKEY_DHKEY L_QSTRING L_INTEGER
	{
		tmpres = dns_c_ctx_settkeydhkey(currcfg, $2, $3);
		
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining tkey-dhkey");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set tkey-dhkey error: %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_PIDFILE L_QSTRING
	{
		tmpres = dns_c_ctx_setpidfilename(currcfg, $2);
		
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining pid-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set pidfile error %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_STATS_FILE L_QSTRING
	{
		tmpres = dns_c_ctx_setstatsfilename(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining statistics-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set statsfile error %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_MEMSTATS_FILE L_QSTRING
	{
		tmpres = dns_c_ctx_setmemstatsfilename(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining memstatistics-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "set memstatsfile error %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_DUMP_FILE L_QSTRING
	{
		tmpres = dns_c_ctx_setdumpfilename(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining dump-file");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "set dumpfile error %s: %s",
				     isc_result_totext(tmpres), $2);
			YYABORT;
		}
		
		isc_mem_free(memctx, $2);
	}
	| L_EXPERT_MODE yea_or_nay
	{
		tmpres = dns_c_ctx_setexpertmode(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining expert-mode.");
		}
	}
	| L_FAKE_IQUERY yea_or_nay
	{
		tmpres = dns_c_ctx_setfakeiquery(currcfg, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining fake-iquery.");
		}
	}
	| L_RECURSION yea_or_nay
	{
		tmpres = dns_c_ctx_setrecursion(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining recursion");
		}
	}
	| L_FETCH_GLUE yea_or_nay
	{
		tmpres = dns_c_ctx_setfetchglue(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining fetch-glue.");
		}
	}
	| L_NOTIFY yea_or_nay
	{
		tmpres = dns_c_ctx_setnotify(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining notify.");
		}
	}
	| L_HOSTSTATS yea_or_nay
	{
		tmpres = dns_c_ctx_sethoststatistics(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining host-statistics.");
		}
	}
	| L_DEALLOC_ON_EXIT yea_or_nay
	{
		tmpres = dns_c_ctx_setdealloconexit(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining deallocate-on-exit.");
		}
	}
	| L_USE_IXFR yea_or_nay
	{
		tmpres = dns_c_ctx_setuseixfr(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining use-ixfr.");
		}
	}
	| L_MAINTAIN_IXFR_BASE yea_or_nay
	{
		/*
		 * Backwards compatibility, treated as
		 * equivalent to provide-ixfr.
		 */
		tmpres = dns_c_ctx_setprovideixfr(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining provide-ixfr.");
		}
	}
	| L_HAS_OLD_CLIENTS yea_or_nay
	{
		tmpres = dns_c_ctx_sethasoldclients(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining has-old-clients.");
		}
	}
	| L_AUTH_NXDOMAIN yea_or_nay
	{
		tmpres = dns_c_ctx_setauthnxdomain(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining auth-nxdomain.");
		}
	}
	| L_MULTIPLE_CNAMES yea_or_nay
	{
		tmpres = dns_c_ctx_setmultiplecnames(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining multiple-cnames.");
		}
	}
	| L_CHECK_NAMES check_names_type check_names_opt
	{
		tmpres = dns_c_ctx_setchecknames(currcfg, $2, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining check-names.");
		}
	}
	| L_USE_ID_POOL yea_or_nay
	{
		tmpres = dns_c_ctx_setuseidpool(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining use-id-pool.");
		}
	}
	| L_RFC2308_TYPE1 yea_or_nay
	{
		tmpres = dns_c_ctx_setrfc2308type1(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining rfc2308-type.");
		}
	}
	| L_PROVIDE_IXFR yea_or_nay
	{
		tmpres = dns_c_ctx_setprovideixfr(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining provide-ixfr.");
		}
	}
	| L_REQUEST_IXFR yea_or_nay
	{
		tmpres = dns_c_ctx_setrequestixfr(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining request-ixfr.");
		}
	}
	| L_LISTEN_ON maybe_port L_LBRACE address_match_list L_RBRACE
	{
		if ($4 == NULL) {
			parser_warning(ISC_FALSE,
				       "address-match-list empty. "
				       "listen statement ignored.");
		} else {
			tmpres = dns_c_ctx_addlisten_on(currcfg, $2, $4,
							ISC_FALSE);

			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to add listen statement");
				YYABORT;
			}
		}
	}
	| L_FORWARD forward_opt
	{
		tmpres = dns_c_ctx_setforward(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining forward");
		}
	}
	| L_FORWARDERS {
		dns_c_iplist_t *forwarders;

		tmpres = dns_c_ctx_getforwarders(currcfg, &forwarders);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				     "redefining options forwarders");
			dns_c_iplist_detach(&forwarders);
		} 

		tmpres = dns_c_iplist_new(currcfg->mem, 5, &forwarders);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create "
				     "forwarders list");
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setforwarders(currcfg, ISC_FALSE,
						 forwarders);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set forwarders list.");
			YYABORT;
		}
	} L_LBRACE opt_forwarders_list L_RBRACE
	| L_QUERY_SOURCE query_source_v4
	{
		tmpres = dns_c_ctx_setquerysource(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining query-source.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set query-source.");
			YYABORT;
		}
	}
	| L_QUERY_SOURCE_V6 query_source_v6
	{
		tmpres = dns_c_ctx_setquerysourcev6(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining query-source-v6.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set query-source-v6.");
			YYABORT;
		}
	}
	| L_TRANSFER_SOURCE maybe_wild_ip4_only_addr
	{
		tmpres = dns_c_ctx_settransfersource(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining transfer-source");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set transfer-source");
			YYABORT;
		}
	}
	| L_TRANSFER_SOURCE_V6 maybe_wild_ip6_only_addr
	{
		tmpres = dns_c_ctx_settransfersourcev6(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining transfer-source-v6");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set transfer-source-v6");
			YYABORT;
		}
	}
	| L_ALLOW_QUERY L_LBRACE address_match_list L_RBRACE
	{
		if ($3 == NULL)
			YYABORT;
		tmpres = dns_c_ctx_setqueryacl(currcfg, ISC_FALSE, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining allow-query list");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set allow-query");
			YYABORT;
		}
	}
	| L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE
	{
		tmpres = dns_c_ctx_settransferacl(currcfg, ISC_FALSE, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining allow-transfer list");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set allow-transfer");
			YYABORT;
		}
	}
	| L_ALLOW_RECURSION L_LBRACE address_match_list L_RBRACE
	{
		tmpres = dns_c_ctx_setrecursionacl(currcfg, ISC_FALSE, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining allow-recursion list");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set allow-recursion");
			YYABORT;
		}
	}
	| L_SORTLIST  L_LBRACE address_match_list L_RBRACE
	{
		tmpres = dns_c_ctx_setsortlist(currcfg, ISC_FALSE, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining sortlist.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set sortlist");
			YYABORT;
		}
	}
	| L_ALSO_NOTIFY L_LBRACE notify_in_addr_list L_RBRACE
	{
		tmpres = dns_c_ctx_setalsonotify(currcfg, $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining also-notify.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set also-notify");
			YYABORT;
		}
	}
	| L_BLACKHOLE L_LBRACE address_match_list L_RBRACE
	{
		tmpres = dns_c_ctx_setblackhole(currcfg, ISC_FALSE, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining blackhole.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set blackhole");
			YYABORT;
		}
	}
	| L_TOPOLOGY L_LBRACE address_match_list L_RBRACE
	{
		tmpres = dns_c_ctx_settopology(currcfg, ISC_FALSE, $3);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining topology.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set topology.");
			YYABORT;
		}
	}
	| size_clause
	| transfer_clause
	| L_TRANSFER_FORMAT transfer_format
	{
		tmpres = dns_c_ctx_settransferformat(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining transfer-format.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set transfer-format.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_TIME_IN L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setmaxtransfertimein(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining max-transfer-time-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set max-transfer-time-in.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_TIME_OUT L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setmaxtransfertimeout(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining max-transfer-time-out.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set max-transfer-time-out.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_IDLE_IN L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setmaxtransferidlein(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining max-transfer-idle-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set max-transfer-idle-in.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_IDLE_OUT L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setmaxtransferidleout(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining max-transfer-idle-out.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set max-transfer-idle-out.");
			YYABORT;
		}
	}
	| L_TCP_CLIENTS L_INTEGER
	{
		tmpres = dns_c_ctx_settcpclients(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining tcp-clients.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set tcp-clients.");
			YYABORT;
		}
	}
	| L_RECURSIVE_CLIENTS L_INTEGER
	{
		tmpres = dns_c_ctx_setrecursiveclients(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining recursive-clients.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set recursive-clients.");
			YYABORT;
		}
	}
	| L_CLEAN_INTERVAL L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setcleaninterval(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining cleaning-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set cleaning-interval.");
			YYABORT;
		}
	}
	| L_INTERFACE_INTERVAL L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setinterfaceinterval(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining interface-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set interface-interval.");
			YYABORT;
		}
	}
	| L_STATS_INTERVAL L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setstatsinterval(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining statistics-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set statistics-interval.");
			YYABORT;
		}
	}
	| L_MAX_LOG_SIZE_IXFR L_INTEGER
	{
		tmpres = dns_c_ctx_setmaxlogsizeixfr(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining max-ixfr-log-size.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set max-ixfr-log-size.");
			YYABORT;
		}
	}
	| L_MAX_NCACHE_TTL L_INTEGER
	{
		tmpres = dns_c_ctx_setmaxncachettl(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining max-ncache-ttl.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set max-ncache-ttl.");
			YYABORT;
		}
	}
	| L_HEARTBEAT L_INTEGER
	{
		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_ctx_setheartbeat_interval(currcfg, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining heartbeat-interval.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set heartbeat-interval.");
			YYABORT;
		}
	}
	| L_DIALUP yea_or_nay
	{
		tmpres = dns_c_ctx_setdialup(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining dialup.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set dialup.");
			YYABORT;
		}
	}
	| L_RRSET_ORDER
	{
		dns_c_rrsolist_t *ordering;

		tmpres = dns_c_ctx_getrrsetorderlist(currcfg, &ordering);
		if (tmpres != ISC_R_NOTFOUND) {
			parser_warning(ISC_FALSE,
				     "redefining rrset-order list");
			dns_c_rrsolist_clear(ordering);
		} else {
			tmpres = dns_c_rrsolist_new(currcfg->mem, &ordering);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create rrset-order "
					     "list");
				YYABORT;
			}
			tmpres = dns_c_ctx_setrrsetorderlist(currcfg,
							     ISC_FALSE,
							     ordering);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to set rrset-order.");
				YYABORT;
			}
		}
	} L_LBRACE rrset_ordering_list L_RBRACE
	;


/*
 * Controls.
 */
controls_stmt: L_CONTROLS
	{
		if (currcfg->controls != NULL) {
			parser_warning(ISC_FALSE, "redefining controls");
			dns_c_ctrllist_delete(&currcfg->controls);
		}
		
		tmpres = dns_c_ctrllist_new(currcfg->mem,
					    &currcfg->controls);
		if (tmpres != ISC_R_SUCCESS) {
			YYABORT;
		}
	} L_LBRACE controls L_RBRACE
	;

controls: control L_EOS
	| controls control L_EOS
	;

control: /* Empty */
	| L_INET maybe_wild_addr L_PORT in_port
	  L_ALLOW L_LBRACE address_match_list L_RBRACE
	{
		dns_c_ctrl_t *control;

		tmpres = dns_c_ctrlinet_new(currcfg->mem, &control,
					    $2, $4, $7, ISC_FALSE);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				    "failed to build inet control structure");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->controls->elements, control, next);
	}
	| L_UNIX L_QSTRING L_PERM L_INTEGER L_OWNER L_INTEGER L_GROUP L_INTEGER
	{
		dns_c_ctrl_t *control;

		tmpres = dns_c_ctrlunix_new(currcfg->mem, &control,
					    $2, $4, $6, $8);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to build unix control structure");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->controls->elements, control, next);

		isc_mem_free(memctx, $2);
	}
	;

rrset_ordering_list: rrset_ordering_element L_EOS
	| rrset_ordering_list rrset_ordering_element L_EOS
	;

ordering_class: /* nothing */
	{
		$$ = dns_rdataclass_any;
	}
	| L_CLASS class_name
	{
		$$ = $2;
	}
	;

ordering_type: /* nothing */
	{
		$$ = dns_rdatatype_any;
	}
	| L_TYPE any_string
	{
		isc_textregion_t reg;
		dns_rdatatype_t ty;

		if (strcmp($2, "*") == 0) {
			ty = dns_rdatatype_any;
		} else {
			reg.base = $2;
			reg.length = strlen($2);
		
			tmpres = dns_rdatatype_fromtext(&ty, &reg);
			if (tmpres != DNS_R_SUCCESS) {
				parser_warning(ISC_TRUE,
					       "unknown type. Assuming ``*''");
				ty = dns_rdatatype_any;
			}
		}
		
		isc_mem_free(memctx, $2);
		$$ = ty;
	}
	;


ordering_name: /* nothing */
	{
		$$ = isc_mem_strdup(memctx, "*");
	}
	| L_NAME domain_name
	{
		if (strcmp($2, ".") == 0 || strcmp($2, "*.") == 0) {
			$$ = isc_mem_strdup(memctx, "*");
			isc_mem_free(memctx, $2);
		} else {
			$$ = $2;
		}
	}


rrset_ordering_element: ordering_class ordering_type ordering_name
	L_ORDER L_STRING
	{
		dns_c_rrso_t *orderelem;
		dns_c_ordering_t o;

		tmpres = dns_c_string2ordering($5, &o);
		if (tmpres != ISC_R_SUCCESS) {
			parser_warning(ISC_FALSE,
				       "unknown ordering type ``%s''."
				       " Using default", $5);
			o = DNS_DEFAULT_ORDERING;
		}

		tmpres = dns_c_rrso_new(currcfg->mem,
					&orderelem, $1, $2, $3, o);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create rrset-order element");
			YYABORT;
		}

		ISC_LIST_APPEND(currcfg->options->ordering->elements,
				orderelem, next);

		isc_mem_free(memctx, $5);
		isc_mem_free(memctx, $3);
	}


transfer_format: L_ONE_ANSWER
	{
		$$ = dns_one_answer;
	}
	| L_MANY_ANSWERS
	{
		$$ = dns_many_answers;
	}
	;


maybe_wild_addr: ip4_address
	| ip6_address
	| L_STRING
	{
		struct in_addr any;
		any.s_addr = htonl(INADDR_ANY);

		memset(&any, 0x0, sizeof any);
		isc_sockaddr_fromin(&$$, &any, 0);

		if (strcmp($1, "*") != 0) {
			parser_error(ISC_TRUE,
				     "bad ip-address. using ipv4 ``*''");
		}

		isc_mem_free(memctx, $1);
	}
	;
	
maybe_wild_ip4_only_addr: ip4_address
	{
		$$ = $1;
	}
	| ip6_address
	{
		parser_error(ISC_FALSE,
			     "cannot have an IPv6 address in this context.");
		YYABORT;
	}
	| L_STRING
	{
		struct in_addr any;
		any.s_addr = htonl(INADDR_ANY);

		memset(&any, 0x0, sizeof any);
		isc_sockaddr_fromin(&$$, &any, 0);

		if (strcmp($1, "*") != 0) {
			parser_error(ISC_TRUE,
				     "bad IPv4-address. using ``*''");
		}

		isc_mem_free(memctx, $1);
	}
	;

maybe_wild_ip6_only_addr: ip6_address
	{
		$$ = $1;
	}
	| ip4_address
	{
		parser_error(ISC_FALSE,
			     "cannot have an IPv4 address in this context.");
		YYABORT;
	}
	| L_STRING
	{
		isc_sockaddr_fromin6(&$$, &in6addr_any, 0);

		if (strcmp($1, "*") != 0) {
			parser_error(ISC_TRUE,
				     "bad IPv6-address. using ``*''");
		}

		isc_mem_free(memctx, $1);
	}
	;

maybe_wild_port: in_port
	{
		$$ = $1;
	}
	| L_STRING
	{
		$$ = 0;

		if (strcmp ($1, "*") != 0) {
			parser_error(ISC_TRUE,
				     "bad port specification. Using ``*''");
		}

		isc_mem_free(memctx, $1);
	}
	;

query_source_v6: L_ADDRESS maybe_wild_ip6_only_addr
	{
		isc_sockaddr_setport(&$2, 0); /* '0' is wild port  */
		$$ = $2;
	}
	| L_ADDRESS maybe_wild_ip6_only_addr L_PORT maybe_wild_port
	{
		isc_sockaddr_setport(&$2, $4);
		$$ = $2;
	}
	| L_PORT maybe_wild_port
	{
		isc_sockaddr_t addr;
		isc_sockaddr_fromin6(&addr, &in6addr_any, $2);
		$$ = addr;
	}
	| L_PORT maybe_wild_port L_ADDRESS maybe_wild_ip6_only_addr
	{
		isc_sockaddr_setport(&$4, $2);
		$$ = $4;
	}
	;

query_source_v4: L_ADDRESS maybe_wild_ip4_only_addr
	{
		isc_sockaddr_setport(&$2, 0); /* '0' is wild port  */
		$$ = $2;
	}
	| L_ADDRESS maybe_wild_ip4_only_addr L_PORT maybe_wild_port
	{
		isc_sockaddr_setport(&$2, $4);
		$$ = $2;
	}
	| L_PORT maybe_wild_port
	{
		struct in_addr any;
		isc_sockaddr_t addr;

		memset(&any, 0x0, sizeof any);
		any.s_addr = htonl(INADDR_ANY);
		isc_sockaddr_fromin(&addr, &any, $2);
		$$ = addr;
	}
	| L_PORT maybe_wild_port L_ADDRESS maybe_wild_ip4_only_addr
	{
		isc_sockaddr_setport(&$4, $2);
		$$ = $4;
	}
	;

maybe_port: /* nothing */
	{
		$$ = DNS_C_DEFAULTPORT;
	}
	| L_PORT in_port
	{
		$$ = $2;
	}
	;

maybe_zero_port : /* nothing */
	{
		$$ = 0;
	}
	| L_PORT in_port
	{
		$$ = $2;
	}
	;

yea_or_nay: L_YES
	{
		$$ = isc_boolean_true;
	}
	| L_TRUE
	{
		$$ = isc_boolean_true;
	}
	| L_NO
	{
		$$ = isc_boolean_false;
	}
	| L_FALSE
	{
		$$ = isc_boolean_false;
	}
	| L_INTEGER
	{
		if ($1 == 1) {
			$$ = isc_boolean_true;
		} else if ($1 == 0) {
			$$ = isc_boolean_false;
		} else {
			parser_warning(ISC_TRUE,
				       "number should be 0 or 1; assuming 1");
			$$ = isc_boolean_true;
		}
	}
	;

check_names_type: L_MASTER
	{
		$$ = dns_trans_primary;
	}
	| L_SLAVE
	{
		$$ = dns_trans_secondary;
	}
	| L_RESPONSE
	{
		$$ = dns_trans_response;
	}
	;

check_names_opt: L_WARN
	{
		$$ = dns_severity_warn;
	}
	| L_FAIL
	{
		$$ = dns_severity_fail;
	}
	| L_IGNORE
	{
		$$ = dns_severity_ignore;
	}
	;

forward_opt: L_ONLY
	{
		$$ = dns_c_forw_only;
	}
	| L_FIRST
	{
		$$ = dns_c_forw_first;
	}
	| L_IF_NO_ANSWER
	{
		$$ = dns_c_forw_noanswer;
	}
	| L_IF_NO_DOMAIN
	{
		$$ = dns_c_forw_nodomain;
	}
	;



size_clause: L_DATASIZE size_spec
	{
		tmpres = dns_c_ctx_setdatasize(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining datasize.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set datasize.");
			YYABORT;
		}
	}
	| L_STACKSIZE size_spec
	{
		tmpres = dns_c_ctx_setstacksize(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining stacksize.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set stacksize.");
			YYABORT;
		}
	}
	| L_CORESIZE size_spec
	{
		tmpres = dns_c_ctx_setcoresize(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining coresize.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set coresize.");
			YYABORT;
		}
	}
	| L_FILES size_spec
	{
		tmpres = dns_c_ctx_setfiles(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining files.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set files.");
			YYABORT;
		}
	}
	;


size_spec: any_string
	{
		isc_uint32_t result;

		if (unit_to_uint32($1, &result)) {
			$$ = result;
			if ($$ == DNS_C_SIZE_SPEC_DEFAULT) {
				isc_uint32_t newi = DNS_C_SIZE_SPEC_DEFAULT-1;
				parser_warning(ISC_FALSE,
					       "value (%lu) too big. "
					       "reducing to %lu",
					       (unsigned long)$$,
					       (unsigned long)newi);
				$$ = newi;			}
		} else {
			parser_warning(ISC_FALSE,
				       "invalid unit string '%s'. Using "
				       "default", $1);
			$$ = DNS_C_SIZE_SPEC_DEFAULT;
		}
		isc_mem_free(memctx, $1);
	}
	| L_INTEGER
	{
		$$ = (isc_uint32_t)$1;
		if ($$ == DNS_C_SIZE_SPEC_DEFAULT) {
			isc_uint32_t newi = DNS_C_SIZE_SPEC_DEFAULT - 1;
			parser_warning(ISC_FALSE,
				       "value (%lu) too big. Reducing to %lu",
				       (unsigned long) $$,
				       (unsigned long) newi);
			$$ = newi;
		}
	}
	| L_DEFAULT
	{
		$$ = DNS_C_SIZE_SPEC_DEFAULT;
	}
	| L_UNLIMITED
	{
		$$ = DNS_C_SIZE_SPEC_UNLIM;
	}
	;



transfer_clause: L_TRANSFERS_IN L_INTEGER
	{
		tmpres = dns_c_ctx_settransfersin(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining transfers-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "failed to set transfers-in.");
			YYABORT;
		}
	}
	| L_TRANSFERS_OUT L_INTEGER
	{
		tmpres = dns_c_ctx_settransfersout(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining transfers-out.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set transfers-out.");
			YYABORT;
		}
	}
	| L_TRANSFERS_PER_NS L_INTEGER
	{
		tmpres = dns_c_ctx_settransfersperns(currcfg, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				     "redefining transfers-per-ns.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set transfers-per-ns.");
			YYABORT;
		}
	}
	;


opt_forwarders_list: /* nothing */ {
	}
	| forwarders_in_addr_list
	;

forwarders_in_addr_list: forwarders_in_addr L_EOS
	| forwarders_in_addr_list forwarders_in_addr L_EOS
	;

forwarders_in_addr: ip_address
	{
		tmpres = dns_c_iplist_append(currcfg->options->forwarders, $1);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to add forwarders "
				     "address element.");
			YYABORT;
		}
	}
	;


/*
 * Logging
 */

logging_stmt: L_LOGGING
	{
		/* initialized in logging_init() */
		INSIST(currcfg->logging != NULL);
	}
	L_LBRACE logging_opts_list L_RBRACE
	;

logging_opts_list: logging_opt L_EOS
	| logging_opts_list logging_opt L_EOS
	;

logging_opt: category_stmt
	| channel_stmt
	;


channel_stmt:
	L_CHANNEL channel_name L_LBRACE L_FILE L_QSTRING {
		dns_c_logchan_t *newc;
		
		tmpres = dns_c_ctx_addfile_channel(currcfg,
						   $2, &newc);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefing channel %s", $2);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to add new file channel.");
			YYABORT;
		}

		INSIST(newc != NULL);

		tmpres = dns_c_logchan_setpath(newc, $5);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to add file channel's path.");
			YYABORT;
		}

		isc_mem_free(memctx, $2);
		isc_mem_free(memctx, $5);
	}  maybe_file_modifiers L_EOS optional_channel_opt_list L_RBRACE
	| L_CHANNEL channel_name L_LBRACE L_SYSLOG maybe_syslog_facility {
		dns_c_logchan_t *newc;
		
		tmpres = dns_c_ctx_addsyslogchannel(currcfg,
						    $2, &newc);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining channel %s", $2);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to add new syslog channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setfacility(newc, $5);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel facility.");
			YYABORT;
		}
		isc_mem_free(memctx, $2);
	} L_EOS optional_channel_opt_list L_RBRACE
	| L_CHANNEL channel_name L_LBRACE L_NULL_OUTPUT {
		dns_c_logchan_t *newc;
		
		tmpres = dns_c_ctx_addnullchannel(currcfg,
						  $2, &newc);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining channel %s", $2);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to add new channel ``%s''", $2);
			YYABORT;
		}

		isc_mem_free(memctx, $2);
	} L_EOS optional_channel_opt_list L_RBRACE
	| L_CHANNEL channel_name L_LBRACE logging_non_type_keywords {
		parser_error(ISC_FALSE,
			     "first statment inside a channel definition "
			     "must be ``file'' or ``syslog'' or ``null''.");
		YYABORT;
	}
	;


logging_non_type_keywords: L_SEVERITY | L_PRINT_TIME | L_PRINT_CATEGORY |
	L_PRINT_SEVERITY
	;

	
optional_channel_opt_list: /* empty */
	| channel_opt_list
	;
	
category_stmt: L_CATEGORY category_name {
		dns_c_logcat_t *cat;
		
		tmpres = dns_c_ctx_addcategory(currcfg, $2, &cat);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining category ``%s''", $2);
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to add new logging category.");
			isc_mem_free(memctx, $2);
			YYABORT;
		}
		isc_mem_free(memctx, $2);
	} L_LBRACE channel_list L_RBRACE
	;


channel_severity: any_string
	{
		dns_c_logseverity_t severity;
		dns_c_logchan_t *chan;

		tmpres = dns_c_string2logseverity($1, &severity);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "unknown severity ``%s''", $1);
			YYABORT;
		}

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setseverity(chan, severity);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel severity.");
			YYABORT;
		}

		isc_mem_free(memctx, $1);
	}
	| L_DEBUG
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setseverity(chan,
						   dns_c_log_debug);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel severity(debug).");
			YYABORT;
		}
	}
	| L_DEBUG L_INTEGER
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setseverity(chan,
						   dns_c_log_debug);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel "
				     "severity (debug).");
			YYABORT;
		}

		tmpres = dns_c_logchan_setdebuglevel(chan, $2);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel "
				     "severity debug level.");
			YYABORT;
		}
	}
	| L_DYNAMIC
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setseverity(chan,
						   dns_c_log_dynamic);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel "
				     "severity (dynamic).");
			YYABORT;
		}
	}
	;

version_modifier: L_VERSIONS L_INTEGER
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setversions(chan, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining versions.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel versions.");
			YYABORT;
		}
	}
	| L_VERSIONS L_UNLIMITED
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setversions(chan, -1);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining versions.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel "
				     "versions (unlimited).");
			YYABORT;
		}
	}
	;

size_modifier: L_SIZE size_spec
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setsize(chan, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining size.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel size.");
			YYABORT;
		}
	}
	;

maybe_file_modifiers: /* nothing */
	| version_modifier
	| size_modifier
	| version_modifier size_modifier
	| size_modifier version_modifier
	;

facility_name: any_string
	{
		tmpres = dns_c_string2facility($1, &$$);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE, "unknown syslog facility.");
			$$ = LOG_DAEMON;
		}

		isc_mem_free(memctx, $1);
	}
	| L_SYSLOG
	{
		$$ = LOG_SYSLOG;
	}
	;

maybe_syslog_facility: /* nothing */
	{
		$$ = LOG_DAEMON;
	}
	| facility_name
	{
		$$ = $1;
	}
	;


channel_opt_list: channel_opt L_EOS
	| channel_opt_list channel_opt L_EOS
	;


channel_opt: L_SEVERITY channel_severity { /* nothing to do */ }
	| L_PRINT_TIME yea_or_nay
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setprinttime(chan, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE, "redefining print-time.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel print-time.");
			YYABORT;
		}
	}
	| L_PRINT_CATEGORY yea_or_nay
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setprintcat(chan, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining print-category.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel print-category.");
			YYABORT;
		}
	}
	| L_PRINT_SEVERITY yea_or_nay
	{
		dns_c_logchan_t *chan;

		tmpres = dns_c_ctx_currchannel(currcfg, &chan);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "can't get current channel.");
			YYABORT;
		}

		tmpres = dns_c_logchan_setprintsev(chan, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining print-severity.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't get set channel print-severity.");
			YYABORT;
		}
	}
	;


channel_name: any_string
	| L_NULL_OUTPUT
	{
		$$ = isc_mem_strdup(memctx, "null");
	}
	;


channel: channel_name
	{
		dns_c_logcat_t *cat;

		/*
		 * XXX validate the channel name refers to a previously
		 * defined channel
		 */
		tmpres = dns_c_ctx_currcategory(currcfg, &cat);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE, "can't get current category.");
			YYABORT;
		}

		tmpres = dns_c_logcat_addname(cat, $1);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "can't add new name to category.");
			YYABORT;
		}

		isc_mem_free(memctx, $1);
	}
	;


channel_list: channel L_EOS
	| channel_list channel L_EOS
	;


category_name: any_string
	{
		tmpres = dns_c_checkcategory($1);
		if (tmpres != ISC_R_SUCCESS) {
			parser_warning(ISC_FALSE,
				       "unknown category ``%s''", $1);
		}

		$$ = $1;
	}
	| L_DEFAULT
	{
		char *name = token_to_keyword(L_DEFAULT);

		REQUIRE(name != NULL);
		
		$$ = isc_mem_strdup(memctx, name);
	}
	| L_NOTIFY
	{
		char *name = token_to_keyword(L_NOTIFY);

		REQUIRE(name != NULL);
		
		$$ = isc_mem_strdup(memctx, name);
	}
	;

/*
 * Server Information
 */

server_stmt: L_SERVER ip_address
	{
		dns_peer_t *peer;
		dns_peerlist_t *peers = currcfg->peers;
		isc_netaddr_t netaddr;

		isc_netaddr_fromsockaddr(&netaddr, &$2);
		
		if (peers == NULL) {
			tmpres = dns_peerlist_new(currcfg->mem,
						  &currcfg->peers);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create peer list");
				YYABORT;
			}
			peers = currcfg->peers;
		}

		/*
		 * Check that this IP hasn't already been used.
		 */
		tmpres = dns_peerlist_peerbyaddr(peers, &netaddr, &peer);
		if (tmpres == ISC_R_SUCCESS) {
			dns_peer_detach(&peer);
			parser_error(ISC_TRUE, "redefining peer");
			YYABORT;
		}
		
		tmpres = dns_peer_new(currcfg->mem, &netaddr, &peer);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create peer structure");
			YYABORT;
		}

		dns_peerlist_addpeer(currcfg->peers, peer);
		dns_peer_detach(&peer);
	}
	L_LBRACE server_info_list L_RBRACE
	;

server_info_list: server_info L_EOS
	| server_info_list server_info L_EOS
	;

server_info: L_BOGUS yea_or_nay
	{
		dns_peer_t *peer = NULL;

		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_peer_setbogus(peer, $2);
		dns_peer_detach(&peer);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining server bogus value");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting server bogus value");
			YYABORT;
		}
		
	}
	| L_SUPPORT_IXFR yea_or_nay
	{
		/*
		 * Backwards compatibility, equivalent to request-ixfr.
		 */
		dns_peer_t *peer = NULL;

		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_peer_setrequestixfr(peer, $2);
		dns_peer_detach(&peer);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining peer request-ixfr value");
		} else if(tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting peer "
				     "request-ixfr value");
			YYABORT;
		}
	}
	| L_PROVIDE_IXFR yea_or_nay
	{
		dns_peer_t *peer = NULL;

		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_peer_setprovideixfr(peer, $2);
		dns_peer_detach(&peer);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining peer provide-ixfr value");
		} else if(tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting peer "
				     "provide-ixfr value");
			YYABORT;
		}
	}
	| L_REQUEST_IXFR yea_or_nay
	{
		dns_peer_t *peer = NULL;

		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_peer_setrequestixfr(peer, $2);
		dns_peer_detach(&peer);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining peer request-ixfr value");
		} else if(tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting peer "
				     "request-ixfr value");
			YYABORT;
		}
	}
	| L_TRANSFERS L_INTEGER
	{
		dns_peer_t *peer = NULL;

		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_peer_settransfers(peer, $2);
		dns_peer_detach(&peer);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining peer transfers value");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting peer transfers value");
			YYABORT;
		}
	}
	| L_TRANSFER_FORMAT transfer_format
	{
		dns_peer_t *peer = NULL;

		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_peer_settransferformat(peer, $2);
		dns_peer_detach(&peer);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining peer transfer-format "
				       "value");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting peer transfer-format "
				     "value");
			YYABORT;
		}
	}
	| L_KEYS key_value {
		dns_peer_t *peer = NULL;
		dns_name_t *name = NULL;

		/* XXX need to validate key exists */
		
		dns_peerlist_currpeer(currcfg->peers, &peer);
		INSIST(peer != NULL);

		tmpres = dns_c_charptoname(peer->mem, $2, &name);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error creating key name value");
			YYABORT;
		}
		
		tmpres = dns_peer_setkey(peer, &name);
		isc_mem_free(memctx, $2);
		dns_peer_detach(&peer);
		
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining peer key "
				       "value");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error setting peer key value");
			YYABORT;
		}
	}
	;


key_value: L_LBRACE any_string maybe_eos L_RBRACE
	{
		$$ = $2;
	}
	| any_string
	{
		$$ = $1;
	};


/*
 * Address Matching
 */

address_match_list: address_match_element L_EOS
	{
		dns_c_ipmatchlist_t *ml = 0;

		if ($1 != NULL) {
			tmpres = dns_c_ipmatchlist_new(currcfg->mem, &ml);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE, "insufficient memory");
				dns_c_ipmatchelement_delete(currcfg->mem,
							    &$1);
				YYABORT;
			}
			
			ISC_LIST_APPEND(ml->elements, $1, next);
		}
		
		$$ = ml;
	}
	| address_match_list address_match_element L_EOS
	{
		dns_c_ipmatchlist_t *ml = $1;
		
		if (ml == NULL && $2 != NULL) {
			tmpres = dns_c_ipmatchlist_new(currcfg->mem, &ml);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE, "insufficient memory");
				dns_c_ipmatchelement_delete(currcfg->mem,
							    &$2);
				YYABORT;
			}
		}

		if ($2 != NULL) {
			ISC_LIST_APPEND(ml->elements, $2, next);
		}
		
		$$ = ml;
	}
	;

address_match_element: address_match_simple
	| L_BANG address_match_simple
	{
		if ($2 != NULL) {
			dns_c_ipmatch_negate($2);
		}
		$$ = $2;
	}
	| L_SEC_KEY L_STRING
	{
		dns_c_ipmatchelement_t *ime = NULL;

		if (!dns_c_ctx_keydefinedp(currcfg, $2)) {
			parser_error(ISC_FALSE,
				     "address match key element (%s) "
				     "referenced before defined", $2);
			YYABORT;
		} else {
			tmpres = dns_c_ipmatchkey_new(currcfg->mem, &ime, $2);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_TRUE,
					     "failed to create address match "
					     "key element for %s", $2);
				YYABORT;
			}
		}
		
		isc_mem_free(memctx, $2);
		$$ = ime;
	}
	;

address_match_simple: ip_address
	{
		dns_c_ipmatchelement_t *ime = NULL;
		unsigned int prefixlen = 0;
		
		switch ($1.type.sa.sa_family) {
		case AF_INET:
			prefixlen = 32;
			break;
		case AF_INET6:
			prefixlen = 128;
			break;
		default:
			INSIST(0);
			break;
		}
		tmpres = dns_c_ipmatchpattern_new(currcfg->mem, &ime, $1,
						  prefixlen);
		switch (tmpres) {
		case ISC_R_FAILURE:
			parser_error(ISC_FALSE, "bad address match element.");
			YYABORT;
			break;

		case ISC_R_NOMEMORY:
			parser_error(ISC_FALSE,
				    "insufficient memory available.");
			YYABORT;
			break;

		case ISC_R_SUCCESS:
			break;
		}

		$$ = ime;
	}
	| ip_address L_SLASH L_INTEGER
	{
		dns_c_ipmatchelement_t *ime = NULL;

		if ($3 < 0 ||
		    ($1.type.sa.sa_family == AF_INET && $3 > 32) ||
		    ($1.type.sa.sa_family == AF_INET6 && $3 > 128)) {
			parser_warning(ISC_FALSE,
				       "mask bits (%d) out of range: "
				       "skipping", (int)$3);
			$$ = NULL;
		} else {
			tmpres = dns_c_ipmatchpattern_new(currcfg->mem, &ime,
							  $1, $3);
			switch (tmpres) {
			case ISC_R_FAILURE:
				parser_error(ISC_FALSE,
					     "bad address match element.");
				YYABORT;
				break;

			case ISC_R_NOMEMORY:
				parser_error(ISC_FALSE,
					    "insufficient memory "
					    "available.");
				YYABORT;
				break;

			case ISC_R_SUCCESS:
				break;
			}
		}

		$$ = ime;
	}
	| L_INTEGER L_SLASH L_INTEGER
	{
		struct in_addr ia;
		dns_c_ipmatchelement_t *ime = NULL;
		isc_sockaddr_t address;

		if ($1 > 255) {
			parser_error(ISC_FALSE,
				     "address out of range; skipping");
			YYABORT;
		} else {
			if ($3 < 0 || $3 > 32) {
				parser_warning(ISC_FALSE,
					       "mask bits out of range; "
					       "skipping");
				$$ = NULL;
			} else {
				ia.s_addr = htonl(($1 & 0xff) << 24);
				isc_sockaddr_fromin(&address, &ia, 0);
				
				tmpres =
					dns_c_ipmatchpattern_new(currcfg->mem,
								 &ime,
								 address,
								 $3);
				switch (tmpres) {
				case ISC_R_FAILURE:
					parser_error(ISC_FALSE,
						     "bad address match "
						     "element.");
					YYABORT;
					break;

				case ISC_R_NOMEMORY:
					parser_error(ISC_FALSE,
						    "insufficient memory "
						    "available.");
					YYABORT;
					break;

				case ISC_R_SUCCESS:
					break;
				}
			}
		}

		$$ = ime;
	}
	| address_name
	| L_LBRACE address_match_list L_RBRACE
	{
		dns_c_ipmatchelement_t *ime = NULL;
		
		if ($2 != NULL) {
			tmpres = dns_c_ipmatchindirect_new(currcfg->mem, &ime,
							   $2, NULL);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					    "failed to create indirect "
					    "ipmatch list.");
				YYABORT;
			}
		}

		dns_c_ipmatchlist_detach(&$2);

		$$ = ime;
	}
	;

address_name: any_string
	{
		dns_c_ipmatchelement_t *elem;
		dns_c_acl_t *acl;

		if (strcmp($1, "any") == 0) {
			tmpres = dns_c_ipmatchany_new(currcfg->mem, &elem);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create ``any''"
					     " ipmatch element");
				YYABORT;
			}
		} else if (strcmp($1, "none") == 0) {
			tmpres = dns_c_ipmatchany_new(currcfg->mem, &elem);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create ``none''"
					     " ipmatch element");
				YYABORT;
			}
			dns_c_ipmatch_negate(elem);
		} else if (strcmp($1, "localhost") == 0) {
			tmpres = dns_c_ipmatchlocalhost_new(currcfg->mem,
							    &elem);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create ``localhost''"
					     " ipmatch element");
				YYABORT;
			}
		} else if (strcmp($1, "localnets") == 0) {
			tmpres = dns_c_ipmatchlocalnets_new(currcfg->mem,
							    &elem);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create ``localnets''"
					     " ipmatch element");
				YYABORT;
			}
		} else {
			tmpres = dns_c_acltable_getacl(currcfg->acls,
						       $1, &acl);
			if (tmpres == ISC_R_NOTFOUND) {
				parser_warning(ISC_FALSE,
					       "undefined acl ``%s'' "
					       "referenced", $1);
				elem = NULL;
			} else {
				tmpres = dns_c_ipmatch_aclnew(currcfg->mem,
							      &elem, $1);
				if (tmpres != ISC_R_SUCCESS) {
					parser_error(ISC_FALSE,
						     "failed to create "
						     "IPE-ACL");
					YYABORT;
				}
			}
		}

		isc_mem_free(memctx, $1);
		$$ = elem;
	}
	;

/*
 * Keys
 */


key_stmt: L_SEC_KEY any_string
	{
		dns_c_kdef_t *keydef;
		
		if (currcfg->keydefs == NULL) {
			tmpres = dns_c_kdeflist_new(currcfg->mem,
						    &currcfg->keydefs);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create keylist");
				YYABORT;
			}
		}
		
		tmpres = dns_c_kdef_new(currcfg->keydefs,
					$2, &keydef);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create key definition");
			YYABORT;
		}

		isc_mem_free(memctx, $2);
	}
	L_LBRACE key_definition L_RBRACE
	;

key_definition: algorithm_id secret
	{
		dns_c_kdef_t *keydef;

		INSIST(currcfg->keydefs != NULL);

		keydef = ISC_LIST_TAIL(currcfg->keydefs->keydefs);
		INSIST(keydef != NULL);

		dns_c_kdef_setalgorithm(keydef, $1);
		dns_c_kdef_setsecret(keydef, $2);

		isc_mem_free(memctx, $1);
		isc_mem_free(memctx, $2);
	}
	| secret algorithm_id
	{
		dns_c_kdef_t *keydef;

		INSIST(currcfg->keydefs != NULL);

		keydef = ISC_LIST_TAIL(currcfg->keydefs->keydefs);
		INSIST(keydef != NULL);

		dns_c_kdef_setsecret(keydef, $1);
		dns_c_kdef_setalgorithm(keydef, $2);

		isc_mem_free(memctx, $1);
		isc_mem_free(memctx, $2);
	}
	;

algorithm_id: L_ALGID any_string L_EOS
	{
		$$ = $2;
	}
	;

secret: L_SECRET any_string L_EOS
	{
		$$ = $2;
	}
	;


/*
 * Views
 */


view_stmt: L_VIEW any_string L_LBRACE 
	{
		dns_c_view_t *view;

		if (currcfg->views == NULL) {
			tmpres = dns_c_viewtable_new(currcfg->mem,
						     &currcfg->views);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to create viewtable");
				YYABORT;
			}
		}
		
		tmpres = dns_c_view_new(currcfg->mem, $2, &view);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create view %s", $2);
			YYABORT;
		}

		dns_c_viewtable_addview(currcfg->views, view);
		dns_c_ctx_setcurrview(currcfg, view);

		isc_mem_free(memctx, $2);
	} optional_view_options_list L_RBRACE {
		dns_c_ctx_setcurrview(currcfg, NULL);
	};

optional_view_options_list:
	| view_options_list
	;

view_options_list: view_option L_EOS
	| view_options_list view_option L_EOS;


view_option: L_ALLOW_QUERY L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setallowquery(view, $3,
						  ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view allow-query.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view allow-query.");
			YYABORT;
		}
	}
	| L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setallowtransfer(view,
						     $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view allow-transfer.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view allow-transfer.");
			YYABORT;
		}
	}
	| L_ALLOW_RECURSION L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setallowrecursion(view,
						      $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view allow-recursion.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view allow-recursion.");
			YYABORT;
		}
	}
	| L_ALLOW_UPDATE_FORWARDING L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setallowupdateforwarding(view,
							     $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view "
				       "allow-update-forwarding.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view "
				     "allow-update-forwarding.");
			YYABORT;
		}
	}
	| L_BLACKHOLE L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setblackhole(view,
						 $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view blackhole.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view blackhole.");
			YYABORT;
		}
	}
	| L_FORWARDERS L_LBRACE opt_in_addr_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setforwarders(view,
						  $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view forwarders.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view forwarders.");
			YYABORT;
		}
	}
	| L_SORTLIST L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_setsortlist(view,
						$3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view sortlist.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view sortlist.");
			YYABORT;
		}
	}
	| L_TOPOLOGY L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);

		tmpres = dns_c_view_settopology(view,
						$3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining view topology.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set view topology.");
			YYABORT;
		}
	}
	| L_LISTEN_ON maybe_port L_LBRACE address_match_list L_RBRACE
	{
		dns_c_view_t *view = dns_c_ctx_getcurrview(currcfg);

		INSIST(view != NULL);
		
		if ($4 == NULL) {
			parser_warning(ISC_FALSE,
				       "address-match-list empty. "
				       "listen statement ignored.");
		} else {
			tmpres = dns_c_view_addlisten_on(view, $2, $4,
							 ISC_FALSE);

			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "failed to add listen statement");
				YYABORT;
			}
		}
	}
/* XXX not implemented yet
	| L_RRSET_ORDER L_LBRACE rrset_ordering_list L_RBRACE 
	| L_CHECK_NAMES 
	| L_TRANSFER_FORMAT
*/
        | zone_stmt
	;


zone_ssu_stmt: grant_stmt {
		dns_ssutable_t *ssutable = NULL;
		isc_boolean_t ok = ISC_TRUE;
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		REQUIRE(zone != NULL);

		switch(zone->ztype) {
		case dns_c_zone_hint:
			parser_error(ISC_FALSE,
				     "hint zones do not have grant/deny "
				     "statements.");
			ok = ISC_FALSE;
			break;
			
		case dns_c_zone_forward:
			parser_error(ISC_FALSE,
				     "forward zones do not have grant/deny "
				     "statements.");
			ok = ISC_FALSE;
			break;

		default:
			/* nothing */
			break;
		}

		if (ok) {
			tmpres = dns_c_zone_getssuauth(zone, &ssutable);
			if (tmpres == ISC_R_NOTFOUND) {
				REQUIRE(ssutable == NULL);

				tmpres = dns_ssutable_create(currcfg->mem,
						     &ssutable);
				if (tmpres != ISC_R_SUCCESS) {
					parser_error(ISC_FALSE,
						     "failed to create "
						     "ssutable");
					ok = ISC_FALSE;
				}
			}

			if (ok) {
				dns_c_zone_setssuauth(zone, ssutable);
			}
		}

		tmpres = dns_ssutable_addrule(ssutable, $1.grant,
					      $1.ident, $1.matchtype,
					      $1.name,
					      $1.rdatatypes.idx,
					      &$1.rdatatypes.types[0]);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error creating ssu "
				     "identity value");
			ok = ISC_FALSE;
		}
		
		dns_name_free($1.ident, memctx);
		dns_name_free($1.name, memctx);

		isc_mem_put(memctx, $1.ident, sizeof (*$1.ident));
		isc_mem_put(memctx, $1.name, sizeof (*$1.name));

		if (!ok) {
			YYABORT;
		}
	};

grant_stmt: grantp any_string grant_match_type any_string rdatatype_list
	{
		dns_name_t *name = NULL;
		dns_name_t *identity = NULL;
		isc_boolean_t ok = ISC_TRUE;
		
		tmpres = dns_c_charptoname(memctx, $4, &name);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "error creating ssu name value");
			ok = ISC_FALSE;
		}

		if (ok) {
			tmpres = dns_c_charptoname(memctx, $2, &identity);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_FALSE,
					     "error creating ssu "
					     "identity value");
				ok = ISC_FALSE;
			}
		}

		if (ok) {
			if (!dns_name_isabsolute(identity)) {
				parser_error(ISC_FALSE,
					     "identity (%s) must be an "
					     "absolute (not relative) name.",
					     $2);
				ok = ISC_FALSE;
			}

			if (!dns_name_isabsolute(name)) {
				parser_error(ISC_FALSE,
					     "name (%s) must be an "
					     "absolute (not relative) name.",
					     $4);
				ok = ISC_FALSE;
			}

			if ($3 == DNS_SSUMATCHTYPE_WILDCARD &&
			    !dns_name_iswildcard(name)) {
				parser_error(ISC_FALSE,
					     "name (%s) has no wildcard "
					     "character ",
					     $4);
				ok = ISC_FALSE;
			}
		}

		isc_mem_free(memctx, $2);
		isc_mem_free(memctx, $4);

		if (ok) {
			$$.grant = $1;
			$$.ident = identity;
			$$.matchtype = $3;
			$$.name = name;
			$$.rdatatypes = $5;
		} else {
			if (identity != NULL) {
				dns_name_free(identity, memctx);
				isc_mem_put(memctx, identity,
					    sizeof *identity);
			}

			if (name != NULL) {
				dns_name_free(name, memctx);
				isc_mem_put(memctx, name, sizeof *name);
			}

			YYABORT;
		}
	};

grantp: L_GRANT {
		$$ = ISC_TRUE;
	}
	| L_DENY {
		$$ = ISC_FALSE;
	};

grant_match_type: L_NAME {
		$$ = DNS_SSUMATCHTYPE_NAME;
	}
	| L_SUBDOMAIN {
		$$ = DNS_SSUMATCHTYPE_SUBDOMAIN;
	}
	| L_WILDCARD {
		$$ = DNS_SSUMATCHTYPE_WILDCARD;
	}
	| L_SELF {
		$$ = DNS_SSUMATCHTYPE_SELF;
	};

rdatatype_list: /* nothing */
	{
		$$.idx = 0;
	}
	| rdatatype_list rdatatype {
		$1.types[$1.idx++] = $2;
		$$ = $1;
	};

rdatatype: any_string {
		isc_textregion_t reg;
		dns_rdatatype_t ty;

		reg.base = $1;
		reg.length = strlen($1);
		
		tmpres = dns_rdatatype_fromtext(&ty, &reg);
		if (tmpres != DNS_R_SUCCESS) {
			parser_error(ISC_TRUE, "unknown rdatatype.");
			YYABORT;
		}
		
		isc_mem_free(memctx, $1);
		$$ = ty;
	};

	       
	

	


/*
  key
  trusted-keys
  server
  options {
     forwarders
     blackhole
     lame-ttl
     max-ncache-ttl
     min-roots
     cleaning-interval
  }		 
*/
		
/*
 * ACLs
 */

acl_stmt: L_ACL any_string L_LBRACE address_match_list L_RBRACE
	{
		dns_c_acl_t *acl;

		INSIST(currcfg->acls != NULL);
			
		tmpres = dns_c_acl_new(currcfg->acls,
				       $2, ISC_FALSE, &acl);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to create acl %s", $2);
			YYABORT;
		}
		
		dns_c_acl_setipml(acl, $4, ISC_FALSE);
			
		isc_mem_free(memctx, $2);
	}
	;


/*
 * Zones
 */

domain_name: L_QSTRING
	{
		$$ = $1;
	}
	;

/*
 * ``type'' is no longer optional and must be the first statement in the 
 * zone block.
 */
zone_stmt: L_ZONE domain_name optional_class L_LBRACE L_TYPE zone_type L_EOS
	{
		dns_c_zone_t *zone;

                if (currcfg->zlist == NULL) {
                        tmpres = dns_c_zonelist_new(currcfg->mem,
                                                    &currcfg->zlist);
                        if (tmpres != ISC_R_SUCCESS) {
                                isc_log_write(dns_lctx,
                                              DNS_LOGCATEGORY_CONFIG,
                                              DNS_LOGMODULE_CONFIG,
                                              ISC_LOG_ERROR,
                                              "Failed to create zone list");
                                YYABORT;
                        }
                }

		/* XXX internal name support needed! */
                tmpres = dns_c_zone_new(currcfg->mem,
                                        $6, $3, $2, $2, &zone);
                if (tmpres != ISC_R_SUCCESS) {
                        isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                      DNS_LOGMODULE_CONFIG,
                                      ISC_LOG_ERROR,
                                      "Error creating new zone.");
                        YYABORT;
                }

                if (currcfg->options != NULL) {
                        zone->afteropts = ISC_TRUE;
                }

		tmpres = dns_c_zonelist_addzone(currcfg->zlist, zone);
		if (tmpres != ISC_R_SUCCESS) {
			dns_c_zone_detach(&zone);
                        isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                      DNS_LOGMODULE_CONFIG,
                                      ISC_LOG_ERROR,
                                      "Error adding new zone to list.");
                        YYABORT;
		}

		dns_c_ctx_setcurrzone(currcfg, zone);
		
		isc_mem_free(memctx, $2);
	} optional_zone_options_list L_RBRACE {
		dns_c_zone_t *zone;
		dns_c_view_t *view;
		
		zone = dns_c_ctx_getcurrzone(currcfg);
		view = dns_c_ctx_getcurrview(currcfg);

		zone->view = view;

		if (view != NULL) {
			dns_c_view_addzone(view, zone);
		}

		dns_c_ctx_setcurrzone(currcfg, NULL);

		if (callbacks != NULL && callbacks->zonecbk != NULL) {
			tmpres = callbacks->zonecbk(currcfg,
						    zone,
						    view,
						    callbacks->zonecbkuap);
			if (tmpres != ISC_R_SUCCESS) {
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
					      DNS_LOGMODULE_CONFIG,
					      ISC_LOG_ERROR,
				      "zone configuration for '%s' failed: %s",
					      zone->name,
					      isc_result_totext(tmpres));
				YYABORT;
			}

			dns_c_zonelist_rmzone(currcfg->zlist, zone);
		}
	}
	| L_ZONE domain_name optional_class L_LBRACE zone_non_type_keywords
	{
		parser_error(ISC_FALSE,
			     "first statement in a zone definition must "
			     "be ``type''");
		YYABORT;
	}
	| L_ZONE domain_name
	{
		parser_warning(ISC_FALSE,
			       "references to zones not implemented yet.");
	}
	;

optional_zone_options_list: /* Empty */
	| zone_option_list 
	;

class_name: any_string
	{
		isc_textregion_t reg;
		dns_rdataclass_t cl;

		if (strcmp($1, "*") == 0) {
			cl = dns_rdataclass_any;
		} else {
			reg.base = $1;
			reg.length = strlen($1);
			
			tmpres = dns_rdataclass_fromtext(&cl, &reg);
			if (tmpres != DNS_R_SUCCESS) {
				parser_error(ISC_TRUE,
					     "unknown class assuming ``*''.");
				cl = dns_rdataclass_any;
			}
		}
		
		isc_mem_free(memctx, $1);
		$$ = cl;
	}

optional_class: /* Empty */
	{
		$$ = dns_rdataclass_in;
	}
	| class_name
	;

zone_type: L_MASTER
	{
		$$ = dns_c_zone_master;
	}
	| L_SLAVE
	{
		$$ = dns_c_zone_slave;
	}
	| L_HINT
	{
		$$ = dns_c_zone_hint;
	}
	| L_STUB
	{
		$$ = dns_c_zone_stub;
	}
	| L_FORWARD
	{
		$$ = dns_c_zone_forward;
	}
	;



zone_option_list: zone_option L_EOS
	| zone_option_list zone_option L_EOS
	;


/*
 * This rule is used in enforcing the requirement that zone_type must be
 * the first element in a zone statement
 */
zone_non_type_keywords: L_FILE | L_FILE_IXFR | L_IXFR_TMP | L_MASTERS |
	L_TRANSFER_SOURCE | L_CHECK_NAMES | L_ALLOW_UPDATE |
	L_ALLOW_UPDATE_FORWARDING | L_ALLOW_QUERY |
	L_ALLOW_TRANSFER | L_FORWARD | L_FORWARDERS | L_MAX_TRANSFER_TIME_IN |
	L_TCP_CLIENTS | L_RECURSIVE_CLIENTS | L_GRANT | L_DENY |
	L_MAX_TRANSFER_TIME_OUT | L_MAX_TRANSFER_IDLE_IN |
	L_MAX_TRANSFER_IDLE_OUT | L_MAX_LOG_SIZE_IXFR | L_NOTIFY |
	L_MAINTAIN_IXFR_BASE | L_PUBKEY | L_ALSO_NOTIFY | L_DIALUP
	;


zone_option: L_FILE L_QSTRING
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setfile(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone filename.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone file name");
			YYABORT;
		}
		isc_mem_free(memctx, $2);
	}
	| L_FILE_IXFR L_QSTRING
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setixfrbase(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining ixfr-base.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone ixfr_base.");
			YYABORT;
		}
		isc_mem_free(memctx, $2);
	}
	| L_IXFR_TMP L_QSTRING
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setixfrtmp(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining ixfr-tmp-file.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone ixfr_tmp-file.");
			YYABORT;
		}
		isc_mem_free(memctx, $2);
	}
	| L_MASTERS maybe_zero_port L_LBRACE master_in_addr_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setmasterport(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone master's port.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone master port.");
			YYABORT;
		}
		

		tmpres = dns_c_zone_setmasterips(zone,
						 $4, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone masters ips.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone masters ips.");
			YYABORT;
		}
	}
	| L_TRANSFER_SOURCE maybe_wild_ip4_only_addr
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_settransfersource(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone transfer-source.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone transfer-source.");
			YYABORT;
		}
	}
	| L_TRANSFER_SOURCE_V6 maybe_wild_ip6_only_addr
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_settransfersourcev6(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone transfer-source-v6.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone transfer-source-v6.");
			YYABORT;
		}
	}
	| L_CHECK_NAMES check_names_opt
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setchecknames(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone check-names.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone check-names.");
			YYABORT;
		}
	}
	| L_ALLOW_UPDATE L_LBRACE address_match_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setallowupd(zone,
						$3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone allow-update.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone allow-update.");
			YYABORT;
		}
	}
	| L_ALLOW_UPDATE_FORWARDING L_LBRACE address_match_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setallowupdateforwarding(zone,
							     $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone "
				       "allow-update-forwarding.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone "
				     "allow-update-forwarding.");
			YYABORT;
		}
	}
	| L_ALLOW_QUERY L_LBRACE address_match_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setallowquery(zone,
						  $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone allow-query.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone allow-query.");
			YYABORT;
		}
	}
	| L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setallowtransfer(zone,
						     $3, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone allow-transfer.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone allow-transfer.");
			YYABORT;
		}
	}
	| L_FORWARD zone_forward_opt
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setforward(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone forward.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone forward.");
			YYABORT;
		}
	}
	| L_FORWARDERS L_LBRACE opt_zone_forwarders_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);
		dns_c_iplist_t *iplist;
		
		INSIST(zone != NULL);

		if ($3 == NULL) {	/* user defined empty list */
			tmpres = dns_c_iplist_new(currcfg->mem,
						  5, &iplist);
			if (tmpres != ISC_R_SUCCESS) {
				parser_error(ISC_TRUE,
					     "failed to create new zone "
					     "iplist");
				YYABORT;
			}
		} else {
			iplist = $3;
		}
		
		tmpres = dns_c_zone_setforwarders(zone,
						  iplist, ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone forwarders.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone forwarders.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_TIME_IN L_INTEGER
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_zone_setmaxtranstimein(zone, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone "
				       "max-transfer-time-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone "
				     "max-transfer-time-in.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_TIME_OUT L_INTEGER
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_zone_setmaxtranstimeout(zone, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone "
				       "max-transfer-time-out.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone "
				     "max-transfer-time-out.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_IDLE_IN L_INTEGER
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_zone_setmaxtransidlein(zone, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone "
				       "max-transfer-idle-in.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone "
				     "max-transfer-idle-in.");
			YYABORT;
		}
	}
	| L_MAX_TRANSFER_IDLE_OUT L_INTEGER
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		if ( int_too_big($2, 60) ) {
			parser_error(ISC_FALSE,
				     "integer value too big: %u", $2);
			YYABORT;
		}
		
		tmpres = dns_c_zone_setmaxtransidleout(zone, $2 * 60);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone "
				       "max-transfer-idle-out.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone "
				     "max-transfer-idle-out.");
			YYABORT;
		}
	}
	| L_MAX_LOG_SIZE_IXFR L_INTEGER
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setmaxixfrlog(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone	 max-ixfr-log-size.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone max-ixfr-log-size.");
			YYABORT;
		}
	}
	| L_NOTIFY yea_or_nay
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setnotify(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone notify.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone notify.");
			YYABORT;
		}
	}
	| L_MAINTAIN_IXFR_BASE yea_or_nay
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setmaintixfrbase(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone maintain-ixfr-base.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone maintain-ixfr-base.");
			YYABORT;
		}
	}
	| L_PUBKEY L_INTEGER L_INTEGER L_INTEGER L_QSTRING
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);
		dns_c_pubkey_t *pubkey;
		
		INSIST(zone != NULL);

		tmpres = dns_c_pubkey_new(currcfg->mem, $2,
					  $3, $4, $5, &pubkey);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "failed to create a zone pubkey");
			YYABORT;
		}
		
		tmpres = dns_c_zone_addpubkey(zone, pubkey,
					      ISC_FALSE);
		if (tmpres != ISC_R_SUCCESS) {
			dns_c_pubkey_delete(&pubkey);
			parser_error(ISC_FALSE,
				     "failed to add a zone pubkey.");
			YYABORT;
		}

		isc_mem_free(memctx, $5);
	}
	| L_ALSO_NOTIFY L_LBRACE notify_in_addr_list L_RBRACE
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setalsonotify(zone, $3,
						  ISC_FALSE);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone also-notify.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone also-notify.");
			YYABORT;
		}
	}
	| L_DIALUP yea_or_nay
	{
		dns_c_zone_t *zone = dns_c_ctx_getcurrzone(currcfg);

		INSIST(zone != NULL);

		tmpres = dns_c_zone_setdialup(zone, $2);
		if (tmpres == ISC_R_EXISTS) {
			parser_warning(ISC_FALSE,
				       "redefining zone dialup.");
		} else if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_FALSE,
				     "failed to set zone dialup.");
			YYABORT;
		}
	}
	| zone_ssu_stmt
	;


master_in_addr_list: in_addr_list
	;

notify_in_addr_list: opt_in_addr_list
	;

ip4_address: L_IP4ADDR
	{
		isc_sockaddr_fromin(&$$, &$1, 0);
	}
	;

ip6_address: L_IP6ADDR
	{
		isc_sockaddr_fromin6(&$$, &$1, 0);
	};


ip_address: ip4_address | ip6_address
	;
	
in_addr_elem: ip_address
	;

opt_in_addr_list: /* nothing */
	{
		dns_c_iplist_t *list;

		tmpres = dns_c_iplist_new(currcfg->mem, 5, &list);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "failed to create new iplist");
			YYABORT;
		}

		$$ = list;
	}
	| in_addr_list
	;

in_addr_list: in_addr_elem L_EOS
	{
		dns_c_iplist_t *list;

		tmpres = dns_c_iplist_new(currcfg->mem, 5, &list);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "failed to create new iplist");
			YYABORT;
		}

		tmpres = dns_c_iplist_append(list, $1);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "failed to append master address");
			YYABORT;
		}
		
		$$ = list;
	}
	| in_addr_list in_addr_elem L_EOS
	{
		tmpres = dns_c_iplist_append($1, $2);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error(ISC_TRUE,
				     "failed to append master address");
			YYABORT;
		}

		$$ = $1;
	}
	;

zone_forward_opt: L_ONLY
	{
		$$ = dns_c_forw_only;
	}
	| L_FIRST
	{
		$$ = dns_c_forw_first;
	}
	;

opt_zone_forwarders_list: opt_in_addr_list
	;

/*
 * Trusted Key statement
 */

trusted_keys_stmt: L_TRUSTED_KEYS
        {
                dns_c_tkeylist_t *newlist;
                
                tmpres = dns_c_ctx_gettrustedkeys(currcfg,
                                                  &newlist);
                if (tmpres == ISC_R_NOTFOUND) {
                        tmpres = dns_c_tkeylist_new(currcfg->mem, &newlist);
                        if (tmpres != ISC_R_SUCCESS) {
                                isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                              DNS_LOGMODULE_CONFIG,
                                              ISC_LOG_ERROR,
                                              "Failed to create trusted key"
                                              " list.");
                                YYABORT;
                        }

                        tmpres = dns_c_ctx_settrustedkeys(currcfg,
                                                          newlist,
                                                          ISC_FALSE);
                        if (tmpres != ISC_R_SUCCESS) {
                                isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                              DNS_LOGMODULE_CONFIG,
                                              ISC_LOG_ERROR,
                                              "Failed to set trusted keys");
                                YYABORT;
                        }
                }
        } L_LBRACE trusted_keys_list L_RBRACE
        ;

trusted_keys_list: trusted_key L_EOS
	| trusted_keys_list trusted_key L_EOS
	;


trusted_key: domain_name L_INTEGER L_INTEGER L_INTEGER L_QSTRING
        {
                dns_c_tkey_t *tkey;
                dns_c_tkeylist_t *list;

                tmpres = dns_c_ctx_gettrustedkeys(currcfg, &list);
                if (tmpres != ISC_R_SUCCESS) {
                        isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                      DNS_LOGMODULE_CONFIG,
                                      ISC_LOG_ERROR,
                                      "No trusted key list defined!");
                        YYABORT;
                }

                tmpres = dns_c_tkey_new(currcfg->mem, $1, $2, $3,
                                        $4, $5, &tkey);
                if (tmpres != ISC_R_SUCCESS) {
                        isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                      DNS_LOGMODULE_CONFIG,
                                      ISC_LOG_ERROR,
                                      "Failed to create trusted key");
                        YYABORT;
                }

                tmpres = dns_c_tkeylist_append(list,
                                               tkey, ISC_FALSE);
                if (tmpres != ISC_R_SUCCESS) {
                        isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                                      DNS_LOGMODULE_CONFIG,
                                      ISC_LOG_ERROR,
                                      "Failed to append trusted key.");
                        YYABORT;
                }

                isc_mem_free(memctx, $1);
                isc_mem_free(memctx, $5);
        }
        ;



/*
 * Misc.
 */

in_port: L_INTEGER
	{
		if ($1 < 0 || $1 > 65535) {
			parser_warning(ISC_TRUE,
			  "invalid IP port number '%d'; setting port to 0",
				       (int)$1);
			$1 = 0;
		} else {
			$$ = $1;
		}
	}
	;


any_string: L_STRING
	| L_QSTRING
	;

maybe_eos: | L_EOS ;

%%

static int		intuit_token(const char *string);

static isc_boolean_t	is_ip4addr(const char *string, struct in_addr *addr);
static isc_boolean_t	is_ip6addr(const char *string, struct in6_addr *addr);
static isc_result_t	keyword_init(void);
static char *		token_to_text(int token, YYSTYPE lval);
static int		token_value(isc_token_t *token,
				    isc_symtab_t *symtable);
static void		init_action(void);

static YYSTYPE		lastyylval;
static int		lasttoken;


/*
 * Definition of all unique keyword tokens to be recognised by the
 * lexer. All the ``L_'' tokens defined in parser.y must be defined here too.
 */
struct token
{
	char *token;
	int yaccval;
};

static struct token keyword_tokens [] = {
	{ "{",				L_LBRACE },
	{ "}",				L_RBRACE },
	{ ";",				L_EOS },
	{ "/",				L_SLASH },
	{ "!",				L_BANG },

	{ "acl",			L_ACL },
	{ "address",			L_ADDRESS },
	{ "algorithm",			L_ALGID },
	{ "allow",			L_ALLOW },
	{ "allow-query",		L_ALLOW_QUERY },
	{ "allow-transfer",		L_ALLOW_TRANSFER },
	{ "allow-recursion",		L_ALLOW_RECURSION },
	{ "allow-update",		L_ALLOW_UPDATE },
	{ "allow-update-forwarding",	L_ALLOW_UPDATE_FORWARDING },
	{ "also-notify",		L_ALSO_NOTIFY },
	{ "auth-nxdomain",		L_AUTH_NXDOMAIN },
	{ "blackhole",			L_BLACKHOLE },
	{ "bogus",			L_BOGUS },
	{ "category",			L_CATEGORY },
	{ "class",			L_CLASS },
	{ "channel",			L_CHANNEL },
	{ "check-names",		L_CHECK_NAMES },
	{ "cleaning-interval",		L_CLEAN_INTERVAL },
	{ "controls",			L_CONTROLS },
	{ "coresize",			L_CORESIZE },
	{ "datasize",			L_DATASIZE },
	{ "deallocate-on-exit",		L_DEALLOC_ON_EXIT },
	{ "debug",			L_DEBUG },
	{ "default",			L_DEFAULT },
	{ "dialup",			L_DIALUP },
	{ "directory",			L_DIRECTORY },
	{ "dump-file",			L_DUMP_FILE },
	{ "dynamic",			L_DYNAMIC },
	{ "expert-mode",		L_EXPERT_MODE },
	{ "fail",			L_FAIL },
	{ "fake-iquery",		L_FAKE_IQUERY },
	{ "false",			L_FALSE },
	{ "fetch-glue",			L_FETCH_GLUE },
	{ "file",			L_FILE },
	{ "files",			L_FILES },
	{ "first",			L_FIRST },
	{ "forward",			L_FORWARD },
	{ "forwarders",			L_FORWARDERS },
	{ "grant", 			L_GRANT },
	{ "deny", 			L_DENY },
	{ "subdomain", 			L_SUBDOMAIN },
	{ "domain", 			L_DOMAIN },
	{ "self", 			L_SELF },
	{ "wildcard", 			L_WILDCARD },
	{ "group",			L_GROUP },
	{ "has-old-clients",		L_HAS_OLD_CLIENTS },
	{ "heartbeat-interval",		L_HEARTBEAT },
	{ "hint",			L_HINT },
	{ "host-statistics",		L_HOSTSTATS },
	{ "if-no-answer",		L_IF_NO_ANSWER },
	{ "if-no-domain",		L_IF_NO_DOMAIN },
	{ "ignore",			L_IGNORE },
	{ "include",			L_INCLUDE },
	{ "inet",			L_INET },
	{ "interface-interval",		L_INTERFACE_INTERVAL },
	{ "ixfr-base",			L_FILE_IXFR },
	{ "ixfr-tmp-file",		L_IXFR_TMP },
	{ "key",			L_SEC_KEY },
	{ "keys",			L_KEYS },
	{ "listen-on",			L_LISTEN_ON },
	{ "logging",			L_LOGGING },
	{ "maintain-ixfr-base",		L_MAINTAIN_IXFR_BASE },
	{ "many-answers",		L_MANY_ANSWERS },
	{ "master",			L_MASTER },
	{ "masters",			L_MASTERS },
	{ "max-ixfr-log-size",		L_MAX_LOG_SIZE_IXFR },
	{ "max-ncache-ttl",		L_MAX_NCACHE_TTL },
	{ "max-transfer-time-in",	L_MAX_TRANSFER_TIME_IN },
	{ "max-transfer-time-out",	L_MAX_TRANSFER_TIME_OUT },
	{ "max-transfer-idle-in",	L_MAX_TRANSFER_IDLE_IN },
	{ "max-transfer-idle-out",	L_MAX_TRANSFER_IDLE_OUT },
	{ "memstatistics-file",		L_MEMSTATS_FILE },
	{ "multiple-cnames",		L_MULTIPLE_CNAMES },
	{ "name",			L_NAME },
	{ "named-xfer",			L_NAMED_XFER },
	{ "no",				L_NO },
	{ "notify",			L_NOTIFY },
	{ "null",			L_NULL_OUTPUT },
	{ "one-answer",			L_ONE_ANSWER },
	{ "only",			L_ONLY },
	{ "order",			L_ORDER },
	{ "options",			L_OPTIONS },
	{ "owner",			L_OWNER },
	{ "perm",			L_PERM },
	{ "pid-file",			L_PIDFILE },
	{ "port",			L_PORT },
	{ "print-category",		L_PRINT_CATEGORY },
	{ "print-severity",		L_PRINT_SEVERITY },
	{ "print-time",			L_PRINT_TIME },
        { "provide-ixfr", 		L_PROVIDE_IXFR },
	{ "pubkey",			L_PUBKEY },
	{ "query-source",		L_QUERY_SOURCE },
	{ "query-source-v6",		L_QUERY_SOURCE_V6 },
	{ "request-ixfr",		L_REQUEST_IXFR },
	{ "rfc2308-type1",		L_RFC2308_TYPE1 },
	{ "rrset-order",		L_RRSET_ORDER },
	{ "recursion",			L_RECURSION },
	{ "recursive-clients",		L_RECURSIVE_CLIENTS },
	{ "response",			L_RESPONSE },
	{ "secret",			L_SECRET },
	{ "server",			L_SERVER },
	{ "severity",			L_SEVERITY },
	{ "size",			L_SIZE },
	{ "slave",			L_SLAVE },
	{ "sortlist",			L_SORTLIST },
	{ "stacksize",			L_STACKSIZE },
	{ "statistics-file",		L_STATS_FILE },
	{ "statistics-interval",	L_STATS_INTERVAL },
	{ "stub",			L_STUB },
	{ "support-ixfr",		L_SUPPORT_IXFR },
	{ "syslog",			L_SYSLOG },
	{ "tcp-clients",		L_TCP_CLIENTS },
	{ "tkey-domain",		L_TKEY_DOMAIN },
	{ "tkey-dhkey",			L_TKEY_DHKEY },
	{ "topology",			L_TOPOLOGY },
	{ "transfer-format",		L_TRANSFER_FORMAT },
	{ "transfer-source",		L_TRANSFER_SOURCE },
	{ "transfer-source-v6",		L_TRANSFER_SOURCE_V6 },
	{ "transfers",			L_TRANSFERS },
	{ "transfers-in",		L_TRANSFERS_IN },
	{ "transfers-out",		L_TRANSFERS_OUT },
	{ "transfers-per-ns",		L_TRANSFERS_PER_NS },
	{ "true",			L_TRUE },
	{ "trusted-keys",		L_TRUSTED_KEYS },
	{ "type",			L_TYPE },
	{ "unix",			L_UNIX },
	{ "unlimited",			L_UNLIMITED },
	{ "use-id-pool",		L_USE_ID_POOL },
	{ "use-ixfr",			L_USE_IXFR },
	{ "version",			L_VERSION },
	{ "versions",			L_VERSIONS },
	{ "view",			L_VIEW },
	{ "warn",			L_WARN },
	{ "yes",			L_YES },
	{ "zone",			L_ZONE },

	{ NULL, 0 }
};


static struct token class_symbol_tokens[] = {
	{ "IN", dns_rdataclass_in },
#if 0					/* XXX expand */
	{ "CHAOS", dns_rdataclass_chaos },
	{ "HS", dns_rdataclass_hs },
	{ "HESIOD", dns_rdataclass_hs },
#endif
	{ "ANY", dns_rdataclass_any },
	{ "NONE", dns_rdataclass_none },
	{ NULL, 0 }
};


static isc_once_t once = ISC_ONCE_INIT;


static void
init_action(void)
{
	isc_mutex_init(&yacc_mutex);
}


/*
 * XXX Need a parameter to specify where error messages should go (syslog, 
 * FILE, /dev/null etc.) Also some way to tell the function to obey logging 
 * statments as appropriate.
 */
  
isc_result_t
dns_c_parse_namedconf(const char *filename, isc_mem_t *mem,
		      dns_c_ctx_t **configctx, dns_c_cbks_t *cbks)
{
	isc_result_t res;
	const char *funcname = "dns_parse_namedconf";

	RUNTIME_CHECK(isc_once_do(&once, init_action) == ISC_R_SUCCESS);
	
	/* Lock down whole parser. */
	if (isc_mutex_lock(&yacc_mutex) != ISC_R_SUCCESS) {
		return (ISC_R_UNEXPECTED);
	}

	REQUIRE(currcfg == NULL);
	REQUIRE(filename != NULL);
	REQUIRE(*filename != '\0');
	REQUIRE(configctx != NULL);
	INSIST(mylexer == NULL);
	INSIST(memctx == NULL);
	INSIST(keywords == NULL);
	INSIST(callbacks == NULL);

#if 1
	if (getenv("DEBUG_LEXER") != NULL) { /* XXX debug */
		debug_lexer++;
	}
#endif	

	specials['{'] = 1;
	specials['}'] = 1;
	specials[';'] = 1;
	specials['/'] = 1;
	specials['"'] = 1;
	specials['!'] = 1;
#if 0
	specials['*'] = 1;
#endif


	/*
	 * This memory context is only used by the lexer routines (and must 
	 * stay that way). Any memory that must live past the return of
	 * yyparse() must be allocated via the 'mem' parameter to this
	 * function.
	 */
	res = isc_mem_create(0, 0, &memctx);
	if (res != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "%s: Error creating mem context.",
			      funcname);
		goto done;
	}

	res = keyword_init();
	if (res != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "%s: Error initializing keywords.",
			      funcname);
		goto done;
	}

	res = dns_c_ctx_new(mem, &currcfg);
	if (res != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "%s: Error creating config context.",
			      funcname);
		goto done;
	}

	res = isc_lex_create(memctx, CONF_MAX_IDENT, &mylexer);
	if (res != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "%s: Error creating lexer",
			      funcname);
		goto done;
	}
	
	isc_lex_setspecials(mylexer, specials);
	isc_lex_setcomments(mylexer, (ISC_LEXCOMMENT_C |
				      ISC_LEXCOMMENT_CPLUSPLUS |
				      ISC_LEXCOMMENT_SHELL));

	res = isc_lex_openfile(mylexer, (char *)filename) ; /* remove const */
	if (res != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
			      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
			      "%s: Error opening file %s.",
			      funcname, filename);
		goto done;
	}

	callbacks = cbks;
	
	if (yyparse() != 0) {
		res = ISC_R_FAILURE;

		/* Syntax errors in the config file make it very difficult
		 * to clean up memory properly (which causes assertion
		 * failure when the memory manager is destroyed).
		 */
		isc_mem_destroy_check(memctx, ISC_FALSE);

                dns_c_ctx_delete(&currcfg);
                currcfg = NULL;
        } else {
                res = ISC_R_SUCCESS;
        }


 done:
	if (mylexer != NULL)
		isc_lex_destroy(&mylexer);

	isc_symtab_destroy(&keywords);

	isc_mem_destroy(&memctx);

	if (res == ISC_R_SUCCESS) {
		res = dns_c_checkconfig(currcfg);
		if (res != ISC_R_SUCCESS) {
			dns_c_ctx_delete(&currcfg);
		}
	}
	
	*configctx = currcfg;

	callbacks = NULL;
	currcfg = NULL;
	memctx = NULL;
	mylexer = NULL;

	RUNTIME_CHECK(isc_mutex_unlock(&yacc_mutex) == ISC_R_SUCCESS);

	return (res);
}



/***
 *** PRIVATE
 ***/

static isc_result_t
keyword_init(void)
{
	struct token *tok;
	isc_symvalue_t symval;

	RUNTIME_CHECK(isc_symtab_create(memctx, 97 /* prime < 100 */,
					NULL, NULL, ISC_FALSE,
					&keywords) == ISC_R_SUCCESS);


	/* Stick all the keywords into the main symbol table. */
	for (tok = &keyword_tokens[0] ; tok->token != NULL ; tok++) {
		symval.as_integer = tok->yaccval;
		RUNTIME_CHECK(isc_symtab_define(keywords, tok->token,
						KEYWORD_SYM_TYPE, symval,
						isc_symexists_reject) ==
			      ISC_R_SUCCESS);
	}

	/* Now the class names */
	for (tok = &class_symbol_tokens[0] ; tok->token != NULL ; tok++) {
		symval.as_integer = tok->yaccval;
		RUNTIME_CHECK(isc_symtab_define(keywords, tok->token,
						CLASS_SYM_TYPE, symval,
						isc_symexists_reject) ==
			      ISC_R_SUCCESS);
	}

	return (ISC_R_SUCCESS);
}



static int
yylex(void)
{
	isc_token_t token;
	isc_result_t res;
	int options = (ISC_LEXOPT_EOF |
		       ISC_LEXOPT_NUMBER |
		       ISC_LEXOPT_QSTRING |
		       ISC_LEXOPT_NOMORE);

	INSIST(mylexer != NULL);

	res = isc_lex_gettoken(mylexer, options, &token);

	switch(res) {
	case ISC_R_SUCCESS:
		res = token_value(&token, keywords); /* modifies yylval */
		break;

	case ISC_R_EOF:
		res = 0;
		break;

	case ISC_R_UNBALANCED:
		parser_error(ISC_TRUE,
			     "%s: %d: unbalanced parentheses",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	case ISC_R_NOSPACE:
		parser_error(ISC_TRUE,
			     "%s: %d: token too big.",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	case ISC_R_UNEXPECTEDEND:
		parser_error(ISC_TRUE,
			     "%s: %d: unexpected EOF",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	default:
		parser_error(ISC_TRUE,
			     "%s: %d unknown lexer error (%d)",
			     isc_lex_getsourcename(mylexer),
			     (int)isc_lex_getsourceline(mylexer),
			     (int)res);
		res = -1;
		break;
	}


	lastyylval = yylval;
	lasttoken = res;

	return (res);
}



static char *
token_to_text(int token, YYSTYPE lval) {
	static char buffer[1024];
	char *tk;

	/* Yacc keeps token numbers above 128, it seems. */
	if (token < 128) {
		if (token == 0)
			strncpy(buffer, "<end of file>", sizeof buffer);
		else
			if ((unsigned int) sprintf(buffer, "'%c'", token)
			    >= sizeof buffer) {
				abort();
			}
	} else {
		switch (token) {
		case L_STRING:
			if ((unsigned int) sprintf(buffer, "'%s'",
						   lval.text) >=
			    sizeof buffer) {
				abort();
			}
			break;
		case L_QSTRING:
			if ((unsigned int) sprintf(buffer, "\"%s\"",
						   lval.text) >=
			    sizeof buffer) {
				abort();
			}
			break;
		case L_IP6ADDR:
			strcpy(buffer, "UNAVAILABLE-IPV6-ADDRESS");
			inet_ntop(AF_INET6, lval.ip6_addr.s6_addr,
				  buffer, sizeof buffer);
			break;
		case L_IP4ADDR:
			strcpy(buffer, "UNAVAILABLE-IPV4-ADDRESS");
			inet_ntop(AF_INET, &lval.ip4_addr.s_addr,
				  buffer, sizeof buffer);
			break;
		case L_INTEGER:
			sprintf(buffer, "%lu", (unsigned long)lval.ul_int);
			break;
		case L_END_INCLUDE:
			strcpy (buffer, "<end of include>");
			break;
		default:
			tk = token_to_keyword(token);
			if (tk == NULL) {
				sprintf(buffer, "UNKNOWN-TOKEN-TYPE (%d)",
					(int)token);
			} else {
				strncpy(buffer, tk, sizeof buffer - 1);
				buffer[sizeof buffer - 1] = '\0';
			}
			break;
		}
	}

	return (buffer);
}

static char *
token_to_keyword(int token)
{
	int i;
	
	for (i = 0 ; keyword_tokens[i].token != NULL ; i++) {
		if (keyword_tokens[i].yaccval == token) {
			break;
		}
	}

	return (keyword_tokens[i].token);
}
	


static void
parser_complain(isc_boolean_t is_warning, isc_boolean_t print_last_token,
		const char *format, va_list args)
{
        static char where[ISC_DIR_PATHMAX + 100];
        static char message[2048];
	int level = ISC_LOG_ERROR;
        const char *filename = isc_lex_getsourcename(mylexer);
        int lineno = isc_lex_getsourceline(mylexer);

        /*
         * We can't get a trace of the include files we may be nested in
         * (lex.c has the structures hidden). So we only report the current
         * file.
         */
        if (filename == NULL) {
                filename = "(none)";
        }

	if (is_warning) {
		level = ISC_LOG_WARNING;
	}

	sprintf(where, "%s:%d: ", filename, lineno);
	if ((unsigned int)vsprintf(message, format, args) >= sizeof message)
		FATAL_ERROR(__FILE__, __LINE__,
			    "error message would overflow");

	if (print_last_token) {
		if (dns_lctx != NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				       DNS_LOGMODULE_CONFIG, level,
				       "%s%s near `%s'", where, message,
				       token_to_text(lasttoken, lastyylval));
		} else {
			fprintf(stderr, "%s%s near `%s'\n", where, message,
				token_to_text(lasttoken, lastyylval));
		}
	} else {
		if (dns_lctx != NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				       DNS_LOGMODULE_CONFIG, level,
				       "%s%s", where, message);
		} else {
			fprintf(stderr, "%s%s\n", where, message);
		}
	}
}




/*
 * For reporting items that are semantic, but not syntactic errors
 */
static void
parser_error(isc_boolean_t lasttoken, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	parser_complain(ISC_TRUE, lasttoken, fmt, args);
	va_end(args);

	currcfg->errors++;
}


static void
parser_warning(isc_boolean_t lasttoken, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	parser_complain(ISC_FALSE, lasttoken, fmt, args);
	va_end(args);

	currcfg->warnings++;
}


static isc_boolean_t
int_too_big(isc_uint32_t base, isc_uint32_t mult) {
	isc_uint32_t max = UINT_MAX;

	if ((max / mult) < base) {
		return ISC_TRUE;
	} else {
		return ISC_FALSE;
	}
}


static void
yyerror(const char *string)
{
	parser_error(ISC_TRUE, string);
}



static int
token_value(isc_token_t *token, isc_symtab_t *symtable)
{
	int res = -1;
	const char *tokstring;
	char tmpident [2];
	isc_symvalue_t keywordtok;

	switch (token->type) {
	case isc_tokentype_unknown:
		if (debug_lexer) {
			fprintf(stderr, "unknown lexer token\n");
		}

		res = -1;
		break;

	case isc_tokentype_special:
	case isc_tokentype_string:
		if (token->type == isc_tokentype_special) {
			tmpident[0] = token->value.as_char;
			tmpident[1] = '\0';
			tokstring = tmpident;
		} else {
			tokstring = token->value.as_textregion.base;
		}

		res = isc_symtab_lookup(symtable, tokstring,
					KEYWORD_SYM_TYPE, &keywordtok);

		if (res != ISC_R_SUCCESS) {
			res = intuit_token(tokstring);
		} else {
			res = keywordtok.as_integer;
		}

		if (debug_lexer) {
			fprintf(stderr, "lexer token: %s : %s (%d)\n",
				(token->type == isc_tokentype_special ?
				 "special" : "string"), tokstring, res);
		}

		break;

	case isc_tokentype_number:
		yylval.ul_int = (isc_uint32_t)token->value.as_ulong;
		res = L_INTEGER;

		if(debug_lexer) {
			fprintf(stderr, "lexer token: number : %lu\n",
				(unsigned long)yylval.ul_int);
		}

		break;

	case isc_tokentype_qstring:
		yylval.text = isc_mem_strdup(memctx,
					     token->value.as_textregion.base);
		if (yylval.text == NULL) {
			res = -1;
		} else {
			res = L_QSTRING;
		}

		if (debug_lexer) {
			fprintf(stderr, "lexer token: qstring : \"%s\"\n",
				yylval.text);
		}

		break;

	case isc_tokentype_eof:
		res = isc_lex_close(mylexer);
		INSIST(res == ISC_R_NOMORE || res == ISC_R_SUCCESS);

		if (isc_lex_getsourcename(mylexer) == NULL) {
			/* the only way to tell that we
			 *  closed the main file and not an included file
			 */
			if (debug_lexer) {
				fprintf(stderr, "lexer token: EOF\n");
			}
			res = 0;
		} else {
			if (debug_lexer) {
				fprintf(stderr, "lexer token: EOF (main)\n");
			}
			res = L_END_INCLUDE;
		}
		break;

	case isc_tokentype_initialws:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: initial ws\n");
		}
		res = -1;
		break;

	case isc_tokentype_eol:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: eol\n");
		}
		res = -1;
		break;

	case isc_tokentype_nomore:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: nomore\n");
		}
		res = -1;
		break;
	}

	return (res);
}




static int
intuit_token(const char *string)
{
	int resval;

	if (is_ip4addr(string, &yylval.ip4_addr)) {
		resval = L_IP4ADDR;
	} else if (is_ip6addr(string, &yylval.ip6_addr)) {
		resval = L_IP6ADDR;
	} else {
		yylval.text = isc_mem_strdup(memctx, string);
		if (yylval.text == NULL) {
			resval = -1;
		} else {
			resval = L_STRING;
		}
	}

	return (resval);
}


/*
 * Conversion Routines
 */

static isc_boolean_t
unit_to_uint32(char *in, isc_uint32_t *out) {
	int c, units_done = 0;
	isc_uint32_t result = 0L;

	INSIST(in != NULL);

	for (; (c = *in) != '\0'; in++) {
		if (units_done)
			return (ISC_FALSE);
		if (isdigit(c)) {
			result *= 10;
			result += (c - '0');
		} else {
			switch (c) {
			case 'k':
			case 'K':
				result *= 1024;
				units_done = 1;
				break;
			case 'm':
			case 'M':
				result *= (1024*1024);
				units_done = 1;
				break;
			case 'g':
			case 'G':
				result *= (1024*1024*1024);
				units_done = 1;
				break;
			default:
				return (ISC_FALSE);
			}
		}
	}

	*out = result;
	return (ISC_TRUE);
}


static isc_boolean_t
is_ip6addr(const char *string, struct in6_addr *addr)
{
	if (inet_pton(AF_INET6, string, addr) != 1) {
		return ISC_FALSE;
	}
	return ISC_TRUE;
}



static isc_boolean_t
is_ip4addr(const char *string, struct in_addr *addr)
{
	char addrbuf[sizeof "xxx.xxx.xxx.xxx" + 1];
	const char *p = string;
	int dots = 0;
	char dot = '.';

	while (*p) {
		if (!isdigit(*p & 0xff) && *p != dot) {
			return (ISC_FALSE);
		} else if (!isdigit(*p & 0xff)) {
			dots++;
		}
		p++;
	}

	if (dots > 3) {
		return (ISC_FALSE);
	} else if (dots < 3) {
		if (dots == 1) {
			if (strlen(string) + 5 <= sizeof (addrbuf)) {
				strcpy(addrbuf, string);
				strcat(addrbuf, ".0.0");
			} else {
				return (ISC_FALSE);
			}
		} else if (dots == 2) {
			if (strlen(string) + 3 <= sizeof (addrbuf)) {
				strcpy(addrbuf, string);
				strcat(addrbuf, ".0");
			} else {
				return (ISC_FALSE);
			}
		}
	} else if (strlen(string) < sizeof addrbuf) {
		strcpy (addrbuf, string);
	} else {
		return (ISC_FALSE);
	}
	
	if (inet_pton(AF_INET, addrbuf, addr) != 1) {
		return ISC_FALSE;
	}
	return ISC_TRUE;
}
