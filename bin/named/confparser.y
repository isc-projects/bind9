%{
#if !defined(lint) && !defined(SABER)
static char rcsid[] = "$Id: confparser.y,v 1.4 1999/06/08 13:27:36 brister Exp $";
#endif /* not lint */

/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
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

/****
 **** MODULE INFO
 ****/

/*
 * This is the parser for the named.conf file. API is:
 *
 *	parser_init()
 *		To be called one time only to do global
 *		initialzation *before* calling isc_parse_configuration().
 *		Caller is responsible for thread locking.
 *
 *	parse_configuration()
 *		The main parsing routine. Will parse the config file and
 *		will return a structure containing all the relevant
 *		information. Only one thread can go through it at a time,
 *		and the function handles locking itself.
 *
 * MP:
 *
 *	Caller must prevent parallel calls.
 *
 * Reliability:
 *      
 *
 * Resources:
 *
 *	Uses memory allocaters provided by the caller.
 *
 * Security:
 *      
 *
 * Standards:
 *      
 */
 
#include <config.h>

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h> 
#include <limits.h>
#include <netinet/in.h>

#include <syslog.h>
 
#include <isc/assertions.h> 
#include <isc/mutex.h>
#include <isc/lex.h>
#include <isc/symtab.h>
#include <isc/error.h> 

#include "confparser.h" 
#include "zone.h"
#include "configctx.h"

static int onetime;
static isc_mutex_t yacc_mutex;

/* All these statics are protected by the above yacc_mutex */ 
static int seen_options;
static int seen_topology;
 
static isc_zonectx_t *currzonectx;
static isc_zoneinfo_t *currzone;
static isc_cfgctx_t *currcfg;
static const char *currfile;

static isc_mem_t *memctx;		/* used for internal allocations */
static isc_lex_t *mylexer;
static isc_symtab_t *keywords;
static isc_lexspecials_t specials;

/* Type keys used in symbol table element instances. */
static int keyword_type = 1;
static int class_sym_type = 2;
 

#define NS_DEFAULTPORT 53     /* XXX this should be imported NOT defined */

#define CONF_MAX_IDENT 1024
#define SYMTAB_SIZE 499			/* bigest prime less than 500 */

/* This should be sufficient to permit multiple parsers and lexers if needed */
#define yyparse confyyparse
#define yylex confyylex 

static void parser_error(char *fmt, ...);
static void parser_warning(char *fmt, ...);
static void print_msg(const char *fmt, va_list args);
static void free_textregion(isc_textregion_t region, isc_mem_t *mem);
static int intuit_token(isc_symtab_t *symtable, const char *string);
static isc_result_t symtable_init(void);

static void yyerror(const char *);
static int yylex(void);
static isc_result_t copy_textregion(isc_mem_t *mem,
				    isc_textregion_t region,
				    isc_textregion_t *newregion);
static int unit_to_ulong(char *in, unsigned long *out);
static void debug_print(const char *fmt, ...);
 
int yyparse(void);

static isc_result_t tmpres;
static int debug_lexer;
static int debugging_stuff;
 

%}

%union {
	isc_textregion_t	text;
	int			number;
	long			l_int;
	unsigned long		ul_int;
	isc_uint16_t		port_int;
	isc_zonet_t		ztype;
	struct in_addr		ip_addr;
	isc_boolean_t		boolean;
	isc_rrclass_t		rrclass;

	/* NOT IMPLEMENTED YET */
/*
	ip_match_element	ime;
	ip_match_list		iml;
	rrset_order_list	rol;
	rrset_order_element	roe;
	struct dst_key *	keyi;
	enum axfr_format	axfr_fmt;
*/
}

%token		L_LBRACE
%token		L_RBRACE
%token		L_EOS
%token		L_SLASH
%token		L_BANG
%token		L_STAR
%token		L_QUOTE

/* Misc */
%token <text>		L_STRING
%token <text>		L_QSTRING
%token <l_int>		L_INTEGER
%token <ip_addr>	L_IPADDR


%token		L_MASTER
%token		L_SLAVE
%token		L_SORTLIST
%token		L_HINT
%token		L_STUB
%token		L_FORWARD

%token 		L_INCLUDE
%token		L_END_INCLUDE

/* options statement */
%token		L_OPTIONS
%token		L_DIRECTORY
%token		L_DIRECTORY
%token		L_PIDFILE
%token		L_NAMED_XFER
%token		L_DUMP_FILE
%token		L_STATS_FILE
%token		L_MEMSTATS_FILE
%token		L_FAKE_IQUERY
%token		L_RECURSION
%token		L_FETCH_GLUE 
%token		L_QUERY_SOURCE
%token		L_LISTEN_ON
%token		L_PORT
%token		L_ACL
%token		L_ADDRESS
%token		L_ALGID
%token		L_ALLOW_QUERY
%token		L_ALLOW_TRANSFER
%token		L_ALLOW_UPDATE
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

%type <ul_int>		size_spec
%type <text>		any_string

%type <port_int>	in_port
%type <port_int>	maybe_wild_port
%type <port_int>	maybe_zero_port
%type <port_int>	maybe_port

%type <ip_addr>		maybe_wild_addr
%type <text>		facility_name
%type <number>		maybe_syslog_facility
%type <text>		channel_name
%type <text>		category_name

%type <rrclass>		ordering_class
%type <rrclass>		optional_class

/* Zone statements */
%token			L_ZONE
%token			L_TYPE
%token			L_FILE
%type <ztype>		zone_type


/* Items used for yes/no responses: */
%type	<boolean>	yea_or_nay
%token			L_YES
%token			L_TRUE
%token			L_NO
%token			L_FALSE

/* Miscellaneous items (used in several places): */

%%

config_file: statement_list
	{
		/* XXX Do post-read validations etc. */
	}
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
	| L_END_INCLUDE
	| error L_EOS
	| error L_END_INCLUDE
	;


include_stmt: L_INCLUDE L_QSTRING
	{
		/* XXX */
		fprintf(stderr,
			"include files are currently broken (memory leak)\n");
		exit(1);
		isc_lex_openfile(mylexer, $2.base);
		free_textregion($2, memctx);
	}
	;

options_stmt: L_OPTIONS
	{
		debug_print( "debug: getting options");
		if (seen_options) {
			parser_error("cannot redefine options");
			RUNTIME_CHECK(isc_cfg_erase_options(currcfg) ==
				      ISC_R_SUCCESS);
		}
	}
	L_LBRACE options L_RBRACE
	{
		seen_options = 1;
	}
	;

options: option L_EOS
	| options option L_EOS
	;


option: /* Empty */
	| L_VERSION L_QSTRING
	{
		debug_print( "debug: setting options version %s", $2.base);
		tmpres = isc_cfg_set_version(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set version error %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_DIRECTORY L_QSTRING
	{
		debug_print( "debug: setting options directory %s", $2.base);
		tmpres = isc_cfg_set_directory(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set directory error: %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_NAMED_XFER L_QSTRING
	{
		debug_print( "debug: setting options named-xfer %s",
			     $2.base);
		tmpres = isc_cfg_set_named_xfer(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set named-xfer error: %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_PIDFILE L_QSTRING
	{
		debug_print( "debug: setting options pidfilename %s",
			     $2.base);
		tmpres = isc_cfg_set_pid_filename(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set pidfile error %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_STATS_FILE L_QSTRING
	{
		debug_print( "debug: setting options statsfilename %s",
			     $2.base);
		tmpres = isc_cfg_set_stats_filename(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set statsfile error %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_MEMSTATS_FILE L_QSTRING
	{
		debug_print("debug: setting options memstatsfilename %s",
			    $2.base);
		tmpres = isc_cfg_set_memstats_filename(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set memstatsfile error %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_DUMP_FILE L_QSTRING
	{
		debug_print("debug: setting options dumpfilename %s",
			    $2.base);
		tmpres = isc_cfg_set_dump_filename(currcfg, $2.base);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("set dumpfile error %s: %s",
				     isc_result_totext(tmpres), $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_FAKE_IQUERY yea_or_nay
	{
		isc_cfg_set_fake_iquery(currcfg, $2);
	}
	| L_RECURSION yea_or_nay
	{
		isc_cfg_set_recursion(currcfg, $2);
	}
	| L_FETCH_GLUE yea_or_nay /* XXX */
	{
		isc_cfg_set_fetch_glue(currcfg, $2);
	}
	| L_NOTIFY yea_or_nay
	{
		isc_cfg_set_notify(currcfg, $2);
	}
	| L_HOSTSTATS yea_or_nay
	{
		isc_cfg_set_hoststats(currcfg, $2);
	}
	| L_DEALLOC_ON_EXIT yea_or_nay
	{
		isc_cfg_set_dealloc_on_exit(currcfg, $2);
	}
	| L_USE_IXFR yea_or_nay
	{
		isc_cfg_set_use_ixfr(currcfg, $2);
	}
	| L_MAINTAIN_IXFR_BASE yea_or_nay
	{
		isc_cfg_set_maintain_ixfr_base(currcfg, $2);
	}
	| L_HAS_OLD_CLIENTS yea_or_nay
	{
		isc_cfg_set_has_old_clients(currcfg, $2);
	}
	| L_AUTH_NXDOMAIN yea_or_nay
	{
		isc_cfg_set_auth_nx_domain(currcfg, $2);
	}
	| L_MULTIPLE_CNAMES yea_or_nay
	{
		isc_cfg_set_multiple_cnames(currcfg, $2);
	}
	| L_CHECK_NAMES check_names_type check_names_opt
	{
		/* XXX stuff here */
	}
	| L_USE_ID_POOL yea_or_nay
	{
		isc_cfg_set_use_id_pool(currcfg, $2);
	}
	| L_LISTEN_ON maybe_port L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| L_FORWARD forward_opt
	| L_FORWARDERS
	{
		/* XXX stuff here */
	} L_LBRACE opt_forwarders_list L_RBRACE
	| L_QUERY_SOURCE query_source
	| L_ALLOW_QUERY	L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| L_SORTLIST  L_LBRACE address_match_list L_RBRACE
	| L_BLACKHOLE L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| L_TOPOLOGY L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| size_clause
	{
		/* To get around the $$ = $1 default rule. */
	}
	| transfer_clause
	/* XXX L_TRANSFER_FORMAT goes here */
	| L_MAX_TRANSFER_TIME_IN L_INTEGER
	{
		isc_cfg_set_max_transfer_time_in(currcfg, $2 * 60);
	}
	| L_CLEAN_INTERVAL L_INTEGER
	{
		isc_cfg_set_clean_interval(currcfg, $2 * 60);
	}
	| L_INTERFACE_INTERVAL L_INTEGER
	{
		isc_cfg_set_interface_interval(currcfg, $2 * 60);
	}
	| L_STATS_INTERVAL L_INTEGER
	{
		isc_cfg_set_stats_interval(currcfg, $2 * 60);
	}
	| L_MAX_LOG_SIZE_IXFR L_INTEGER
	{
		isc_cfg_set_max_log_size_ixfr(currcfg, $2);
	}
	| L_MAX_NCACHE_TTL L_INTEGER
	{
		isc_cfg_set_max_ncache_ttl(currcfg, $2);
	}
	| L_HEARTBEAT L_INTEGER
	{
		isc_cfg_set_heartbeat_interval(currcfg, $2 * 60);
	}
	| L_DIALUP yea_or_nay
	{
		isc_cfg_set_dialup(currcfg, $2);
	}
	| L_RRSET_ORDER	L_LBRACE rrset_ordering_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| error
	;


/*
 * Controls.
 */
controls_stmt: L_CONTROLS L_LBRACE controls L_RBRACE
	;		

controls: control L_EOS
	| controls control L_EOS
	;

control: /* Empty */
	| L_INET maybe_wild_addr L_PORT in_port
	  L_ALLOW L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	| L_UNIX L_QSTRING L_PERM L_INTEGER L_OWNER L_INTEGER L_GROUP L_INTEGER
	{
		/* XXX stuff here */
	}
	| error
	;

rrset_ordering_list: rrset_ordering_element L_EOS
	{
		/* XXX stuff here */
	}
	| rrset_ordering_list rrset_ordering_element L_EOS
	{
		/* XXX stuff here */
	}
	;

ordering_class: /* nothing */
	{
		$$ = class_any;
	}
	| L_CLASS any_string
	{
		isc_symvalue_t classtok;
		tmpres = isc_symtab_lookup(keywords, $2.base,
					   class_sym_type, &classtok);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("unknown type '%s'. Assuming ANY\n",
				     $2.base);
			$$ = class_any;
		} else {
			$$ = (isc_rrclass_t) classtok.as_integer;
		}
		free_textregion($2, memctx);
	}
	;

ordering_type: /* nothing */
	{
		/* XXX stuff here */
	}
	| L_TYPE any_string
	{
		/* XXX stuff here */
	}

ordering_name: /* nothing */
	{
		/* XXX stuff here */
	}
	| L_NAME L_QSTRING
	{
		/* XXX stuff here */
	}


rrset_ordering_element: ordering_class ordering_type ordering_name L_ORDER L_STRING
	{
		/* XXX stuff here */
	}

	
transfer_format: L_ONE_ANSWER
	{
		/* XXX stuff here */
	}
	| L_MANY_ANSWERS
	{
		/* XXX stuff here */
	}
	;


maybe_wild_addr: L_IPADDR
	{
		$$ = $1;
	}
	| '*'
	{
		$$.s_addr = htonl(INADDR_ANY);
	}
	;

maybe_wild_port: in_port
	{
		$$ = $1;
	}
	| '*'
	{
		$$ = htons(0);
	}
	;

query_source_address: L_ADDRESS maybe_wild_addr
	{
		/* XXX stuff here */
	}
	;

query_source_port: L_PORT maybe_wild_port
	{
		/* XXX stuff here */
	}
	;

query_source: query_source_address
	| query_source_port
	| query_source_address query_source_port
	| query_source_port query_source_address
	;

maybe_port: /* nothing */
	{
		$$ = htons(NS_DEFAULTPORT);
	}
	| L_PORT in_port
	{
		$$ = $2;
	}
	;

maybe_zero_port : /* nothing */
	{
		$$ = htons(0);
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
			parser_warning("number should be 0 or 1; assuming 1");
			$$ = isc_boolean_true;
		}
	}
	;

check_names_type: L_MASTER
	{
		/* XXX stuff here */
	}
	| L_SLAVE
	{
		/* XXX stuff here */
	}
	| L_RESPONSE
	{
		/* XXX stuff here */
	}
	;

check_names_opt: L_WARN
	{
		/* XXX stuff here */
	}
	| L_FAIL
	{
		/* XXX stuff here */
	}
	| L_IGNORE
	{
		/* XXX stuff here */
	}
	;

forward_opt: L_ONLY
	{
		/* XXX stuff here */
	}
	| L_FIRST
	{
		/* XXX stuff here */
	}
	| L_IF_NO_ANSWER
	{
		/* XXX stuff here */
	}
	| L_IF_NO_DOMAIN
	{
		/* XXX stuff here */
	}
	;



size_clause: L_DATASIZE size_spec
	{
		debug_print( "debug: setting options datasize %ld", $2);
		isc_cfg_set_data_size(currcfg, $2);
	}
	| L_STACKSIZE size_spec
	{
		debug_print( "debug: setting options stacksize %ld", $2);
		isc_cfg_set_stack_size(currcfg, $2);
	}
	| L_CORESIZE size_spec
	{
		debug_print( "debug: setting options coresize %ld", $2);
		isc_cfg_set_core_size(currcfg, $2);
	}
	| L_FILES size_spec
	{
		debug_print("debug: setting options files %ld", $2);
		isc_cfg_set_files(currcfg, $2);
	}
	;


size_spec: any_string
	{
		u_long result;

		fprintf(stderr, "geting size\n");
		if (unit_to_ulong($1.base, &result))
			$$ = result;
		else {
			parser_error("invalid unit string '%s'", $1);
			/* 0 means "use default" */
			$$ = 0;
		}
		free_textregion($1, memctx);
	}
	| L_INTEGER
	{	
		$$ = (unsigned long)$1;
	}
	| L_DEFAULT
	{
		$$ = 0;
	}
	| L_UNLIMITED
	{
		$$ = ULONG_MAX;
	}
	;



transfer_clause: L_TRANSFERS_IN L_INTEGER
	{
		isc_cfg_set_transfers_in(currcfg, (unsigned long)$2);
	}
	| L_TRANSFERS_OUT L_INTEGER
	{
		isc_cfg_set_transfers_out(currcfg, (unsigned long)$2);
	}
	| L_TRANSFERS_PER_NS L_INTEGER
	{
		isc_cfg_set_transfers_per_ns(currcfg, (unsigned long) $2);
	}
	;


opt_forwarders_list: /* nothing */
	| forwarders_in_addr_list
	;

forwarders_in_addr_list: forwarders_in_addr L_EOS
	{
		/* nothing */
	}
	| forwarders_in_addr_list forwarders_in_addr L_EOS
	{
		/* nothing */
	}
	;

forwarders_in_addr: L_IPADDR
	{
		/* XXX stuff here */
	}
	;

/*
 * Logging
 */

logging_stmt: L_LOGGING
	{
		/* XXX stuff here */
	}
	L_LBRACE logging_opts_list L_RBRACE
	{
		/* XXX stuff here */
	}
	;

logging_opts_list: logging_opt L_EOS
	| logging_opts_list logging_opt L_EOS
	| error
	;

logging_opt: L_CATEGORY category 
	{
		/* XXX stuff here */
	}
	L_LBRACE channel_list L_RBRACE
	| L_CHANNEL channel_name
	{
		/* XXX stuff here */
	}
	L_LBRACE channel_opt_list L_RBRACE
	{
		/* XXX stuff here */
	}
	;

channel_severity: any_string
	{
		/* XXX stuff here */
	}
	| L_DEBUG
	{
		/* XXX stuff here */
	}
	| L_DEBUG L_INTEGER
	{
		/* XXX stuff here */
	}
	| L_DYNAMIC
	{
		/* XXX stuff here */
	}
	;

version_modifier: L_VERSIONS L_INTEGER
	{
		/* XXX stuff here */
	}
	| L_VERSIONS L_UNLIMITED
	{
		/* XXX stuff here */
	}
	;

size_modifier: L_SIZE size_spec
	{
		/* XXX stuff here */
	}
	;

maybe_file_modifiers: /* nothing */
	{
		/* XXX stuff here */
	}
	| version_modifier
	{
		/* XXX stuff here */
	}
	| size_modifier
	{
		/* XXX stuff here */
	}
	| version_modifier size_modifier
	| size_modifier version_modifier
	;

channel_file: L_FILE L_QSTRING maybe_file_modifiers
	{
		/* XXX stuff here */
	}
	;


facility_name: any_string
	{
		$$ = $1;
	}
	| L_SYSLOG
	{
		/* XXX stuff here */
	}
	;

maybe_syslog_facility: /* nothing */
	{
		$$ = LOG_DAEMON;
	}
	| facility_name
	{
		/* XXX stuff here */
	}
	;

channel_syslog: L_SYSLOG maybe_syslog_facility
	{
		/* XXX stuff here */
	}
	;

channel_opt: channel_file { /* nothing to do */ }
	| channel_syslog { /* nothing to do */ }
	| L_NULL_OUTPUT
	{
		/* XXX stuff here */
	}
	| L_SEVERITY channel_severity { /* nothing to do */ }
	| L_PRINT_TIME yea_or_nay
	{
		/* XXX stuff here */
	}
	| L_PRINT_CATEGORY yea_or_nay
	{
		/* XXX stuff here */
	}
	| L_PRINT_SEVERITY yea_or_nay
	{
		/* XXX stuff here */
	}
	;

channel_opt_list: channel_opt L_EOS
	| channel_opt_list channel_opt L_EOS
	| error
	;

channel_name: any_string
	| L_NULL_OUTPUT
	{
		/* XXX stuff here */
	}
	;

channel: channel_name
	{
		/* XXX stuff here */
	}
	;

channel_list: channel L_EOS
	| channel_list channel L_EOS
	| error
	;

category_name: any_string
	| L_DEFAULT
	{
		/* XXX stuff here */
	}
	| L_NOTIFY
	{
		/* XXX stuff here */
	}
	;

category: category_name
	{
		/* XXX stuff here */
	}
	;


/*
 * Server Information
 */

server_stmt: L_SERVER L_IPADDR
	{
		/* XXX stuff here */
	}
	L_LBRACE server_info_list L_RBRACE
	{
		/* XXX stuff here */
	}
	;

server_info_list: server_info L_EOS
	| server_info_list server_info L_EOS
	;

server_info: L_BOGUS yea_or_nay
	{
		/* XXX stuff here */
	}
	| L_SUPPORT_IXFR yea_or_nay
	{
		/* XXX stuff here */
	}	
	| L_TRANSFERS L_INTEGER
	{
		/* XXX stuff here */
	}
	| L_TRANSFER_FORMAT transfer_format
	{
		/* XXX stuff here */
	}
	| L_KEYS L_LBRACE key_list L_RBRACE
	| error
	;

/*
 * Address Matching
 */

address_match_list: address_match_element L_EOS
	{
		/* XXX stuff here */
	}
	| address_match_list address_match_element L_EOS
	{
		/* XXX stuff here */
	}
	;

address_match_element: address_match_simple
	| '!' address_match_simple
	{
		/* XXX stuff here */
	}
	| L_SEC_KEY L_STRING
	{
		/* XXX stuff here */
	}
	;

address_match_simple: L_IPADDR
	{
		/* XXX stuff here */
	}
	| L_IPADDR L_SLASH L_INTEGER
	{
		/* XXX stuff here */
	}
	| L_INTEGER L_SLASH L_INTEGER
	{
		/* XXX stuff here */
	}
	| address_name
	| L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	;

address_name: any_string
	{
		/* XXX stuff here */
	}
	;

/*
 * Keys
 */

key_ref: any_string
	{
		/* XXX stuff here */
	}
	;

key_list_element: key_ref
	{
		/* XXX stuff here */
	}
	;

key_list: key_list_element L_EOS
	| key_list key_list_element L_EOS
	| error
	;

key_stmt: L_SEC_KEY
	{
		/* XXX stuff here */
	}
	any_string L_LBRACE key_definition L_RBRACE
	{
		/* XXX stuff here */
	}
	;
	
key_definition: algorithm_id secret
	{
		/* XXX stuff here */
	}
	| secret algorithm_id
	{
		/* XXX stuff here */
	}
	| error
	{
		/* XXX stuff here */
	}
	;

algorithm_id: L_ALGID any_string L_EOS
	{
		/* XXX stuff here */
	}
	;

secret: L_SECRET any_string L_EOS
	{
		/* XXX stuff here */
	}
	;

/*
 * ACLs
 */

acl_stmt: L_ACL any_string L_LBRACE address_match_list L_RBRACE
	{
		/* XXX stuff here */
	}
	;


/*
 * Zones
 */

zone_stmt: L_ZONE L_QSTRING optional_class
	{
		isc_zoneinfo_t *zi = NULL;

		debug_print( "debug: zone statement %s", $2.base);
		if (isc_zone_newinfo(currzonectx, &zi) != ISC_R_SUCCESS) {
			debug_print( "newzone error");
			return (1);
		}

		isc_zone_setorigin(zi, $2.base);

		currzone = zi;

		isc_zone_setclass(currzone, $3);
		
		free_textregion($2, memctx);
	} optional_zone_options_list {
		/* XXX install zone if parsed correctly and remove
		   it if not. */
	}
	;

optional_zone_options_list: /* Empty */
	| L_LBRACE zone_option_list L_RBRACE
	;

optional_class: /* Empty */
	{
		$$ = class_in;
	}
	| any_string
	{
		isc_symvalue_t classtok;
		tmpres = isc_symtab_lookup(keywords, $1.base,
					   class_sym_type, &classtok);
		if (tmpres != ISC_R_SUCCESS) {
			parser_error("unknown type '%s'. Assuming ANY\n",
				     $1.base);
			$$ = class_none;
		} else {
			$$ = (isc_rrclass_t)classtok.as_integer;
		}
		free_textregion($1, memctx);
	}
	;

zone_type: L_MASTER
	{
		$$ = zone_master;
	}
	| L_SLAVE
	{
		$$ = zone_slave;
	}
	| L_HINT
	{
		$$ = zone_hint;
	}
	| L_STUB
	{
		$$ = zone_stub;
	}
	| L_FORWARD
	{
		$$ = zone_forward;
	}
	;



zone_option_list: zone_option L_EOS
	| zone_option_list zone_option L_EOS
	;

zone_option: L_TYPE zone_type
	{
		INSIST(currzone != NULL);
		currzone->type = $2;
	}
	| L_FILE L_QSTRING
	{
		INSIST(currzone != NULL);
		if (currzone->source.base != NULL) {
			parser_warning("zone filename already set; skipping");
		} else {
			isc_zone_setsource(currzone, $2.base);
		}
		free_textregion($2, memctx);
	}
	| L_FILE_IXFR L_QSTRING
	{
					/* XXX stuff here */
	}
	| L_IXFR_TMP L_QSTRING
	{
					/* XXX stuff here */
	}
	| L_MASTERS maybe_zero_port L_LBRACE master_in_addr_list L_RBRACE
	{
					/* XXX stuff here */
	}
	| L_TRANSFER_SOURCE maybe_wild_addr
	{
					/* XXX stuff here */
	}
	| L_CHECK_NAMES check_names_opt
	{
					/* XXX stuff here */
	}
	| L_ALLOW_UPDATE L_LBRACE address_match_list L_RBRACE
	{
					/* XXX stuff here */
	}
	| L_ALLOW_QUERY L_LBRACE address_match_list L_RBRACE
	{
					/* XXX stuff here */
	}
	| L_ALLOW_TRANSFER L_LBRACE address_match_list L_RBRACE
	{
					/* XXX stuff here */
	}
	| L_FORWARD zone_forward_opt
	| L_FORWARDERS {
					/* XXX stuff here */
	} L_LBRACE opt_zone_forwarders_list L_RBRACE
	| L_MAX_TRANSFER_TIME_IN L_INTEGER
	{
					/* XXX stuff here */
	}
	| L_MAX_LOG_SIZE_IXFR L_INTEGER
	{
					/* XXX stuff here */
        }
	| L_NOTIFY yea_or_nay
	{
					/* XXX stuff here */
	}
	| L_MAINTAIN_IXFR_BASE yea_or_nay
	{
					/* XXX stuff here */
	}
	| L_PUBKEY L_INTEGER L_INTEGER L_INTEGER L_QSTRING
	{
					/* XXX stuff here */
	}
	| L_ALSO_NOTIFY L_LBRACE opt_notify_in_addr_list L_RBRACE
	| L_DIALUP yea_or_nay 
	{
					/* XXX stuff here */
	}
	| error
        ;


master_in_addr_list: master_in_addr L_EOS
	{
		/* nothing */
	}
	| master_in_addr_list master_in_addr L_EOS
	{
		/* nothing */
	}
	;

master_in_addr: L_IPADDR
	{
		/* XXX stuff here */
	}
	;

opt_notify_in_addr_list: /* nothing */
	| notify_in_addr_list
	;

notify_in_addr_list: notify_in_addr L_EOS
	{
		/* nothing */
	}
	| notify_in_addr_list notify_in_addr L_EOS
	{
		/* nothing */
	}
	;

notify_in_addr: L_IPADDR
	{
		/* XXX stuff here */
	}
	;

zone_forward_opt: L_ONLY
	{
		/* XXX stuff here */
	}
	| L_FIRST
	{
		/* XXX stuff here */
	}
	;

opt_zone_forwarders_list: /* nothing */
	| zone_forwarders_in_addr_list
	;

zone_forwarders_in_addr_list: zone_forwarders_in_addr L_EOS
	{
		/* nothing */
	}
	| zone_forwarders_in_addr_list zone_forwarders_in_addr L_EOS
	{
		/* nothing */
	}
	;

zone_forwarders_in_addr: L_IPADDR
	{
		/* XXX stuff here */
	}
	;

/*
 * Trusted Key statement
 */

trusted_keys_stmt: L_TRUSTED_KEYS L_LBRACE trusted_keys_list L_RBRACE
	{
		/* XXX stuff here */
	}
	;
trusted_keys_list: trusted_key L_EOS
	{
		/* nothing */
	}
	| trusted_keys_list trusted_key L_EOS
	{
		/* nothing */
	}
	;
trusted_key: L_STRING L_INTEGER L_INTEGER L_INTEGER L_QSTRING
	{
		/* XXX stuff here */
	}
	;

/*
 * Misc.
 */

in_port: L_INTEGER
	{
		if ($1 < 0 || $1 > 65535) {
		  	parser_warning(
			  "invalid IP port number '%d'; setting port to 0",
			               $1);
			$1 = 0;
		} else
			$$ = htons($1);
	}
	;



any_string: L_STRING
	| L_QSTRING
	;

%%

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
	{ "{", L_LBRACE },
	{ "}", L_RBRACE },
	{ ";", L_EOS },
	{ "/", L_SLASH },
	{ "!", L_BANG },
	{ "*", L_STAR },
	
	{ "acl", L_ACL }, 
	{ "address", L_ADDRESS },
	{ "algorithm", L_ALGID },
	{ "allow", L_ALLOW },
	{ "allow-query", L_ALLOW_QUERY }, 
	{ "allow-transfer", L_ALLOW_TRANSFER },
	{ "allow-update", L_ALLOW_UPDATE },
	{ "also-notify", L_ALSO_NOTIFY },
	{ "auth-nxdomain", L_AUTH_NXDOMAIN },
	{ "blackhole", L_BLACKHOLE },
	{ "bogus", L_BOGUS },
	{ "category", L_CATEGORY },
	{ "class", L_CLASS },
	{ "channel", L_CHANNEL },
	{ "check-names", L_CHECK_NAMES },
	{ "cleaning-interval", L_CLEAN_INTERVAL },
	{ "controls", L_CONTROLS },
	{ "coresize", L_CORESIZE },
	{ "datasize", L_DATASIZE },
	{ "deallocate-on-exit", L_DEALLOC_ON_EXIT },
	{ "debug", L_DEBUG },
	{ "default", L_DEFAULT },
	{ "dialup", L_DIALUP },
	{ "directory", L_DIRECTORY }, 
	{ "dump-file", L_DUMP_FILE },
	{ "dynamic", L_DYNAMIC },
	{ "fail", L_FAIL },
	{ "fake-iquery", L_FAKE_IQUERY },
	{ "false", L_FALSE },
	{ "fetch-glue", L_FETCH_GLUE },
	{ "file", L_FILE }, 
	{ "files", L_FILES }, 
	{ "first", L_FIRST }, 
	{ "forward", L_FORWARD },
	{ "forwarders", L_FORWARDERS },
	{ "group", L_GROUP },
	{ "has-old-clients", L_HAS_OLD_CLIENTS },
	{ "heartbeat-interval", L_HEARTBEAT },
	{ "hint", L_HINT },
	{ "host-statistics", L_HOSTSTATS },
	{ "if-no-answer", L_IF_NO_ANSWER },
	{ "if-no-domain", L_IF_NO_DOMAIN },
	{ "ignore", L_IGNORE },
	{ "include", L_INCLUDE },
	{ "inet", L_INET },
	{ "interface-interval", L_INTERFACE_INTERVAL },
	{ "ixfr-base", L_FILE_IXFR },
	{ "ixfr-tmp-file", L_IXFR_TMP },
	{ "key", L_SEC_KEY },
	{ "keys", L_KEYS },
	{ "listen-on", L_LISTEN_ON },
	{ "logging", L_LOGGING },
	{ "maintain-ixfr-base", L_MAINTAIN_IXFR_BASE },
	{ "many-answers", L_MANY_ANSWERS },
	{ "master", L_MASTER },
	{ "masters", L_MASTERS },
	{ "max-ixfr-log-size", L_MAX_LOG_SIZE_IXFR },
	{ "max-ncache-ttl", L_MAX_NCACHE_TTL },
	{ "max-transfer-time-in", L_MAX_TRANSFER_TIME_IN },
	{ "memstatistics-file", L_MEMSTATS_FILE },
	{ "multiple-cnames", L_MULTIPLE_CNAMES },
	{ "name", L_NAME },
	{ "named-xfer", L_NAMED_XFER },
	{ "no", L_NO },
	{ "notify", L_NOTIFY },
	{ "null", L_NULL_OUTPUT },
	{ "one-answer", L_ONE_ANSWER },
	{ "only", L_ONLY },
	{ "order", L_ORDER },
	{ "options", L_OPTIONS },
	{ "owner", L_OWNER },
	{ "perm", L_PERM },
	{ "pid-file", L_PIDFILE },
	{ "port", L_PORT },
	{ "print-category", L_PRINT_CATEGORY },
	{ "print-severity", L_PRINT_SEVERITY },
	{ "print-time", L_PRINT_TIME },
	{ "pubkey", L_PUBKEY },
	{ "query-source", L_QUERY_SOURCE },
	{ "rrset-order", L_RRSET_ORDER },
	{ "recursion", L_RECURSION },
	{ "response", L_RESPONSE },
	{ "secret", L_SECRET },
	{ "server", L_SERVER }, 
	{ "severity", L_SEVERITY }, 
	{ "size", L_SIZE }, 
	{ "slave", L_SLAVE },
#ifdef SORT_RESPONSE
	{ "sortlist", L_SORTLIST },
#endif /* SORT_RESPONSE */
	{ "stacksize", L_STACKSIZE },
	{ "statistics-file", L_STATS_FILE },
	{ "statistics-interval", L_STATS_INTERVAL },
	{ "stub", L_STUB },
	{ "support-ixfr", L_SUPPORT_IXFR },
	{ "syslog", L_SYSLOG }, 
	{ "topology", L_TOPOLOGY },
	{ "transfer-format", L_TRANSFER_FORMAT }, 
	{ "transfer-source", L_TRANSFER_SOURCE },
	{ "transfers", L_TRANSFERS }, 
	{ "transfers-in", L_TRANSFERS_IN }, 
	{ "transfers-out", L_TRANSFERS_OUT }, 
	{ "transfers-per-ns", L_TRANSFERS_PER_NS }, 
	{ "true", L_TRUE }, 
	{ "trusted-keys", L_TRUSTED_KEYS },
	{ "type", L_TYPE },
	{ "unix", L_UNIX },
	{ "unlimited", L_UNLIMITED },
	{ "use-id-pool", L_USE_ID_POOL },
	{ "use-ixfr", L_USE_IXFR },
	{ "version", L_VERSION },
	{ "versions", L_VERSIONS }, 
	{ "warn", L_WARN },
	{ "yes", L_YES }, 
	{ "zone", L_ZONE },

	{ NULL, 0 }
};


static struct token class_symbol_tokens[] = {
	{ "IN", class_in },
	{ "CHAOS", class_chaos },
	{ "HS", class_hs },
	{ "HESIOD", class_hesiod },
	{ "ANY", class_any },
	{ "NONE", class_none },
	{ NULL, 0 }
};


static void undef_symtab_entry(char *key, unsigned int type,
			       isc_symvalue_t value, void *arg);
static int token_value(isc_token_t *token, isc_symtab_t *symtable);



isc_result_t
parser_init(void)
{
	isc_result_t res;

	INSIST(onetime == 0);

	/* our caller is (better be) locking us */
	res = isc_mutex_init(&yacc_mutex);
	onetime++;

	specials['{'] = 1;
	specials['}'] = 1;
	specials[';'] = 1;
	specials['/'] = 1;
	specials['"'] = 1;
	specials['!'] = 1;
	specials['*'] = 1;

	return (res);
}


isc_result_t
parse_configuration(const char *filename, isc_mem_t *mem,
		    isc_cfgctx_t **configctx)
{
	isc_result_t res;
	const char *funcname = "parse_configuration";

	REQUIRE(currcfg == NULL);
	REQUIRE(filename != NULL);
	REQUIRE(strlen(filename) > 0);
	REQUIRE(configctx != NULL);
	INSIST(memctx == NULL);
	INSIST(mylexer == NULL);
	INSIST(keywords == NULL);

	/* Lock down whole parser. */
	if (isc_mutex_lock(&yacc_mutex) != ISC_R_SUCCESS) {
		return (ISC_R_UNEXPECTED);
	}

	if (getenv("DEBUG_LEXER") != NULL) {
		debug_lexer++;
	}

	seen_options = 0;
	seen_topology = 0;
	
	/* It would be better to do this create in parse_init and let the
	 * object live across calls, but doing it here lets us catch memory 
	 * leaks (in the destroy method)
	 */
	RUNTIME_CHECK(isc_mem_create(0, 0, &memctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(symtable_init() == ISC_R_SUCCESS);
	
	RUNTIME_CHECK(isc_lex_create(memctx, CONF_MAX_IDENT, &mylexer)
		      == ISC_R_SUCCESS);

	isc_lex_setspecials(mylexer, specials);
	isc_lex_setcomments(mylexer, (ISC_LEXCOMMENT_C |
				      ISC_LEXCOMMENT_CPLUSPLUS |
				      ISC_LEXCOMMENT_SHELL));
	
	res = isc_lex_openfile(mylexer, (char *)filename) ; /* remove const */
	if (res != ISC_R_SUCCESS) {
		debug_print("%s: Error opening file %s: %s",
			    funcname, filename, isc_result_totext(res));
		goto done;
	}
	
	if ((res = isc_cfg_newctx(mem, &currcfg)) != ISC_R_SUCCESS) {
		debug_print("%s: Error creating config context: %s",
			    funcname, isc_result_totext(res));
		goto done;
	}

	currfile = filename;
	currzonectx = currcfg->zonecontext;

	if (yyparse() != 0) {
		res = ISC_R_FAILURE;
		isc_cfg_freectx(&currcfg);
		currcfg = NULL;
	} else {
		res = ISC_R_SUCCESS;
	}


 done:
	if (keywords != NULL) 
		isc_symtab_destroy(&keywords);
	if (mylexer != NULL)
		isc_lex_destroy(&mylexer);
	isc_mem_destroy(&memctx);
	
	*configctx = currcfg;

	currcfg = NULL;
	memctx = NULL;
	keywords = NULL;
	mylexer = NULL;
	
	RUNTIME_CHECK(isc_mutex_unlock(&yacc_mutex) == ISC_R_SUCCESS);

	if (*configctx != NULL)		/* XXX DEBUG */
		isc_cfg_dump_config(stderr,*configctx);
	
	return (res);
}



/***
 *** PRIVATE
 ***/


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
		parser_error("%s: %d: unbalanced parentheses",
			      isc_lex_getsourcename(mylexer),
			      isc_lex_getsourceline(mylexer));
		res = -1;
		break;

	case ISC_R_NOSPACE:
		parser_error("%s: %d: token too big.",
			     isc_lex_getsourcename(mylexer),
			     isc_lex_getsourceline(mylexer));
		res = -1;
		break;
			
	case ISC_R_UNEXPECTEDEND:
		parser_error("%s: %d: unexpected EOF",
			     isc_lex_getsourcename(mylexer),
			     isc_lex_getsourceline(mylexer));
		res = -1;
		break;
		
	default:
		parser_error("%s: %d unknown lexer error (%d)",
			     isc_lex_getsourcename(mylexer),
			     isc_lex_getsourceline(mylexer),
			     res);
		res = -1;
		break;
	}

	return (res);
}



static void
undef_symtab_entry(char *key, unsigned int type, isc_symvalue_t value, 
		void *arg)
{
	/* XXX nothing yet */
}


/* XXX this should switch to using logging stuff. */
static void
print_msg(const char *fmt, va_list args)
{
	fprintf(stderr," %s: %d: ",
		isc_lex_getsourcename(mylexer),
		isc_lex_getsourceline(mylexer));
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}


static void
debug_print(const char *fmt, ...)
{
	va_list args;

	/* XXX probably want to print based on some debug level */
	
	if (debugging_stuff) {
		va_start(args, fmt);
		print_msg(fmt, args);
		va_end(args);
	}
}

	
       
/*
 * For reporting items that are semantic, but not syntactic errors
 */
static void
parser_error(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	print_msg(fmt, args);
	va_end(args);

	currcfg->errors++;
}

	
static void
parser_warning(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	print_msg(fmt, args);
	va_end(args);

	currcfg->warnings++;
}

static void
yyerror_helper(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	print_msg(fmt, args);
	va_end(args);

	currcfg->warnings++;
}


static void
yyerror(const char *string)
{
	yyerror_helper("%s",string);
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

		if (debug_lexer) {
			fprintf(stderr, "lexer token: %s / %s\n",
				(token->type == isc_tokentype_special ?
				 "special" : "string"), tokstring);
		}
		
		res = isc_symtab_lookup(symtable, tokstring,
					keyword_type, &keywordtok);

		if (res != ISC_R_SUCCESS) {
			res = intuit_token(symtable, tmpident);
			/* XXX */
			res = copy_textregion(memctx,
					      token->value.as_textregion,
					      &yylval.text);
			if (res != ISC_R_SUCCESS) {
				res = -1;
			} else {
				res = L_STRING;
			}
		} else {
			res = keywordtok.as_integer;
		}
		break;
		
	case isc_tokentype_number:
		yylval.ul_int = token->value.as_ulong;
		res = L_INTEGER;

		if(debug_lexer) {
			fprintf(stderr, "lexer token: number / %ld\n",
				yylval.ul_int);
		}
		
		break;
		
	case isc_tokentype_qstring:
		res = copy_textregion(memctx,token->value.as_textregion,
				      &yylval.text);
		if (res != ISC_R_SUCCESS) {
			res = -1;
		} else {
			res = L_QSTRING;
		}

		if (debug_lexer) {
			fprintf(stderr, "lexer token: qstring \"%s\"\n",
				yylval.text.base);
		}
		
		break;
		
	case isc_tokentype_eof:
		if (debug_lexer) {
			fprintf(stderr, "lexer token: EOF\n");
		}
		res = isc_lex_close(mylexer);
		INSIST(res == ISC_R_NOMORE || res == ISC_R_SUCCESS);

		if (isc_lex_getsourcename(mylexer) == NULL) {
			/* the only way to tell that we
			   closed the main file and not an included file */
			res = 0;
		} else {
			res = L_END_INCLUDE;
		}
		break;
		
	case isc_tokentype_initialws:
	case isc_tokentype_eol:
	case isc_tokentype_nomore:
		res = -1;
		break;
	}

	return (res);
}


/*
 * Allocate a new buffer and copy the data to it. Add an extra byte for a null.
 */
static isc_result_t
copy_textregion(isc_mem_t *mem,
		isc_textregion_t region, isc_textregion_t *newregion)
{
	INSIST(mem != NULL);

	newregion->base = isc_mem_get(mem, region.length + 1);
	if (newregion->base == NULL) {
		return (ISC_R_NOMEMORY);
	}

	newregion->length = region.length + 1;
	memcpy(newregion->base, region.base, region.length);
	newregion->base[region.length] = '\0';
	
	return (ISC_R_SUCCESS);
}


static void
free_textregion(isc_textregion_t region, isc_mem_t *mem)
{
	INSIST(mem != NULL);
	INSIST(region.base != NULL);
	INSIST(region.length > 0);

	isc_mem_put(mem, region.base, region.length);

	return;
}



static int
intuit_token(isc_symtab_t *symtab, const char *string)
{
	/* XXX given a string that's something other than a keyword, figure
	 * out the type of data is represents.
	 */
	return -1;
}


/*
 * Conversion Routines
 */

static int
unit_to_ulong(char *in, unsigned long *out) {	
	int c, units_done = 0;
	unsigned long result = 0L;

	INSIST(in != NULL);

	for (; (c = *in) != '\0'; in++) {
		if (units_done)
			return (0);
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
				return (0);
			}
		}
	}

	*out = result;
	return (1);
}

static isc_result_t
define_symbol(isc_symtab_t *symtable, const char *key, int type, int value) {
	isc_symvalue_t symval;
	isc_result_t res;

	symval.as_integer = value;
	res = isc_symtab_define(symtable, /* dump const */ (char *) key,
				type, symval, isc_symexists_reject);

	if (res != ISC_R_SUCCESS) {
		debug_print("Error installing keyword: %s: %s",
			     key, isc_result_totext(res));
		return (res);
	}

	return (ISC_R_SUCCESS);
}

	

static isc_result_t
symtable_init(void)
{
	struct token *tok;
	
	RUNTIME_CHECK(isc_symtab_create(memctx, SYMTAB_SIZE,
					undef_symtab_entry, NULL,
					ISC_FALSE, &keywords) ==
		      ISC_R_SUCCESS);


	/* Stick all the keywords into the main symbol table. */
	for (tok = &keyword_tokens[0] ; tok->token != NULL ; tok++) {
		RUNTIME_CHECK(define_symbol(keywords, tok->token,
					    keyword_type, tok->yaccval) ==
			      ISC_R_SUCCESS);
	}

	/* Now the class names */
	for (tok = &class_symbol_tokens[0] ; tok->token != NULL ; tok++) {
		RUNTIME_CHECK(define_symbol(keywords, tok->token,
					    class_sym_type, tok->yaccval) ==
			      ISC_R_SUCCESS);
	}

	return (ISC_R_SUCCESS);
}
