%{
#if !defined(lint) && !defined(SABER)
static char rcsid[] = "$Id: parser.y,v 1.1 1999/01/30 00:50:10 brister Exp $";
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

#include <config.h>

#include <stdarg.h>
#include <stdio.h>
 
#include <isc/assertions.h> 
#include <isc/mutex.h>

#include "parser.h" 
#include "zone.h"
#include "configctx.h"

static int onetime ;
static isc_mutex_t yacc_mutex;
 
static isc_zonectx_t *currzonectx;
static isc_zoneinfo_t *currzone;
static isc_cfgctx_t *currcfg;
static const char *currfile;

 
static void parser_cleanup(void);
static void print_msg(char *fmt, va_list args);
static void parser_warning(char *fmt, ...);
static void parser_error(char *fmt, ...);
 
int yyparse(void);
void yyerror(const char *);
int yylex(void);
 
 
 
%}

%union {
	char *			cp;
	long			num;
	isc_zonet_t		ztype;
}


%token		L_LBRACE
%token		L_RBRACE
%token		L_EOS
%token		L_MASTER
%token		L_SLAVE
%token		L_HINT
%token		L_STUB
%token		L_FORWARD


/* options statement */
%token		L_OPTIONS
%token		L_DIRECTORY


/* Zone statements */
%token		L_ZONE
%type <ztype>	zone_type
%token		L_TYPE
%token		L_FILE


/* Misc */
%token <cp>	L_STRING
%token <cp>	L_QSTRING
%token <num>	L_INTEGER


%%

config_file: statement_list
	{
		/* XXX Do post-read validations etc. */
	}
	;

statement_list: statement
	| statement_list statement
	;

statement: options_stmt L_EOS
	| zone L_EOS
	;

options_stmt: L_OPTIONS L_LBRACE options_list L_RBRACE
	;

options_list: option L_EOS
	| options_list option L_EOS
	;


option: /* Empty */
	| L_DIRECTORY L_QSTRING
	{
		printf("doing the option\n");
		if (isc_cfg_setdirectory(currcfg, $2) != ISC_R_SUCCESS) {
			parser_cleanup();
			fprintf(stderr, "setdirectory error\n");
			return (1);
		}
	}
	;

zone: L_ZONE L_QSTRING
	{
		isc_zoneinfo_t *zi = NULL;

		if (isc_zone_newinfo(currzonectx, &zi) != ISC_R_SUCCESS) {
			parser_cleanup();
			fprintf(stderr, "newzone error\n");
			return (1);
		}

		isc_zone_setorigin(zi, $2);

		currzone = zi;
	} optional_zone_options_list {
		/* XXX install zone if parsed correctly and remove
		   it if not. */
	}
	;

optional_zone_options_list: /* Empty */
	| L_LBRACE zone_option_list L_RBRACE
	;

zone_option_list: zone_option L_EOS
	| zone_option_list zone_option L_EOS
	;

zone_option: L_TYPE zone_type
	{
	}
	| L_FILE L_QSTRING
	{
		INSIST(currzone != NULL);
		if (currzone->source != NULL) {
			parser_warning("zone filename already set; skipping");
		} else {
			isc_zone_setsource(currzone, $2);
		}
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



%%

isc_result_t
isc_parser_init()
{
	isc_result_t res = ISC_R_SUCCESS;

	if (onetime == 0) {
		/* our caller is locking us */
		res = isc_mutex_init(&yacc_mutex);

		onetime++;
	}

	return (res);
}


isc_result_t
isc_parse_configuration(const char *filename,
			isc_mem_t *mem,
			isc_cfgctx_t **configctx) {
	isc_result_t res ;
	isc_result_t t;
	FILE *fp;
	extern FILE *yyin;

	/* Take out mutex on whole parser. */
	if (isc_mutex_lock(&yacc_mutex) != ISC_R_SUCCESS) {
		return (ISC_R_UNEXPECTED);
	}
	
	INSIST(currcfg == NULL);

	if ((res = isc_cfg_newctx(mem, &currcfg)) != ISC_R_SUCCESS) {
		isc_mutex_unlock(&yacc_mutex);
		return (res);
	}

	if ((fp = fopen(filename, "r")) == NULL) {
		isc_mutex_unlock(&yacc_mutex);
		return (ISC_R_INVALIDFILE);
	}

	yyin = fp ;
	currfile = filename;
	currzonectx = currcfg->zonecontext;

	if (yyparse() != 0) {
		res = ISC_R_FAILURE;
	}

	fclose(fp);
	
	*configctx = currcfg;
	currcfg = NULL;
	
	if ((t = isc_mutex_unlock(&yacc_mutex)) != ISC_R_SUCCESS) {
		res = t;
	}

	return (res);
}



/***
 *** PRIVATE
 ***/

static void
parser_cleanup(void)
{
	/* XXX destroy the config context */
}


static void
print_msg(char *fmt, va_list args)
{
	fprintf(stderr," %s: \n", currfile);
	vfprintf(stderr, fmt, args);
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
parser_error(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	print_msg(fmt, args);
	va_end(args);

	currcfg->errors++;
}



