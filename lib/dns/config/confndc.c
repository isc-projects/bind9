/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: confndc.c,v 1.17 2000/06/02 15:12:28 brister Exp $ */

/*
**	options {
**	  [ default-server server_name; ]
**	  [ default-key key_name; ]
**	};
**	
**	server server_name {
**	  key key_name;
**	  [ host name_or_addr; ]
**	};
**	
**	key key_name {
**	  algorithm string;
**	  secret  string;
**	};
**	
*/


#include <config.h>

#include <ctype.h>
#include <stdlib.h>

#include <isc/string.h>
#include <isc/dir.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/net.h>
#include <isc/print.h>
#include <isc/symtab.h>
#include <isc/util.h>

#include <dns/confndc.h>
#include <dns/log.h>
 
/* Type keys for symtab lookup */
#define KEYWORD_SYM_TYPE 0x1
#define CLASS_SYM_TYPE 0x2
#define ACL_SYM_TYPE 0x3

#define CONF_MAX_IDENT 1024

typedef struct  {
	isc_mem_t	       *themem;
	isc_lex_t	       *thelexer;
	isc_symtab_t	       *thekeywords;
	int			errors;
	int			warnings;
	isc_boolean_t		debug_lexer;

	dns_c_ndcctx_t	       *thecontext;

	isc_uint32_t		currtok;
	isc_uint32_t		prevtok;
	char			tokstr[CONF_MAX_IDENT];
	char			prevtokstr[CONF_MAX_IDENT];

	isc_uint32_t		intval;
	struct in_addr		ip4addr;
	struct in6_addr		ip6addr;
} ndcpcontext;

struct keywordtoken {
        const char *token;
        const int yaccval;
};


/* 
 * DATA
 */

#define L_ALGORITHM                                        1
#define L_DEFAULT_KEY                                      3
#define L_DEFAULT_SERVER                                   4
#define L_END_INCLUDE                                      5
#define L_END_INPUT                                        6
#define L_EOS                                              7
#define L_HOST                                             8
#define L_IP4ADDR                                          9
#define L_IP6ADDR                                          10
#define L_KEY                                              11
#define L_LBRACE                                           12
#define L_OPTIONS                                          13
#define L_QSTRING                                          14
#define L_QUOTE                                            15
#define L_RBRACE                                           16
#define L_SECRET                                           17
#define L_SERVER                                           18
#define L_STRING                                           20
#define L_INTEGER					   21

static struct keywordtoken keyword_tokens[] = {
        { "{",                          L_LBRACE },
        { "}",                          L_RBRACE },
        { ";",                          L_EOS },
	{ "default-server",		L_DEFAULT_SERVER },
	{ "default-key",		L_DEFAULT_KEY },
	{ "key",			L_KEY },
	{ "host",			L_HOST },
	{ "algorithm",			L_ALGORITHM },
	{ "secret",			L_SECRET },
	{ "options", 			L_OPTIONS },
	{ "server", 			L_SERVER },
        { NULL, 0 }
};


/* This table contains all the L_* values that are not stored in any other
 * keywordtoken table.
 */

static struct keywordtoken misc_tokens[] = {
	{ "<end-of-include>", L_END_INCLUDE },
	{ "<end-of-input>", L_END_INPUT },
	{ "<ip4 address>", L_IP4ADDR },
	{ "<ip6 address>", L_IP6ADDR },
	{ "<quoted string>", L_QSTRING },
	{ "<quote character>", L_QUOTE },
	{ "<string>", L_STRING },
};



static isc_result_t
parse_file(ndcpcontext *pctx, dns_c_ndcctx_t **context);

static isc_result_t
parse_statement(ndcpcontext *pctx);
static isc_result_t
parse_options(ndcpcontext *pctx, dns_c_ndcopts_t **opts);
static isc_result_t
parse_serverstmt(ndcpcontext *pctx, dns_c_ndcserver_t **server);
static isc_result_t
parse_keystmt(ndcpcontext *pctx, dns_c_kdeflist_t *keys);

static const char *
keyword2str(isc_int32_t val);
static isc_boolean_t
eat(ndcpcontext *pctx, isc_uint32_t token);
static isc_boolean_t
eat_eos(ndcpcontext *pctx);
static isc_boolean_t
eat_lbrace(ndcpcontext *pctx);
static isc_boolean_t
eat_rbrace(ndcpcontext *pctx);

static isc_boolean_t
looking_at(ndcpcontext *pctx, isc_uint32_t token);
static isc_boolean_t
looking_at_anystring(ndcpcontext *pctx);

static isc_result_t
parser_setup(ndcpcontext *pctx, isc_mem_t *mem, const char *filename);
static void
parser_complain(isc_boolean_t is_warning, isc_boolean_t print_last_token,
		ndcpcontext *pctx, const char *format, va_list args);
static void
parser_error(ndcpcontext *pctx, isc_boolean_t lasttoken, const char *fmt, ...);
static void
parser_warn(ndcpcontext *pctx, isc_boolean_t lasttoken, const char *fmt, ...);
static isc_boolean_t
is_ip6addr(const char *string, struct in6_addr *addr);
static isc_boolean_t
is_ip4addr(const char *string, struct in_addr *addr);
static isc_result_t
getnexttoken(ndcpcontext *pctx);
static void
syntax_error(ndcpcontext *pctx, isc_uint32_t keyword);


/* *********************************************************************** */
/*	              PUBLIC DATA STRUCTURE FUNCTIONS                      */
/* *********************************************************************** */

isc_result_t
dns_c_ndcctx_new(isc_mem_t *mem, dns_c_ndcctx_t **ctx) {
	dns_c_ndcctx_t *newctx;

	REQUIRE(ctx != NULL);
	REQUIRE(*ctx == NULL);

	newctx = isc_mem_get(mem, sizeof *newctx);
	if (newctx == NULL)
		return (ISC_R_NOMEMORY);
	
	newctx->mem = mem;
	newctx->magic = DNS_C_NDCCTX_MAGIC;
	newctx->opts = NULL;
	newctx->servers = NULL;
	newctx->keys = NULL;

	*ctx = newctx;
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_destroy(dns_c_ndcctx_t **ndcctx) {
	dns_c_ndcctx_t *ctx;
	isc_mem_t *mem;
	
	REQUIRE(ndcctx != NULL);

	ctx = *ndcctx;
	
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));

	mem = ctx->mem;
	ctx->mem = NULL;

	if (ctx->opts != NULL)
		dns_c_ndcopts_destroy(&ctx->opts);

	if (ctx->servers != NULL)
		dns_c_ndcserverlist_destroy(&ctx->servers);

	if (ctx->keys != NULL)
		dns_c_kdeflist_delete(&ctx->keys);

	ctx->magic = 0;
	isc_mem_put(mem, ctx, sizeof *ctx);

	*ndcctx = NULL;

	return (ISC_R_SUCCESS);
}


void
dns_c_ndcctx_print(FILE *fp, dns_c_ndcctx_t *ctx) {
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));

	if (ctx->opts != NULL)
		dns_c_ndcopts_print(fp, ctx->opts);

	if (ctx->servers != NULL)
		dns_c_ndcserverlist_print(fp, ctx->servers);

	if (ctx->keys != NULL)
		dns_c_kdeflist_print(fp, 0, ctx->keys);
}


void
dns_c_ndcopts_print(FILE *fp, dns_c_ndcopts_t *opts) {
	REQUIRE(fp != NULL);
	REQUIRE(DNS_C_NDCOPTIONS_VALID(opts));

	fprintf(fp, "options {\n");
	if (opts->defserver != NULL)
		fprintf(fp, "\tdefault-server %s;\n", opts->defserver);

	if (opts->defkey != NULL)
		fprintf(fp, "\tdefault-key %s;\n", opts->defkey);

	fprintf(fp, "};\n\n\n");
}


void
dns_c_ndcserverlist_print(FILE *fp, dns_c_ndcserverlist_t *servers) {
	dns_c_ndcserver_t *server;
	
	REQUIRE(DNS_C_NDCSERVERLIST_VALID(servers));
	REQUIRE(fp != NULL);

	server = dns_c_ndcserverlist_first(servers);
	while (server != NULL) {
		dns_c_ndcserver_print(fp, server);
		server = dns_c_ndcserverlist_next(server);
	}
}


void
dns_c_ndcserver_print(FILE *fp, dns_c_ndcserver_t *server) {
	fprintf(fp, "server %s {\n", server->name);
	if (server->key != NULL)
		fprintf(fp, "\tkey %s;\n", server->key);

	if (server->host != NULL)
		fprintf(fp, "\thost %s;\n", server->host);

	fprintf(fp, "};\n\n\n");
}


isc_result_t
dns_c_ndcctx_setoptions(dns_c_ndcctx_t *ctx, dns_c_ndcopts_t *opts) {
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(opts == NULL || DNS_C_NDCOPTIONS_VALID(opts));

	existed = ISC_TF(ctx->opts != NULL);
	
	ctx->opts = opts;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_getoptions(dns_c_ndcctx_t *ctx, dns_c_ndcopts_t **opts) {
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(opts != NULL);
	REQUIRE(*opts == NULL);
	
	*opts = ctx->opts;

	if (ctx->opts == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_setservers(dns_c_ndcctx_t *ctx, dns_c_ndcserverlist_t *servers) {
	isc_boolean_t existed;

	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(servers == NULL || DNS_C_NDCSERVERLIST_VALID(servers));

	existed = ISC_TF(ctx->servers != NULL);
	
	ctx->servers = servers;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_getservers(dns_c_ndcctx_t *ctx, dns_c_ndcserverlist_t **servers) {
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(servers != NULL);
	REQUIRE(*servers == NULL);
	
	*servers = ctx->servers;

	if (ctx->servers == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_addserver(dns_c_ndcctx_t *ctx, dns_c_ndcserver_t **server) {
	isc_result_t result;
	
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(server != NULL);
	REQUIRE(DNS_C_NDCSERVER_VALID(*server));
	
	if (ctx->servers == NULL) {
		result = dns_c_ndcserverlist_new(ctx->mem, &ctx->servers);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	ISC_LIST_APPEND(ctx->servers->list, *server, next);
	*server = NULL;

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_getserver(dns_c_ndcctx_t *ctx, const char *name,
		       dns_c_ndcserver_t **server)
{
	dns_c_ndcserver_t *s;

	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(name != NULL);
	REQUIRE(server != NULL && *server == NULL);

	if (ctx->servers != NULL) {
		for (s = ISC_LIST_HEAD(ctx->servers->list); s != NULL;
		     s = ISC_LIST_NEXT(s, next)) {
			INSIST(s->name != NULL);
			if (strcasecmp(s->name, name) == 0) {
				*server = s;
				return (ISC_R_SUCCESS);
			}
		}
	}

	return (ISC_R_NOTFOUND);
}

isc_result_t
dns_c_ndcctx_getkeys(dns_c_ndcctx_t *ctx, dns_c_kdeflist_t **keys) {
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(keys != NULL);
	REQUIRE(*keys == NULL);

	*keys = ctx->keys;

	if (ctx->keys == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcctx_setkeys(dns_c_ndcctx_t *ctx, dns_c_kdeflist_t *keys) {
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(DNS_C_KDEFLIST_VALID(keys));

	existed = ISC_TF(ctx->keys != NULL);
	
	ctx->keys = keys;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcserverlist_new(isc_mem_t *mem, dns_c_ndcserverlist_t **servers) {
	dns_c_ndcserverlist_t *newlist;

	REQUIRE(servers != NULL);
	REQUIRE(*servers == NULL);
	
	newlist = isc_mem_get(mem, sizeof *newlist);
	if (newlist == NULL)
		return (ISC_R_NOMEMORY);

	newlist->mem = mem;
	newlist->magic = DNS_C_NDCSERVERLIST_MAGIC;
	ISC_LIST_INIT(newlist->list);

	*servers = newlist;
	
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcserverlist_destroy(dns_c_ndcserverlist_t **servers) {
	dns_c_ndcserverlist_t *slist;
	dns_c_ndcserver_t *server;
	dns_c_ndcserver_t *p;
	isc_mem_t *mem;

	REQUIRE(servers != NULL);

	slist = *servers;

	REQUIRE(DNS_C_NDCSERVERLIST_VALID(slist));

	server = ISC_LIST_HEAD(slist->list);
	while (server != NULL) {
		p = ISC_LIST_NEXT(server, next);
		ISC_LIST_UNLINK(slist->list, server, next);
		dns_c_ndcserver_destroy(&server);
		server = p;
	}

	mem = slist->mem;
	slist->mem = NULL;
	slist->magic = 0;
	isc_mem_put(mem, slist, sizeof *slist);

	return (ISC_R_SUCCESS);
}

dns_c_ndcserver_t *
dns_c_ndcserverlist_first(dns_c_ndcserverlist_t *servers) {
	REQUIRE(DNS_C_NDCSERVERLIST_VALID(servers));
	
	return (ISC_LIST_HEAD(servers->list));
}

dns_c_ndcserver_t *
dns_c_ndcserverlist_next(dns_c_ndcserver_t *server) {
	REQUIRE(DNS_C_NDCSERVER_VALID(server));

	return (ISC_LIST_NEXT(server, next));
}


isc_result_t
dns_c_ndcopts_new(isc_mem_t *mem, dns_c_ndcopts_t **opts) {
	dns_c_ndcopts_t *newo;
	
	REQUIRE(opts != NULL);
	REQUIRE(*opts == NULL);

	newo = isc_mem_get(mem, sizeof *newo);
	if (newo == NULL)
		return (ISC_R_NOMEMORY);

	newo->magic = DNS_C_NDCOPTIONS_MAGIC;
	newo->mem = mem;
	newo->defserver = NULL;
	newo->defkey = NULL;

	*opts = newo;
	
	return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcopts_destroy(dns_c_ndcopts_t **opts) {
	dns_c_ndcopts_t *o;
	isc_mem_t *mem;
	
	REQUIRE(opts != NULL);

	o = *opts;
	
	REQUIRE(DNS_C_NDCOPTIONS_VALID(o));

	if (o->defserver != NULL)
		isc_mem_free(o->mem, o->defserver);

	if (o->defkey != NULL)
		isc_mem_free(o->mem, o->defkey);

	mem = o->mem;
	o->mem = NULL;
	o->magic = 0;

	isc_mem_put(mem, o, sizeof *o);

	return (ISC_R_SUCCESS);
}
	
		
isc_result_t
dns_c_ndcopts_getdefserver(dns_c_ndcopts_t *opts, const char **retval) {
	REQUIRE(DNS_C_NDCOPTIONS_VALID(opts));
	REQUIRE(retval != NULL);
	REQUIRE(*retval == NULL);

	*retval = opts->defserver;

	if (opts->defserver == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcopts_getdefkey(dns_c_ndcopts_t *opts, const char **retval) {
	REQUIRE(DNS_C_NDCOPTIONS_VALID(opts));
	REQUIRE(retval != NULL);
	REQUIRE(*retval == NULL);

	*retval = opts->defkey;

	if (opts->defkey == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcopts_setdefserver(dns_c_ndcopts_t *opts, const char *newval) {
	isc_boolean_t existed;

	REQUIRE(DNS_C_NDCOPTIONS_VALID(opts));
	REQUIRE(newval == NULL || *newval != '\0');

	existed = ISC_TF(opts->defserver != NULL);

	if (newval != NULL) {
		opts->defserver = isc_mem_strdup(opts->mem, newval);
		if (opts->defserver == NULL)
			return (ISC_R_NOMEMORY);

	} else
		opts->defserver = NULL;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcopts_setdefkey(dns_c_ndcopts_t *opts, const char *newval) {
	isc_boolean_t existed;

	REQUIRE(DNS_C_NDCOPTIONS_VALID(opts));
	REQUIRE(newval == NULL || *newval != '\0');

	existed = ISC_TF(opts->defkey != NULL);
	
	if (newval != NULL) {
		opts->defkey = isc_mem_strdup(opts->mem, newval);
		if (opts->defkey == NULL)
			return (ISC_R_NOMEMORY);

	} else
		opts->defkey = NULL;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}



isc_result_t
dns_c_ndcserver_new(isc_mem_t *mem, dns_c_ndcserver_t **server) {
	dns_c_ndcserver_t *serv = NULL;
	
	REQUIRE(server != NULL);
	REQUIRE(*server == NULL);

	serv = isc_mem_get(mem, sizeof *serv);
	if (serv == NULL)
		return (ISC_R_NOMEMORY);

	serv->magic = DNS_C_NDCSERVER_MAGIC;
	serv->mem = mem;
	serv->name = NULL;
	serv->key = NULL;
	serv->host = NULL;
	ISC_LINK_INIT(serv, next);

	*server = serv;

	return (ISC_R_SUCCESS);
}
	
isc_result_t
dns_c_ndcserver_destroy(dns_c_ndcserver_t **server) {
	dns_c_ndcserver_t *serv;
	isc_mem_t *mem;
	
	REQUIRE(server != NULL);

	serv = *server ;
	REQUIRE(DNS_C_NDCSERVER_VALID(serv));

	if (serv->name != NULL)
		isc_mem_free(serv->mem, serv->name);
	
	if (serv->key != NULL)
		isc_mem_free(serv->mem, serv->key);
	
	if (serv->host != NULL)
		isc_mem_free(serv->mem, serv->host);

	mem = serv->mem;
	serv->mem = NULL;
	serv->magic = 0;

	isc_mem_put(mem, serv, sizeof *serv);

	return (ISC_R_SUCCESS);
}

	
isc_result_t
dns_c_ndcserver_setkey(dns_c_ndcserver_t *server, const char *val) {
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_NDCSERVER_VALID(server));

	existed = ISC_TF(server->key != NULL);

	if (val != NULL) {
		server->key = isc_mem_strdup(server->mem, val);
		if (server->key == NULL)
			return (ISC_R_NOMEMORY);

	} else
		server->key = NULL;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcserver_setname(dns_c_ndcserver_t *server, const char *val) {
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_NDCSERVER_VALID(server));

	existed = ISC_TF(server->name != NULL);

	if (val != NULL) {
		server->name = isc_mem_strdup(server->mem, val);
		if (server->name == NULL)
			return (ISC_R_NOMEMORY);

	} else
		server->name = NULL;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcserver_sethost(dns_c_ndcserver_t *server, const char *val) {
	isc_boolean_t existed;
	
	REQUIRE(DNS_C_NDCSERVER_VALID(server));

	existed = ISC_TF(server->host != NULL);

	if (val != NULL) {
		server->host = isc_mem_strdup(server->mem, val);
		if (server->host == NULL)
			return (ISC_R_NOMEMORY);

	} else
		server->host = NULL;

	if (existed)
		return (ISC_R_EXISTS);
	else
		return (ISC_R_SUCCESS);
}
	
isc_result_t
dns_c_ndcserver_getkey(dns_c_ndcserver_t *server, const char **val) {
	REQUIRE(DNS_C_NDCSERVER_VALID(server));
	REQUIRE(val != NULL);
	REQUIRE (*val == NULL);

	*val = server->key;

	if (server->key == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

isc_result_t
dns_c_ndcserver_gethost(dns_c_ndcserver_t *server, const char **val) {
	REQUIRE(DNS_C_NDCSERVER_VALID(server));
	REQUIRE(val != NULL);
	REQUIRE (*val == NULL);

	*val = server->host;

	if (server->host == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}


isc_result_t
dns_c_ndcserver_getname(dns_c_ndcserver_t *server, const char **val) {
	REQUIRE(DNS_C_NDCSERVER_VALID(server));
	REQUIRE(val != NULL);
	REQUIRE (*val == NULL);

	*val = server->name;

	if (server->name == NULL)
		return (ISC_R_NOTFOUND);
	else
		return (ISC_R_SUCCESS);
}

/* *********************************************************************** */
/*                       PUBLIC PARSING ROUTINE                            */
/* *********************************************************************** */

isc_result_t
dns_c_ndcparseconf(const char *filename, isc_mem_t *mem,
		   dns_c_ndcctx_t **ndcctx)
{
	ndcpcontext pctx;
	isc_result_t result;
	dns_c_ndcctx_t *aConfig;
	
	result = parser_setup(&pctx, mem, filename);
	if (result != ISC_R_SUCCESS)
		goto done;
	
	result = parse_file(&pctx, &aConfig);
	if (result != ISC_R_SUCCESS && aConfig != NULL)
		dns_c_ndcctx_destroy(&aConfig);

 done:
	if (pctx.thelexer != NULL)
		isc_lex_destroy(&pctx.thelexer);
	
	if (pctx.thekeywords != NULL)
		isc_symtab_destroy(&pctx.thekeywords);

	*ndcctx = aConfig;
	
	return (result);
}

/* *********************************************************************** */
/*                      PRIVATE PARSING ROUTINES                           */
/* *********************************************************************** */

static isc_result_t
parse_file(ndcpcontext *pctx, dns_c_ndcctx_t **context) {
	isc_result_t result;
	isc_boolean_t done = ISC_FALSE;

	result = dns_c_ndcctx_new(pctx->themem, context);
	if (result != ISC_R_SUCCESS)
		return (result);

	pctx->thecontext = *context;

	result = getnexttoken(pctx);
	done = ISC_TF(result != ISC_R_SUCCESS);
	
	while (!done) {
		switch (pctx->currtok) {
		case L_END_INPUT:
			result = ISC_R_SUCCESS;
			done = ISC_TRUE;
			break;

		default:
			result = parse_statement(pctx);
			if (result != ISC_R_SUCCESS) {
				done = ISC_TRUE;
				break;
			}
		}
	}

	return (result);
}

static isc_result_t
parse_statement(ndcpcontext *pctx) {
	isc_result_t result;
	dns_c_ndcctx_t *ctx = pctx->thecontext;
	dns_c_ndcopts_t *opts = NULL;
	dns_c_ndcopts_t *tmpopts = NULL;
	dns_c_ndcserver_t  *server = NULL;
	dns_c_kdeflist_t *keys = NULL;
	
	switch (pctx->currtok) {
	case L_OPTIONS:
		result = parse_options(pctx, &opts);
		if (result == ISC_R_SUCCESS) {
			(void)dns_c_ndcctx_getoptions(ctx, &tmpopts);
			result = dns_c_ndcctx_setoptions(ctx, opts);
			if (result == ISC_R_EXISTS) {
				parser_warn(pctx, ISC_FALSE,
					    "redefining 'options'");
				result = ISC_R_SUCCESS;
				dns_c_ndcopts_destroy(&tmpopts);
			}

			opts = NULL;
		}
		break;

	case L_SERVER:
		result = parse_serverstmt(pctx, &server);
		if (result == ISC_R_SUCCESS)
			result = dns_c_ndcctx_addserver(ctx, &server);
		break;

	case L_KEY:
		keys = NULL;
		result = dns_c_ndcctx_getkeys(ctx, &keys);
		if (result == ISC_R_NOTFOUND) {
			result = dns_c_kdeflist_new(pctx->themem, &keys);
			if (result != ISC_R_SUCCESS)
				return (result);
			dns_c_ndcctx_setkeys(ctx, keys);
		}

		result = parse_keystmt(pctx, keys);
		break;
		
	default:
		syntax_error(pctx, pctx->currtok);
		result = ISC_R_FAILURE;
		break;
	}

	if (result == ISC_R_SUCCESS)
		if (!eat_eos(pctx))
			result = ISC_R_FAILURE;

	if (server != NULL)
		dns_c_ndcserver_destroy(&server);

	if (opts != NULL)
		dns_c_ndcopts_destroy(&opts);
							
	return (result);
}

static isc_result_t
parse_options(ndcpcontext *pctx, dns_c_ndcopts_t **opts) {
	isc_result_t result;
	isc_uint32_t option;
	dns_c_ndcopts_t *newopts = NULL;
	dns_c_ndcctx_t *cfgctx = pctx->thecontext;

	REQUIRE(DNS_C_NDCCTX_VALID(cfgctx));
	
	if (!eat(pctx, L_OPTIONS) || !eat_lbrace(pctx))
		return (ISC_R_FAILURE);

	result = dns_c_ndcopts_new(cfgctx->mem, &newopts);
	if (result != ISC_R_SUCCESS)
		return (result);
	
	result = ISC_R_SUCCESS;
	while (result == ISC_R_SUCCESS && pctx->currtok != L_RBRACE) {
		option = pctx->currtok;

		if (!eat(pctx, pctx->currtok))
			return (ISC_R_FAILURE);
		
		switch (option) {
		case L_DEFAULT_SERVER:
			if (!looking_at_anystring(pctx))
				return (result);

			result = dns_c_ndcopts_setdefserver(newopts,
							    pctx->tokstr);
			if (result == ISC_R_SUCCESS)
				result = getnexttoken(pctx);
			
			if (result != ISC_R_SUCCESS)
				return (result);

			break;
				
		case L_DEFAULT_KEY:
			if (!looking_at_anystring(pctx))
				return (result);
			
			result = dns_c_ndcopts_setdefkey(newopts,
							 pctx->tokstr);

			if (result == ISC_R_SUCCESS)
				result = getnexttoken(pctx);
			
			if (result != ISC_R_SUCCESS)
				return (result);
			break;

		default:
			syntax_error(pctx, pctx->currtok);
			result = ISC_R_FAILURE;
			break;
		}

		if (result == ISC_R_EXISTS) {
			parser_warn(pctx, ISC_FALSE, "redefining %s",
				    keyword2str(option));
			result = ISC_R_SUCCESS;

		} else if (result == ISC_R_SUCCESS && !eat_eos(pctx))
			result = ISC_R_FAILURE;
	}

	if (result == ISC_R_SUCCESS && !eat_rbrace(pctx))
		result = ISC_R_FAILURE;

	if (result == ISC_R_SUCCESS)
		*opts = newopts;
	else
		dns_c_ndcopts_destroy(&newopts);
	
	return (result);
}


static isc_result_t
parse_serverstmt(ndcpcontext *pctx, dns_c_ndcserver_t **server) {
	isc_result_t result = ISC_R_FAILURE;
	char *servername = NULL;
	char *keyname = NULL;
	char *hostname = NULL;
	dns_c_ndcserver_t *serv = NULL;
		
	if (!eat(pctx, L_SERVER))
		return (ISC_R_FAILURE);

	if (!looking_at_anystring(pctx))
		return (result);
	else if (pctx->tokstr[0] == '\0') {
		parser_error(pctx, ISC_TRUE,
			     "zero-length server name is illegal");
		return (ISC_R_FAILURE);
	}

	servername = isc_mem_strdup(pctx->themem, pctx->tokstr);
	if (servername == NULL) {
		result = ISC_R_FAILURE;
		goto done;
	}

	result = getnexttoken(pctx);

	if (result != ISC_R_SUCCESS || !eat(pctx, L_LBRACE)) {
		result = ISC_R_FAILURE;
		goto done;
	}

	while (pctx->currtok != L_RBRACE) {
		isc_int32_t field = pctx->currtok;

		if (!eat(pctx, field)) {
			result = ISC_R_FAILURE;
			goto done;
		}
		
		switch (field) {
		case L_KEY:
			if (!looking_at_anystring(pctx)) {
				result = ISC_R_FAILURE;
				goto done;
			}

			if (keyname != NULL) {
				parser_warn(pctx, ISC_FALSE,
					    "multiple 'key' definitions");
				isc_mem_free(pctx->themem, keyname);
			}

			keyname = isc_mem_strdup(pctx->themem, pctx->tokstr);
			if (keyname == NULL)
				result = ISC_R_NOMEMORY;
			
			if (result == ISC_R_SUCCESS)
				result = getnexttoken(pctx);
			
			break;

		case L_HOST:
			if (!looking_at_anystring(pctx)) {
				result = ISC_R_FAILURE;
				goto done;
			}

			if (hostname != NULL) {
				parser_warn(pctx, ISC_FALSE,
					    "multiple 'host' definitions");
				isc_mem_free(pctx->themem, hostname);
			}

			hostname = isc_mem_strdup(pctx->themem, pctx->tokstr);
			if (hostname == NULL)
				result = ISC_R_NOMEMORY;
			
			if (result == ISC_R_SUCCESS)
				result = getnexttoken(pctx);
			
			break;

		default:
			syntax_error(pctx, field);
			result = ISC_R_FAILURE;
			goto done;
		}

		if (result != ISC_R_SUCCESS)
			goto done;
		
		if (!eat_eos(pctx)) {
			result = ISC_R_FAILURE;
			goto done;
		}
	}

	if (!eat(pctx, L_RBRACE)) {
		result = ISC_R_FAILURE;
		goto done;
	}

	REQUIRE(servername != NULL);

	if (keyname == NULL) {
		parser_error(pctx, ISC_FALSE,
			     "server statement requiresult a key value");
		result = ISC_R_FAILURE;
		goto done;
	}

	result = dns_c_ndcserver_new(pctx->themem, &serv);
	if (result != ISC_R_SUCCESS)
		goto done;

	result = dns_c_ndcserver_setname(serv, servername);
	if (result != ISC_R_SUCCESS)
		goto done;
	
	result = dns_c_ndcserver_setkey(serv, keyname);
	if (result != ISC_R_SUCCESS)
		goto done;

	result = dns_c_ndcserver_sethost(serv, hostname);
	if (result != ISC_R_SUCCESS)
		goto done;

	*server = serv;
	serv = NULL;

done:
	if (serv != NULL)
		dns_c_ndcserver_destroy(&serv);
	
	if (servername != NULL)
		isc_mem_free(pctx->themem, servername);

	if (keyname != NULL)
		isc_mem_free(pctx->themem, keyname);

	if (hostname != NULL)
		isc_mem_free(pctx->themem, hostname);

	return (result);
}


static isc_result_t
parse_keystmt(ndcpcontext *pctx, dns_c_kdeflist_t *keys) {
	isc_result_t result = ISC_R_FAILURE;
	dns_c_ndcctx_t *ctx = pctx->thecontext;
	dns_c_kdef_t *key = NULL;
	char *keyname = NULL;
	char *algorithm = NULL;
	char *secret = NULL;
	
	REQUIRE(DNS_C_NDCCTX_VALID(ctx));
	REQUIRE(DNS_C_KDEFLIST_VALID(keys));

	if (!eat(pctx, L_KEY))
		return (ISC_R_FAILURE);

	if (!looking_at_anystring(pctx))
		return (result);

	else if (pctx->tokstr[0] == '\0') {
		parser_error(pctx, ISC_TRUE,
			     "zero length key names are illegal");
		return (ISC_R_FAILURE);
	}

	keyname = isc_mem_strdup(pctx->themem, pctx->tokstr);

	result = getnexttoken(pctx);

	if (result != ISC_R_SUCCESS)
		goto done;

	if (!eat(pctx, L_LBRACE)) {
		result = ISC_R_FAILURE;
		goto done;
	}

	while (pctx->currtok != L_RBRACE) {
		isc_uint32_t field = pctx->currtok;

		if (!eat(pctx, field)) {
			result = ISC_R_FAILURE;
			goto done;
		}

		switch (field) {
		case L_ALGORITHM:
			if (!looking_at_anystring(pctx)) {
				result = ISC_R_FAILURE;
				goto done;
			}
			
			if (algorithm != NULL) {
				parser_warn(pctx, ISC_FALSE,
					    "multiple 'algorithm' values");
				isc_mem_free(pctx->themem, algorithm);
			}

			algorithm = isc_mem_strdup(pctx->themem, pctx->tokstr);
			if (algorithm == NULL)
				result = ISC_R_NOMEMORY;
			if (result == ISC_R_SUCCESS)
				result = getnexttoken(pctx);
			break;

		case L_SECRET:
			if (!looking_at_anystring(pctx)) {
				result = ISC_R_FAILURE;
				goto done;
			}
			
			if (secret != NULL) {
				parser_warn(pctx, ISC_FALSE,
					    "multiple 'secret' values");
				isc_mem_free(pctx->themem, secret);
			}

			secret = isc_mem_strdup(pctx->themem, pctx->tokstr);

			if (secret == NULL)
				result = ISC_R_NOMEMORY;

			if (result == ISC_R_SUCCESS)
				result = getnexttoken(pctx);
			break;

		default:
			syntax_error(pctx, field);
			result = ISC_R_FAILURE;
			break;
		}

		if (!eat_eos(pctx)) {
			result = ISC_R_FAILURE;
			goto done;
		}
	}

	if (!eat(pctx, L_RBRACE)) {
		result = ISC_R_FAILURE;
		goto done;
	}

	if (algorithm == NULL) {
		parser_error(pctx, ISC_FALSE, "missing 'algorithm'");
		result = ISC_R_FAILURE;

	} else if (*algorithm == '\0') {
		parser_error(pctx, ISC_FALSE, "zero length 'algorithm'");
		result = ISC_R_FAILURE;
	}
	
	if (secret == NULL) {
		parser_error(pctx, ISC_FALSE, "missing 'secret'");
		result = ISC_R_FAILURE;
	} else if (*secret == '\0') {
		parser_error(pctx, ISC_FALSE, "zero length 'secret'");
		result = ISC_R_FAILURE;
	}

	if (result != ISC_R_SUCCESS)
		goto done;
	
	result = dns_c_kdef_new(keys->mem, keyname, &key);
	if (result != ISC_R_SUCCESS)
		goto done;
	dns_c_kdeflist_append(keys, key, ISC_FALSE);

	result = dns_c_kdef_setalgorithm(key, algorithm);
	if (result != ISC_R_SUCCESS)
		goto done;

	result = dns_c_kdef_setsecret(key, secret);

done:
	if (keyname != NULL)
		isc_mem_free(pctx->themem,  keyname);

	if (algorithm != NULL)
		isc_mem_free(pctx->themem,  algorithm);

	if (secret != NULL)
		isc_mem_free(pctx->themem,  secret);

	return (result);
}
	
static const char *
keyword2str(isc_int32_t val) {
	int i;

	for (i = 0 ; keyword_tokens[i].token != NULL ; i++)
		if (keyword_tokens[i].yaccval == val)
			return (keyword_tokens[i].token);

	for (i = 0 ; misc_tokens[i].token != NULL ; i++)
		if (misc_tokens[i].yaccval == val)
			return (misc_tokens[i].token);

	return ("<UNKNOWN KEYWORD VALUE>");
}

static isc_boolean_t
eat(ndcpcontext *pctx, isc_uint32_t token) {
	isc_boolean_t rval = ISC_FALSE;
	
	if (looking_at(pctx, token))
		if (getnexttoken(pctx) == ISC_R_SUCCESS)
			rval = ISC_TRUE;

	return (rval);
}

static isc_boolean_t
looking_at(ndcpcontext *pctx, isc_uint32_t token) {
	isc_boolean_t rval = ISC_TRUE;
	
	if (pctx->currtok != token) {
		parser_error(pctx, ISC_TRUE, "expected a '%s'",
			     keyword2str(token));
		rval = ISC_FALSE;
	}

	return (rval);
}

static isc_boolean_t
looking_at_anystring(ndcpcontext *pctx) {
	if (pctx->currtok != L_STRING && pctx->currtok != L_QSTRING) {
		parser_error(pctx, ISC_TRUE, "expected a string");
		return (ISC_FALSE);
	}

	return (ISC_TRUE);
}

static isc_boolean_t
eat_lbrace(ndcpcontext *pctx) {
	return (eat(pctx, L_LBRACE));
}

static isc_boolean_t
eat_rbrace(ndcpcontext *pctx) {
	return (eat(pctx, L_RBRACE));
}

static isc_boolean_t
eat_eos(ndcpcontext *pctx) {
	return (eat(pctx, L_EOS));
}

/* ************************************************** */
/* *************      PRIVATE STUFF      ************ */
/* ************************************************** */

static isc_result_t
parser_setup(ndcpcontext *pctx, isc_mem_t *mem, const char *filename) {
	isc_result_t result;
	isc_lexspecials_t specials;
        struct keywordtoken *tok;
        isc_symvalue_t symval;

	pctx->themem = mem;
	pctx->thelexer = NULL;
	pctx->thekeywords = NULL;
	pctx->thecontext = NULL;
	pctx->errors = 0;
	pctx->warnings = 0;
	pctx->debug_lexer = ISC_TF(getenv("DEBUG_LEXER") != NULL);

	pctx->prevtok = pctx->currtok = 0;

	memset(&pctx->prevtokstr[0], 0x0, sizeof pctx->prevtokstr);
	memset(&pctx->tokstr[0], 0x0, sizeof pctx->tokstr);

	pctx->intval = 0;
	memset(&pctx->ip4addr, 0x0, sizeof pctx->ip4addr);
	memset(&pctx->ip6addr, 0x0, sizeof pctx->ip6addr);

	result = isc_lex_create(mem, CONF_MAX_IDENT, &pctx->thelexer);
        if (result != ISC_R_SUCCESS) {
                isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                              DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
                              "%s: Error creating lexer",
                              "dns_c_parse_namedconf");
		return (ISC_R_FAILURE);
	}

	memset(specials, 0x0, sizeof specials);
	
        specials['{'] = 1;
        specials['}'] = 1;
        specials[';'] = 1;
        specials['"'] = 1;
        isc_lex_setspecials(pctx->thelexer, specials);
	
        isc_lex_setcomments(pctx->thelexer, (ISC_LEXCOMMENT_C |
					     ISC_LEXCOMMENT_CPLUSPLUS |
					     ISC_LEXCOMMENT_SHELL));

        result = isc_lex_openfile(pctx->thelexer, filename);
        if (result != ISC_R_SUCCESS) {
                isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                              DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
                              "%s: Error opening file %s",
                              "dns_c_parse_namedconf", filename);
		return (result);
        }

	/*
	 * 97 == buckey size: higest prime < 100
	 */
	result = isc_symtab_create(mem, 97, NULL, NULL, ISC_FALSE,
				   &pctx->thekeywords);
	if (result != ISC_R_SUCCESS) {
                isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
                              DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
                              "%s: Error creating symtab",
                              "dns_c_parse_namedconf", filename);
		return (result);
	}

        /*
	 * Stick all the keywords into the main symbol table.
	 */
        for (tok = &keyword_tokens[0] ; tok->token != NULL ; tok++) {
                symval.as_integer = tok->yaccval;
                result = isc_symtab_define(pctx->thekeywords, tok->token,
					KEYWORD_SYM_TYPE, symval,
					isc_symexists_reject);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				      DNS_LOGMODULE_CONFIG, ISC_LOG_CRITICAL,
				      "%s: Error installing keyword",
				      "dns_c_parse_namedconf");
			return (result);
		}
        }

	return (ISC_R_SUCCESS);
}

static void
parser_complain(isc_boolean_t is_warning, isc_boolean_t print_last_token,
		ndcpcontext *pctx,
                const char *format, va_list args)
{
        static char where[ISC_DIR_PATHMAX + 100];
        static char message[2048];
	int level = ISC_LOG_CRITICAL;
	const char *filename = isc_lex_getsourcename(pctx->thelexer);
	unsigned long lineno = isc_lex_getsourceline(pctx->thelexer);

        /*
         * We can't get a trace of the include files we may be nested in
         * (lex.c has the structuresult hidden). So we only report the current
         * file.
         */
        if (filename == NULL)
                filename = "(none)";

	if (is_warning)
		level = ISC_LOG_WARNING;

        sprintf(where, "%s:%lu: ", filename, lineno);
	vsnprintf(message, sizeof(message), format, args);

        if (print_last_token) {
		if (dns_lctx != NULL)
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				       DNS_LOGMODULE_CONFIG, level,
				       "%s%s near '%s'", where, message,
				      pctx->tokstr);

		else
			fprintf(stderr, "%s%s near '%s'\n", where, message,
				pctx->tokstr);

        } else {
		if (dns_lctx != NULL)
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_CONFIG,
				       DNS_LOGMODULE_CONFIG, level,
				       "%s%s", where, message);

		else
			fprintf(stderr, "%s%s\n", where, message);
        }
}

/*
 * For reporting items that are semantic, but not syntactic errors
 */
static void
parser_error(ndcpcontext *pctx, isc_boolean_t lasttoken, const char *fmt, ...)
{
        va_list args;

        va_start(args, fmt);
        parser_complain(ISC_TRUE, lasttoken, pctx, fmt, args);
        va_end(args);

        pctx->errors++;
}


static void
parser_warn(ndcpcontext *pctx, isc_boolean_t lasttoken, const char *fmt, ...) {
        va_list args;

        va_start(args, fmt);
        parser_complain(ISC_FALSE, lasttoken, pctx, fmt, args);
        va_end(args);

	pctx->warnings++;
}

/*
 * Conversion Routines
 */

static isc_boolean_t
is_ip6addr(const char *string, struct in6_addr *addr) {
        if (inet_pton(AF_INET6, string, addr) != 1)
                return (ISC_FALSE);

        return (ISC_TRUE);
}



static isc_boolean_t
is_ip4addr(const char *string, struct in_addr *addr) {
        char addrbuf[sizeof "xxx.xxx.xxx.xxx" + 1];
        const char *p = string;
        int dots = 0;
        char dot = '.';

        while (*p) {
                if (!isdigit(*p & 0xff) && *p != dot)
                        return (ISC_FALSE);

                else if (!isdigit(*p & 0xff))
                        dots++;

                p++;
        }

        if (dots > 3)
                return (ISC_FALSE);

        else if (dots < 3) {
                if (dots == 1) {
                        if (strlen(string) + 5 <= sizeof (addrbuf)) {
                                strcpy(addrbuf, string);
                                strcat(addrbuf, ".0.0");
                        } else
                                return (ISC_FALSE);

                } else if (dots == 2) {
                        if (strlen(string) + 3 <= sizeof (addrbuf)) {
                                strcpy(addrbuf, string);
                                strcat(addrbuf, ".0");
                        } else
                                return (ISC_FALSE);

                }
        } else if (strlen(string) < sizeof addrbuf)
                strcpy (addrbuf, string);

        else
                return (ISC_FALSE);
        
        if (inet_pton(AF_INET, addrbuf, addr) != 1)
                return (ISC_FALSE);

        return (ISC_TRUE);
}

static isc_result_t
getnexttoken(ndcpcontext *pctx) {
        isc_token_t token;
        isc_result_t result;
        isc_symvalue_t keywordtok;
        int options = (ISC_LEXOPT_EOF |
                       ISC_LEXOPT_NUMBER |
                       ISC_LEXOPT_QSTRING |
                       ISC_LEXOPT_NOMORE);

	pctx->prevtok = pctx->currtok;
	strcpy(pctx->prevtokstr, pctx->tokstr);
	
        result = isc_lex_gettoken(pctx->thelexer, options, &token);

        switch(result) {
        case ISC_R_SUCCESS:
		switch (token.type) {
		case isc_tokentype_unknown:
			if (pctx->debug_lexer)
				fprintf(stderr, "unknown token\n");

			result = ISC_R_FAILURE;
			break;

		case isc_tokentype_special:
		case isc_tokentype_string: {
			char *tokstr = &pctx->tokstr[0];
			
			if (token.type == isc_tokentype_special) {
				tokstr[0] = token.value.as_char;
				tokstr[1] = '\0';
			} else {
				strncpy(tokstr,token.value.as_textregion.base,
					CONF_MAX_IDENT);
				tokstr[CONF_MAX_IDENT - 1] = '\0';
			}

			if (pctx->debug_lexer)
				fprintf(stderr, "lexer token: %s : %s\n",
					(token.type == isc_tokentype_special ?
					 "special" : "string"),
					tokstr);

			result = isc_symtab_lookup(pctx->thekeywords, tokstr,
						   KEYWORD_SYM_TYPE,
						   &keywordtok);

			if (result != ISC_R_SUCCESS) {
				pctx->currtok = L_STRING;
				if (is_ip4addr(tokstr, &pctx->ip4addr))
					pctx->currtok = L_IP4ADDR;

				else if (is_ip6addr(tokstr, &pctx->ip6addr))
					pctx->currtok = L_IP6ADDR;

			} else
				pctx->currtok = keywordtok.as_integer;
				
			result = ISC_R_SUCCESS;
			break;
		}

		case isc_tokentype_number:
			pctx->intval = (isc_uint32_t)token.value.as_ulong;
			pctx->currtok = L_INTEGER;
			sprintf(pctx->tokstr, "%lu",
				(unsigned long)pctx->intval);

			if(pctx->debug_lexer)
				fprintf(stderr, "lexer token: number : %lu\n",
					(unsigned long)pctx->intval);

			break;

		case isc_tokentype_qstring:
			strncpy(&pctx->tokstr[0],
				token.value.as_textregion.base,
				CONF_MAX_IDENT);
			pctx->tokstr[CONF_MAX_IDENT - 1] = '\0';
			pctx->currtok = L_QSTRING;

			if (pctx->debug_lexer)
				fprintf(stderr,
					"lexer token: qstring : \"%s\"\n",
					pctx->tokstr);

			break;

		case isc_tokentype_eof:
			result = isc_lex_close(pctx->thelexer);
			INSIST(result == ISC_R_NOMORE ||
			       result == ISC_R_SUCCESS);

			if (isc_lex_getsourcename(pctx->thelexer) == NULL) {
				/*
				 * The only way to tell that we closed the
				 * main file and not an included file.
				 */
				if (pctx->debug_lexer)
					fprintf(stderr, "lexer token: EOF\n");

				pctx->currtok = L_END_INPUT;

			} else {
				if (pctx->debug_lexer)
					fprintf(stderr,
						"lexer token: EOF (main)\n");

				pctx->currtok = L_END_INCLUDE;
			}
			result = ISC_R_SUCCESS;
			break;

		case isc_tokentype_initialws:
			if (pctx->debug_lexer)
				fprintf(stderr, "lexer token: initial ws\n");

			result = ISC_R_FAILURE;
			break;

		case isc_tokentype_eol:
			if (pctx->debug_lexer)
				fprintf(stderr, "lexer token: eol\n");

			result = ISC_R_FAILURE;
			break;

		case isc_tokentype_nomore:
			if (pctx->debug_lexer)
				fprintf(stderr, "lexer token: nomore\n");

			result = ISC_R_FAILURE;
			break;
		}

		break;

	case ISC_R_EOF:
		pctx->currtok = 0;
		result = ISC_R_SUCCESS;
		break;

	case ISC_R_UNBALANCED:
		parser_error(pctx, ISC_TRUE, "unbalanced parentheses");
		result = ISC_R_FAILURE;
		break;

	case ISC_R_NOSPACE:
		parser_error(pctx, ISC_TRUE, "token too big");
		result = ISC_R_FAILURE;
		break;

	case ISC_R_UNEXPECTEDEND:
		parser_error(pctx, ISC_TRUE, "unexpected EOF");
		result = ISC_R_FAILURE;
		break;

	default:
		parser_error(pctx, ISC_TRUE, "unknown lexer error (%d)");
		result = ISC_R_FAILURE;
		break;
	}
		
	return (result);
}

static void
syntax_error(ndcpcontext *pctx, isc_uint32_t keyword) {
	parser_error(pctx, ISC_FALSE, "syntax error near '%s'",
		     keyword2str(keyword));
}
