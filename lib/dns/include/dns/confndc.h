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

/* $Id: confndc.h,v 1.8.2.1 2000/07/11 19:35:13 gson Exp $ */

#ifndef DNS_CONFNDC_H
#define DNS_CONFNDC_H 1

#include <isc/lang.h>
#include <isc/magic.h>

#include <dns/confkeys.h>

#define DNS_C_NDCCTX_MAGIC		0xabcdef01
#define DNS_C_NDCSERVERLIST_MAGIC	0x12345678
#define DNS_C_NDCOPTIONS_MAGIC		0x2468ace1
#define DNS_C_NDCSERVER_MAGIC		0xaaabbbcc

#define DNS_C_NDCCTX_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_C_NDCCTX_MAGIC)
#define DNS_C_NDCOPTIONS_VALID(ptr) \
	ISC_MAGIC_VALID(ptr, DNS_C_NDCOPTIONS_MAGIC)
#define DNS_C_NDCSERVERLIST_VALID(ptr) \
	ISC_MAGIC_VALID(ptr, DNS_C_NDCSERVERLIST_MAGIC)
#define DNS_C_NDCSERVER_VALID(ptr) \
	ISC_MAGIC_VALID(ptr, DNS_C_NDCSERVER_MAGIC)

typedef struct dns_c_ndcctx		dns_c_ndcctx_t;
typedef struct dns_c_ndcopts		dns_c_ndcopts_t;
typedef struct dns_c_ndcserver		dns_c_ndcserver_t;
typedef struct dns_c_ndcserverlist	dns_c_ndcserverlist_t;
typedef struct dns_c_ndckey		dnc_c_ndckey_t;

struct  dns_c_ndcctx {
	isc_uint32_t		magic;
	isc_mem_t	       *mem;
	
	dns_c_ndcopts_t	       *opts;
	dns_c_ndcserverlist_t  *servers;
	dns_c_kdeflist_t       *keys;
};

struct dns_c_ndcopts {
	isc_uint32_t	magic;
	isc_mem_t      *mem;

	char	       *defserver;
	char	       *defkey;
};

struct dns_c_ndcserverlist {
	isc_uint32_t			magic;
	isc_mem_t		       *mem;

	ISC_LIST(dns_c_ndcserver_t)	list;
};
	
struct dns_c_ndcserver {
	isc_uint32_t			magic;
	isc_mem_t		       *mem;

	char			       *name;
	char			       *key;
	char			       *host;
	ISC_LINK(dns_c_ndcserver_t) 	next;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

/*
 * All the 'set' functions do not delete the replaced value if one exists,
 * so if setting a value for a second time, be sure to 'get' the original
 * value first and do something with it
 */

isc_result_t
dns_c_ndcctx_new(isc_mem_t *mem, dns_c_ndcctx_t **ctx);

void
dns_c_ndcctx_destroy(dns_c_ndcctx_t **ctx);

isc_result_t
dns_c_ndcctx_setoptions(dns_c_ndcctx_t *ctx, dns_c_ndcopts_t *opts);

isc_result_t
dns_c_ndcctx_getoptions(dns_c_ndcctx_t *ctx, dns_c_ndcopts_t **opts);

isc_result_t
dns_c_ndcctx_setservers(dns_c_ndcctx_t *ctx, dns_c_ndcserverlist_t *servers);

isc_result_t
dns_c_ndcctx_getservers(dns_c_ndcctx_t *ctx, dns_c_ndcserverlist_t **servers);

isc_result_t
dns_c_ndcctx_addserver(dns_c_ndcctx_t *ctx, dns_c_ndcserver_t **server);

isc_result_t
dns_c_ndcctx_getserver(dns_c_ndcctx_t *ctx, const char *name,
		       dns_c_ndcserver_t **server);

isc_result_t
dns_c_ndcctx_getkeys(dns_c_ndcctx_t *ctx, dns_c_kdeflist_t **list);

isc_result_t
dns_c_ndcctx_setkeys(dns_c_ndcctx_t *ctx, dns_c_kdeflist_t *list);

isc_result_t
dns_c_ndcctx_addkey(dns_c_ndcctx_t *ctx, dns_c_kdef_t **key);

/* SERVER LIST */
isc_result_t
dns_c_ndcserverlist_new(isc_mem_t *mem, dns_c_ndcserverlist_t **servers);

isc_result_t
dns_c_ndcserverlist_destroy(dns_c_ndcserverlist_t **servers);

dns_c_ndcserver_t *
dns_c_ndcserverlist_first(dns_c_ndcserverlist_t *servers);

dns_c_ndcserver_t *
dns_c_ndcserverlist_next(dns_c_ndcserver_t *servers);

/* SERVER */
isc_result_t
dns_c_ndcserver_new(isc_mem_t *mem, dns_c_ndcserver_t **server);
isc_result_t
dns_c_ndcserver_destroy(dns_c_ndcserver_t **server);
isc_result_t
dns_c_ndcserver_setkey(dns_c_ndcserver_t *server, const char *val);

isc_result_t
dns_c_ndcserver_sethost(dns_c_ndcserver_t *server, const char *val);

isc_result_t
dns_c_ndcserver_setname(dns_c_ndcserver_t *server, const char *val);

isc_result_t
dns_c_ndcserver_getkey(dns_c_ndcserver_t *server, const char **val);

isc_result_t
dns_c_ndcserver_gethost(dns_c_ndcserver_t *server, const char **val);

isc_result_t
dns_c_ndcserver_getname(dns_c_ndcserver_t *server, const char **val);

/* OPTIONS */
isc_result_t
dns_c_ndcopts_new(isc_mem_t *mem, dns_c_ndcopts_t **opts);

isc_result_t
dns_c_ndcopts_destroy(dns_c_ndcopts_t **opts);

isc_result_t
dns_c_ndcopts_getdefserver(dns_c_ndcopts_t *opts, const char **retval);

isc_result_t
dns_c_ndcopts_getdefkey(dns_c_ndcopts_t *opts, const char **retval);

isc_result_t
dns_c_ndcopts_setdefserver(dns_c_ndcopts_t *opts, const char *newval);

isc_result_t
dns_c_ndcopts_setdefkey(dns_c_ndcopts_t *opts, const char *newval);

isc_result_t
dns_c_ndcparseconf(const char *filename, isc_mem_t *mem,
		   dns_c_ndcctx_t **ndcctx);

void
dns_c_ndcctx_print(FILE *fp, dns_c_ndcctx_t *ctx);

void
dns_c_ndcopts_print(FILE *fp, dns_c_ndcopts_t *opts);

void
dns_c_ndcserverlist_print(FILE *fp, dns_c_ndcserverlist_t *servers);

void
dns_c_ndcserver_print(FILE *fp, dns_c_ndcserver_t *server);

ISC_LANG_ENDDECLS

#endif /* DNS_CONFNDC_H */
