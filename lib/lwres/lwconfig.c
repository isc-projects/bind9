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

/***
 *** Module for parsing resolv.conf files.
 ***
 *** entry points are:
 ***	lwres_conf_init(lwres_conf_t *confdata)
 ***		intializes data structure for subsequent parsing.
 ***
 ***	lwres_conf_parse(lwres_context_t *ctx,  const char *filename,
 ***			 lwres_conf_t *confdata)
 ***		parses a file and fills in the data structure.
 ***
 ***	lwres_conf_print(FILE *fp, lwres_conf_t *confdata)
 ***		prints the data structure to the FILE.
 ***
 ***	lwres_conf_clear(lwres_context_t *ctx, lwres_conf_t *confdata)
 ***		frees up all the internal memory used by the data
 ***		 structure. 
 ***
 ***/

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <lwres/lwbuffer.h>
#include <lwres/lwres.h>
#include <lwres/result.h>

#include "assert_p.h"
#include "context_p.h"


#if ! defined(NS_INADDRSZ)
#define NS_INADDRSZ	 4
#endif

#if ! defined(NS_IN6ADDRSZ)
#define NS_IN6ADDRSZ	16
#endif

extern int lwres_net_pton(int af, const char *src, void *dst);
extern const char *lwres_net_ntop(int af, const void *src, char *dst,
				  size_t size);


static int lwres_conf_parsenameserver(lwres_context_t *ctx,  FILE *fp,
				      lwres_conf_t *confdata);
static int lwres_conf_parsedomain(lwres_context_t *ctx, FILE *fp,
				  lwres_conf_t *confdata);
static int lwres_conf_parsesearch(lwres_context_t *ctx,  FILE *fp,
				  lwres_conf_t *confdata);
static int lwres_conf_parsesortlist(lwres_context_t *ctx,  FILE *fp,
				    lwres_conf_t *confdata);
static int lwres_conf_parseoption(lwres_context_t *ctx,  FILE *fp,
				  lwres_conf_t *confdata);
static void lwres_resetaddr(lwres_context_t *ctx, lwres_addr_t *addr,
			    int freeit);
static int lwres_create_addr(lwres_context_t *ctx, const char *buff,
			     lwres_addr_t *addr);

/*
 * Skip over any leading whitespace and then read in the next sequence of
 * non-whitespace characters. Returnss EOF on end-of-file, or the character
 * that caused the reading to stop.
 */
static int
getword(FILE *fp, char *buffer, size_t size)
{
	int ch;
	char *p = buffer;

	REQUIRE(buffer != NULL);
	REQUIRE(size > 0);

	*p = '\0';
		
	ch = fgetc(fp);
	while (ch != '\n' && isspace(ch)) {
		ch = fgetc(fp);
	}

	if (ch == EOF) {
		return (EOF);
	}

	do {
		*p = '\0';
		
		if (ch == EOF || isspace(ch)) {
			break;
		} else if ((size_t) (p - buffer) == size - 1) {
			return (EOF);	/* not enough space */
		}

		*p++ = (char)ch;
		ch = fgetc(fp);
	} while (1);

	return (ch);
}

static void
lwres_resetaddr(lwres_context_t *ctx, lwres_addr_t *addr, int freeit)
{
	REQUIRE(addr != NULL);

	if (freeit && addr->address != NULL) {
		CTXFREE((void *)addr->address, addr->length);
	}

	addr->address = NULL;
	addr->family = 0;
	addr->length = 0;
}

	
static char *
lwres_strdup(lwres_context_t *ctx, const char *str)
{
	char *p;

	REQUIRE(str != NULL);
	REQUIRE(strlen(str) > 0);

	p = CTXMALLOC(strlen(str) + 1);
	if (p != NULL) {
		strcpy(p, str);
	}

	return (p);
}


void
lwres_conf_init(lwres_conf_t *confdata)
{
	int i;
	
	REQUIRE(confdata != NULL);
	
	confdata->nsnext = 0;
	confdata->domainname = NULL;
	confdata->searchnxt = 0;
	confdata->sortlistnxt = 0;
	confdata->resdebug = 0;
	confdata->ndots = 0;
	confdata->no_tld_query = 0;

	for (i = 0 ; i < LWRES_CONFMAXNAMESERVERS ; i++) {
		lwres_resetaddr(NULL, &confdata->nameservers[i], 0);
	}

	for (i = 0 ; i < LWRES_CONFMAXSEARCH ; i++) {
		confdata->search[i] = NULL;
	}

	for (i = 0 ; i < LWRES_CONFMAXSORTLIST ; i++) {
		lwres_resetaddr(NULL, &confdata->sortlist[i].addr, 0);
		lwres_resetaddr(NULL, &confdata->sortlist[i].mask, 0);
	}
}


void
lwres_conf_clear(lwres_context_t *ctx, lwres_conf_t *confdata)
{
	int i;
	
	for (i = 0 ; i < confdata->nsnext ; i++) {
		lwres_resetaddr(ctx, &confdata->nameservers[i], 1);
	}

	if (confdata->domainname != NULL) {
		CTXFREE(confdata->domainname,
			strlen(confdata->domainname) + 1);
		confdata->domainname = NULL;
	}
	
	for (i = 0 ; i < confdata->searchnxt ; i++) {
		if (confdata->search[i] != NULL) {
			CTXFREE(confdata->search[i],
				strlen(confdata->search[i]) + 1);
			confdata->search[i] = NULL;
		}
	}

	for (i = 0 ; i < LWRES_CONFMAXSORTLIST ; i++) {
		lwres_resetaddr(ctx, &confdata->sortlist[i].addr, 1);
		lwres_resetaddr(ctx, &confdata->sortlist[i].mask, 1);
	}

	confdata->nsnext = 0;
	confdata->domainname = NULL;
	confdata->searchnxt = 0;
	confdata->sortlistnxt = 0;
	confdata->resdebug = 0;
	confdata->ndots = 0;
	confdata->no_tld_query = 0;
}


static int
lwres_conf_parsenameserver(lwres_context_t *ctx,  FILE *fp,
			   lwres_conf_t *confdata)
{
	char word[LWRES_CONFMAXLINELEN];
	int res;
				
	if (confdata->nsnext == LWRES_CONFMAXNAMESERVERS) {
		return (LWRES_R_FAILURE);
	}
			
	res = getword(fp, word, sizeof(word));
	if (strlen(word) == 0) {
		return (LWRES_R_FAILURE); /* nothing on line */
	} else if (res != EOF && res != '\n') {
		return (LWRES_R_FAILURE); /* extra junk on line */
	}
	
	res = lwres_create_addr(ctx, word,
				&confdata->nameservers[confdata->nsnext++]);
	if (res != LWRES_R_SUCCESS) {
		return (res);
	}

	return (LWRES_R_SUCCESS);
}


static int
lwres_conf_parsedomain(lwres_context_t *ctx,  FILE *fp, lwres_conf_t *confdata)
{
	char word[LWRES_CONFMAXLINELEN];
	int res, i;
		
	res = getword(fp, word, sizeof(word));
	if (strlen(word) == 0) {
		return (LWRES_R_FAILURE); /* nothing else on line */
	} else if (res != EOF && res != '\n') {
		return (LWRES_R_FAILURE); /* extra junk on line */
	}

	if (confdata->domainname != NULL) {
		CTXFREE(confdata->domainname,
			strlen(confdata->domainname) + 1); /*  */
	}

	/* search and domain are mutually exclusive */
	for (i = 0 ; i < LWRES_CONFMAXSEARCH ; i++) {
		if (confdata->search[i] != NULL) {
			CTXFREE(confdata->search[i],
				strlen(confdata->search[i])+1);
			confdata->search[i] = NULL;
		}
	}
	confdata->searchnxt = 0;
			
	confdata->domainname = lwres_strdup(ctx, word);

	if (confdata->domainname == NULL) {
		return (LWRES_R_FAILURE);
	} else {
		return (LWRES_R_SUCCESS);
	}
}


static int
lwres_conf_parsesearch(lwres_context_t *ctx,  FILE *fp,
		       lwres_conf_t *confdata)
{
	int idx, delim;
	char word[LWRES_CONFMAXLINELEN];
	
	if (confdata->domainname != NULL) {
		/* search and domain are mutually exclusive */
		CTXFREE(confdata->domainname,
			strlen(confdata->domainname) + 1);
		confdata->domainname = NULL;
	}

	/* remove any previous search definitions. */
	for (idx = 0 ; idx < LWRES_CONFMAXSEARCH ; idx++) {
		if (confdata->search[idx] != NULL) {
			CTXFREE(confdata->search[idx],
				strlen(confdata->search[idx])+1);
			confdata->search[idx] = NULL;
		}
	}
	confdata->searchnxt = 0;
			
	delim = getword(fp, word, sizeof(word));
	if (strlen(word) == 0) {
		return (LWRES_R_FAILURE); /* nothing else on line */
	}

	idx = 0;
	while (strlen(word) > 0) {
		if (confdata->searchnxt == LWRES_CONFMAXSEARCH) {
			return (LWRES_R_FAILURE); /* too many domains */
		}

		confdata->search[idx] = lwres_strdup(ctx, word);
		if (confdata->search[idx] == NULL) {
			return (LWRES_R_FAILURE);
		}
				
		if (delim == EOF || delim == '\n') {
			break;
		} else {
			delim = getword(fp, word, sizeof(word));
		}
	}

	return (LWRES_R_SUCCESS);
}


static int
lwres_create_addr(lwres_context_t *ctx, const char *buffer, lwres_addr_t *addr)
{
	unsigned char addrbuff[NS_IN6ADDRSZ];

	if (lwres_net_pton(AF_INET, buffer, &addrbuff) == 1) {
		addr->family = AF_INET;
		addr->length = NS_INADDRSZ;
		addr->address = CTXMALLOC(NS_INADDRSZ);
#if defined(AF_INET6)
	} else if (lwres_net_pton(AF_INET6, buffer, &addrbuff) == 1) {
		addr->family = AF_INET6;
		addr->length = NS_IN6ADDRSZ;
		addr->address = CTXMALLOC(NS_IN6ADDRSZ);
#endif
	} else {
		return (LWRES_R_FAILURE); /* unrecongnised format */
	}

	memcpy((void *)addr->address, addrbuff, 4);

	return (LWRES_R_SUCCESS);
}

	
	
static int
lwres_conf_parsesortlist(lwres_context_t *ctx,  FILE *fp,
			 lwres_conf_t *confdata)
{
	int delim, res, idx;
	char word[LWRES_CONFMAXLINELEN];
	char *p;

	delim = getword(fp, word, sizeof(word));
	if (strlen(word) == 0) {
		return (LWRES_R_FAILURE); /* empty line after keyword */
	}

	while (strlen(word) > 0) {
		if (confdata->sortlistnxt == LWRES_CONFMAXSORTLIST) {
			return (LWRES_R_FAILURE); /* too many values. */
		}
		
		p = strchr(word, '/');
		if (p != NULL) {
			*p++ = '\0';
		}

		idx = confdata->sortlistnxt;
		res = lwres_create_addr(ctx, word,
					&confdata->sortlist[idx].addr);
		if (res != LWRES_R_SUCCESS) {
			return (res);
		}
		
		if (p != NULL) {
			res = lwres_create_addr(ctx, p,
						&confdata->sortlist[idx].mask);
			if (res != LWRES_R_SUCCESS) {
				return (res);
			}
		}

		confdata->sortlistnxt++;
		
		if (delim == EOF || delim == '\n') {
			break;
		} else {
			delim = getword(fp, word, sizeof(word));
		}
	}

	return (LWRES_R_SUCCESS);
}

static int
lwres_conf_parseoption(lwres_context_t *ctx,  FILE *fp,
		       lwres_conf_t *confdata)
{
	int delim;
	long ndots;
	char *p;
	char word[LWRES_CONFMAXLINELEN];

	(void) ctx;
	
	REQUIRE(confdata != NULL);

	delim = getword(fp, word, sizeof(word));
	if (strlen(word) == 0) {
		return (LWRES_R_FAILURE); /* empty line after keyword */
	}

	while (strlen(word) > 0) {
		if (strcmp("debug", word) == 0) {
			confdata->resdebug = 1;
		} else if (strcmp("no_tld_query", word) == 0) {
			confdata->no_tld_query = 1;
		} else if (strncmp("ndots:", word, 6) == 0) {
			ndots = strtol(word + 6, &p, 10);
			if (*p != '\0') { /* bad string */
				return (LWRES_R_FAILURE);
			}
			confdata->ndots = ndots;
		}

		if (delim == EOF || delim == '\n') {
			break;
		} else {
			delim = getword(fp, word, sizeof(word));
		}
	}

	return (LWRES_R_SUCCESS);
}

	
			 
			

	
	
			       
int
lwres_conf_parse(lwres_context_t *ctx,  const char *filename,
		 lwres_conf_t *confdata)
{
	FILE *fp = NULL;
	char word[256];
	int rval, delim;
	
	REQUIRE(filename != NULL);
	REQUIRE(strlen(filename) > 0);
	REQUIRE(confdata != NULL);

	rval = LWRES_R_FAILURE;		/* Make compiler happy. */
	errno = 0;
	if ((fp = fopen(filename, "r")) == NULL)
		return (LWRES_R_FAILURE);

	do {
		delim = getword(fp, word, sizeof(word));
		if (strlen(word) == 0) {
			rval = LWRES_R_SUCCESS;
			break;
		}
		
		if (strcmp(word, "nameserver") == 0) {
			rval = lwres_conf_parsenameserver(ctx, fp, confdata);
		} else if (strcmp(word, "domain") == 0) {
			rval = lwres_conf_parsedomain(ctx, fp, confdata);
		} else if (strcmp(word, "search") == 0) {
			rval = lwres_conf_parsesearch(ctx, fp, confdata);
		} else if (strcmp(word, "sortlist") == 0) {
			rval = lwres_conf_parsesortlist(ctx, fp, confdata);
		} else if (strcmp(word, "option") == 0) {
			rval = lwres_conf_parseoption(ctx, fp, confdata);
		}
	} while (rval == LWRES_R_SUCCESS);
				
	fclose(fp);

	return (rval);
}
			

int
lwres_conf_print(FILE *fp, lwres_conf_t *confdata)
{
	int i;
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	const char *p;

	REQUIRE(confdata->nsnext <= LWRES_CONFMAXNAMESERVERS);
	
	for (i = 0 ; i < confdata->nsnext ; i++) {
		p = lwres_net_ntop(confdata->nameservers[i].family,
				     confdata->nameservers[i].address,
				     tmp, sizeof(tmp));
		if (p != tmp) {
			return (LWRES_R_FAILURE);
		}

		fprintf(fp, "nameserver %s\n", tmp);
	}

	if (confdata->domainname != NULL) {
		fprintf(fp, "domain %s\n", confdata->domainname);
	} else if (confdata->searchnxt > 0) {
		REQUIRE(confdata->searchnxt <= LWRES_CONFMAXSEARCH);

		fprintf(fp, "search");
		for (i = 0 ; i < confdata->searchnxt ; i++) {
			fputs(confdata->search[i], fp);
		}
		fputc('\n', fp);
	}

	REQUIRE(confdata->sortlistnxt <= LWRES_CONFMAXSORTLIST);

	if (confdata->sortlistnxt > 0) {
		fputs("sortlist", fp);
		for (i = 0 ; i < confdata->sortlistnxt ; i++) {
			p = lwres_net_ntop(confdata->sortlist[i].addr.family,
					   confdata->sortlist[i].addr.address,
					   tmp, sizeof(tmp));
			if (p != tmp) {
				return (LWRES_R_FAILURE);
			}

			fprintf(fp, " %s", tmp);

			if (confdata->sortlist[i].mask.length > 0) {
				p = lwres_net_ntop
					(confdata->sortlist[i].mask.family,
					 confdata->sortlist[i].mask.address,
					 tmp, sizeof(tmp));
				if (p != tmp) {
					return (LWRES_R_FAILURE);
				}

				fprintf(fp, "/%s", tmp);
			}
		}
		fputc('\n', fp);
	}

	if (confdata->resdebug) {
		fprintf(fp, "options debug\n");
	}

	if (confdata->ndots > 0) {
		fprintf(fp, "options ndots:%d\n", confdata->ndots);
	}

	if (confdata->no_tld_query) {
		fprintf(fp, "options no_tld_query\n");
	}

	return (LWRES_R_SUCCESS);
}

