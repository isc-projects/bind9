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

/*! \file resconf.c */

/**
 * Module for parsing resolv.conf files (largely derived from lwconfig.c).
 *
 *    irs_resconf_load() opens the file filename and parses it to initialize
 *    the configuration structure.
 *
 * \section lwconfig_return Return Values
 *
 *    irs_resconf_load() returns #IRS_R_SUCCESS if it successfully read and
 *    parsed filename. It returns a non-0 error code if filename could not be
 *    opened or contained incorrect resolver statements.
 *
 * \section lwconfig_see See Also
 *
 *    stdio(3), \link resolver resolver \endlink
 *
 * \section files Files
 *
 *    /etc/resolv.conf
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/sockaddr.h>
#include <isc/util.h>

#include <irs/resconf.h>

#define IRS_RESCONF_MAGIC    ISC_MAGIC('R', 'E', 'S', 'c')
#define IRS_RESCONF_VALID(c) ISC_MAGIC_VALID(c, IRS_RESCONF_MAGIC)

/*!
 * protocol constants
 */

#if !defined(NS_INADDRSZ)
#define NS_INADDRSZ 4
#endif /* if !defined(NS_INADDRSZ) */

#if !defined(NS_IN6ADDRSZ)
#define NS_IN6ADDRSZ 16
#endif /* if !defined(NS_IN6ADDRSZ) */

/*!
 * resolv.conf parameters
 */

#define RESCONFMAXNAMESERVERS 3U   /*%< max 3 "nameserver" entries */
#define RESCONFMAXLINELEN     256U /*%< max size of a line */
#define RESCONFMAXSORTLIST    10U  /*%< max 10 */

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

/*!
 * configuration data structure
 */

struct irs_resconf {
	/*
	 * The configuration data is a thread-specific object, and does not
	 * need to be locked.
	 */
	unsigned int magic;
	isc_mem_t *mctx;

	isc_sockaddrlist_t nameservers;
	unsigned int numns; /*%< number of configured servers */

	char *domainname;
	uint8_t searchnxt; /*%< index for next free slot */

	irs_resconf_searchlist_t searchlist;

	struct {
		isc_netaddr_t addr;
		/*% mask has a non-zero 'family' if set */
		isc_netaddr_t mask;
	} sortlist[RESCONFMAXSORTLIST];
	uint8_t sortlistnxt;

	/*%< non-zero if 'options debug' set */
	uint8_t resdebug;
	/*%< set to n in 'options ndots:n' */
	uint8_t ndots;
	/*%< set to n in 'options attempts:n' */
	uint8_t attempts;
	/*%< set to n in 'options timeout:n' */
	uint8_t timeout;
};

static isc_result_t
resconf_parsenameserver(irs_resconf_t *conf, FILE *fp);
static isc_result_t
resconf_parsedomain(irs_resconf_t *conf, FILE *fp);
static isc_result_t
resconf_parsesearch(irs_resconf_t *conf, FILE *fp);
static isc_result_t
resconf_parsesortlist(irs_resconf_t *conf, FILE *fp);
static isc_result_t
resconf_parseoption(irs_resconf_t *ctx, FILE *fp);

/*!
 * Eat characters from FP until EOL or EOF. Returns EOF or '\n'
 */
static int
eatline(FILE *fp) {
	int ch;

	do {
		ch = fgetc(fp);
	} while (ch != '\n' && ch != EOF);

	return ch;
}

/*!
 * Eats white space up to next newline or non-whitespace character (of
 * EOF). Returns the last character read. Comments are considered white
 * space.
 */
static int
eatwhite(FILE *fp) {
	int ch;

	do {
		ch = fgetc(fp);
	} while (ch != EOF && ch != '\n' && isspace((unsigned char)ch));

	if (ch == ';' || ch == '#') {
		ch = eatline(fp);
	}

	return ch;
}

/*!
 * Skip over any leading whitespace and then read in the next sequence of
 * non-whitespace characters. In this context newline is not considered
 * whitespace. Returns EOF on end-of-file, or the character
 * that caused the reading to stop.
 */
static int
getword(FILE *fp, char *buffer, size_t size) {
	char *p = NULL;
	int ch;

	REQUIRE(buffer != NULL);
	REQUIRE(size > 0U);

	p = buffer;
	*p = '\0';

	ch = eatwhite(fp);
	if (ch == EOF) {
		return EOF;
	}

	do {
		*p = '\0';

		if (isspace((unsigned char)ch)) {
			break;
		} else if ((size_t)(p - buffer) == size - 1) {
			return EOF; /* Not enough space. */
		}

		*p++ = (char)ch;
		ch = fgetc(fp);
	} while (ch != EOF);

	return ch;
}

static isc_result_t
add_server(isc_mem_t *mctx, const char *address_str,
	   isc_sockaddrlist_t *nameservers) {
	int error;
	isc_sockaddr_t *address = NULL;
	struct addrinfo hints, *res;
	isc_result_t result = ISC_R_SUCCESS;

	res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST;
	error = getaddrinfo(address_str, "53", &hints, &res);
	if (error != 0) {
		return ISC_R_BADADDRESSFORM;
	}

	address = isc_mem_get(mctx, sizeof(*address));
	if (res->ai_addrlen > sizeof(address->type)) {
		isc_mem_put(mctx, address, sizeof(*address));
		result = ISC_R_RANGE;
		goto cleanup;
	}

	if (res->ai_family == AF_INET) {
		struct in_addr *v4;
		unsigned char zeroaddress[] = { 0, 0, 0, 0 };
		unsigned char loopaddress[] = { 127, 0, 0, 1 };

		/* XXX: special case: treat all-0 IPv4 address as loopback */
		v4 = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
		if (memcmp(v4, zeroaddress, 4) == 0) {
			memmove(v4, loopaddress, 4);
		}
		memmove(&address->type.sin, res->ai_addr, res->ai_addrlen);
	} else if (res->ai_family == AF_INET6) {
		memmove(&address->type.sin6, res->ai_addr, res->ai_addrlen);
	} else {
		isc_mem_put(mctx, address, sizeof(*address));
		UNEXPECTED_ERROR("ai_family (%d) not INET nor INET6",
				 res->ai_family);
		result = ISC_R_UNEXPECTED;
		goto cleanup;
	}
	address->length = (unsigned int)res->ai_addrlen;

	ISC_LINK_INIT(address, link);
	ISC_LIST_APPEND(*nameservers, address, link);

cleanup:
	freeaddrinfo(res);

	return result;
}

static isc_result_t
create_addr(const char *buffer, isc_netaddr_t *addr, int convert_zero) {
	struct in_addr v4;
	struct in6_addr v6;

	if (inet_pton(AF_INET, buffer, &v4) == 1) {
		if (convert_zero) {
			unsigned char zeroaddress[] = { 0, 0, 0, 0 };
			unsigned char loopaddress[] = { 127, 0, 0, 1 };
			if (memcmp(&v4, zeroaddress, 4) == 0) {
				memmove(&v4, loopaddress, 4);
			}
		}
		addr->family = AF_INET;
		memmove(&addr->type.in, &v4, NS_INADDRSZ);
		addr->zone = 0;
	} else if (inet_pton(AF_INET6, buffer, &v6) == 1) {
		addr->family = AF_INET6;
		memmove(&addr->type.in6, &v6, NS_IN6ADDRSZ);
		addr->zone = 0;
	} else {
		return ISC_R_BADADDRESSFORM; /* Unrecognised format. */
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
resconf_parsenameserver(irs_resconf_t *conf, FILE *fp) {
	char word[RESCONFMAXLINELEN];
	int cp;
	isc_result_t result;

	cp = getword(fp, word, sizeof(word));
	if (cp == EOF || strlen(word) == 0U) {
		return ISC_R_UNEXPECTEDEND; /* Nothing on line. */
	} else if (cp == ' ' || cp == '\t') {
		cp = eatwhite(fp);
	}

	if (cp != EOF && cp != '\n') {
		return ISC_R_UNEXPECTEDTOKEN; /* Extra junk on line. */
	}

	if (conf->numns == RESCONFMAXNAMESERVERS) {
		return ISC_R_SUCCESS;
	}

	result = add_server(conf->mctx, word, &conf->nameservers);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	conf->numns++;

	return ISC_R_SUCCESS;
}

static isc_result_t
resconf_parsedomain(irs_resconf_t *conf, FILE *fp) {
	char word[RESCONFMAXLINELEN];
	int res;

	res = getword(fp, word, sizeof(word));
	if (res == EOF || strlen(word) == 0U) {
		return ISC_R_UNEXPECTEDEND; /* Nothing else on line. */
	} else if (res == ' ' || res == '\t') {
		res = eatwhite(fp);
	}

	if (res != EOF && res != '\n') {
		return ISC_R_UNEXPECTEDTOKEN; /* Extra junk on line. */
	}

	if (conf->domainname != NULL) {
		isc_mem_free(conf->mctx, conf->domainname);
	}

	/*
	 * Search and domain are mutually exclusive.
	 * Search is cleared later.
	 */

	conf->domainname = isc_mem_strdup(conf->mctx, word);

	return ISC_R_SUCCESS;
}

static void
free_search(irs_resconf_t *conf) {
	ISC_LIST_FOREACH (conf->searchlist, searchentry, link) {
		ISC_LIST_UNLINK(conf->searchlist, searchentry, link);
		isc_mem_free(conf->mctx, searchentry->domain);
		isc_mem_put(conf->mctx, searchentry, sizeof(*searchentry));
	}
}

/*!
 * Append new search entry to searchlist.
 *
 * Always copy domain name passed.
 */
static isc_result_t
add_search(irs_resconf_t *conf, char *domain) {
	irs_resconf_search_t *entry = NULL;

	entry = isc_mem_get(conf->mctx, sizeof(*entry));
	*entry = (irs_resconf_search_t){
		.domain = isc_mem_strdup(conf->mctx, domain),
		.link = ISC_LINK_INITIALIZER,
	};

	ISC_LIST_APPEND(conf->searchlist, entry, link);

	return ISC_R_SUCCESS;
}

static isc_result_t
resconf_parsesearch(irs_resconf_t *conf, FILE *fp) {
	int delim;
	char word[RESCONFMAXLINELEN];
	isc_result_t result;

	if (conf->domainname != NULL) {
		/*
		 * Search and domain are mutually exclusive.
		 */
		isc_mem_free(conf->mctx, conf->domainname);
	}

	/*
	 * Remove any previous search definitions.
	 */
	free_search(conf);

	delim = getword(fp, word, sizeof(word));
	if (delim == EOF || strlen(word) == 0U) {
		return ISC_R_UNEXPECTEDEND; /* Nothing else on line. */
	}
	do {
		result = add_search(conf, word);
		if (result != ISC_R_SUCCESS) {
			return result;
		}

		if (delim == '\n') {
			break;
		}

		delim = getword(fp, word, sizeof(word));
		if (delim == EOF) {
			return ISC_R_UNEXPECTEDEND;
		}
	} while (strlen(word) > 0U);

	return ISC_R_SUCCESS;
}

static isc_result_t
resconf_parsesortlist(irs_resconf_t *conf, FILE *fp) {
	int delim, res;
	unsigned int idx;
	char word[RESCONFMAXLINELEN];
	char *p;

	delim = getword(fp, word, sizeof(word));
	if (delim == EOF || strlen(word) == 0U) {
		return ISC_R_UNEXPECTEDEND; /* Empty line after keyword. */
	}

	while (delim != EOF && strlen(word) > 0U) {
		if (conf->sortlistnxt == RESCONFMAXSORTLIST) {
			return ISC_R_QUOTA; /* Too many values. */
		}

		p = strchr(word, '/');
		if (p != NULL) {
			*p++ = '\0';
		}

		idx = conf->sortlistnxt;
		INSIST(idx <
		       sizeof(conf->sortlist) / sizeof(conf->sortlist[0]));
		res = create_addr(word, &conf->sortlist[idx].addr, 1);
		if (res != ISC_R_SUCCESS) {
			return res;
		}

		if (p != NULL) {
			res = create_addr(p, &conf->sortlist[idx].mask, 0);
			if (res != ISC_R_SUCCESS) {
				return res;
			}
		} else {
			/*
			 * Make up a mask. (XXX: is this correct?)
			 */
			conf->sortlist[idx].mask = conf->sortlist[idx].addr;
			memset(&conf->sortlist[idx].mask.type, 0xff,
			       sizeof(conf->sortlist[idx].mask.type));
		}

		conf->sortlistnxt++;

		if (delim == EOF || delim == '\n') {
			break;
		} else {
			delim = getword(fp, word, sizeof(word));
		}
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
resconf_optionnumber(const char *word, uint8_t *number) {
	char *p;
	long n;

	n = strtol(word, &p, 10);
	if (*p != '\0') { /* Bad string. */
		return ISC_R_UNEXPECTEDTOKEN;
	}
	if (n < 0 || n > 0xff) { /* Out of range. */
		return ISC_R_RANGE;
	}
	*number = n;
	return ISC_R_SUCCESS;
}

static isc_result_t
resconf_parseoption(irs_resconf_t *conf, FILE *fp) {
	int delim;
	isc_result_t result = ISC_R_SUCCESS;
	char word[RESCONFMAXLINELEN];

	delim = getword(fp, word, sizeof(word));
	if (strlen(word) == 0U) {
		return ISC_R_UNEXPECTEDEND; /* Empty line after keyword. */
	}

	while (strlen(word) > 0U) {
		if (strcmp("debug", word) == 0) {
			conf->resdebug = 1;
		} else if (strncmp("ndots:", word, 6) == 0) {
			CHECK(resconf_optionnumber(word + 6, &conf->ndots));
		} else if (strncmp("attempts:", word, 9) == 0) {
			CHECK(resconf_optionnumber(word + 9, &conf->attempts));
		} else if (strncmp("timeout:", word, 8) == 0) {
			CHECK(resconf_optionnumber(word + 8, &conf->timeout));
		}

		if (delim == EOF || delim == '\n') {
			break;
		} else {
			delim = getword(fp, word, sizeof(word));
		}
	}

cleanup:
	return result;
}

/*% parses a file and fills in the data structure. */
isc_result_t
irs_resconf_load(isc_mem_t *mctx, const char *filename, irs_resconf_t **confp) {
	FILE *fp = NULL;
	char word[256];
	isc_result_t rval, ret = ISC_R_SUCCESS;
	irs_resconf_t *conf;
	int stopchar = EOF;

	REQUIRE(mctx != NULL);
	REQUIRE(filename != NULL);
	REQUIRE(strlen(filename) > 0U);
	REQUIRE(confp != NULL && *confp == NULL);

	conf = isc_mem_get(mctx, sizeof(*conf));
	*conf = (irs_resconf_t){
		.mctx = mctx,
		.nameservers = ISC_LIST_INITIALIZER,
		.searchlist = ISC_LIST_INITIALIZER,
		.ndots = 1,
		.attempts = 3,
	};

	errno = 0;
	if ((fp = fopen(filename, "r")) != NULL) {
		while (!feof(fp) && !ferror(fp)) {
			stopchar = getword(fp, word, sizeof(word));
			if (stopchar == EOF) {
				if (strlen(word) != 0) {
					if (ret == ISC_R_SUCCESS) {
						ret = ISC_R_UNEXPECTEDEND;
					}
				}
				break;
			}

			if (strlen(word) == 0U) {
				rval = ISC_R_SUCCESS;
			} else if (strcmp(word, "nameserver") == 0) {
				rval = resconf_parsenameserver(conf, fp);
			} else if (strcmp(word, "domain") == 0) {
				rval = resconf_parsedomain(conf, fp);
			} else if (strcmp(word, "search") == 0) {
				rval = resconf_parsesearch(conf, fp);
			} else if (strcmp(word, "sortlist") == 0) {
				rval = resconf_parsesortlist(conf, fp);
			} else if (strcmp(word, "options") == 0) {
				rval = resconf_parseoption(conf, fp);
			} else {
				/* Unrecognised word. Ignore entire line. */
				rval = ISC_R_SUCCESS;
				if (stopchar != '\n') {
					if (eatline(fp) == EOF) {
						break;
					}
				}
			}
			if (ret == ISC_R_SUCCESS && rval != ISC_R_SUCCESS) {
				ret = rval;
			}
		}

		fclose(fp);
	} else {
		switch (errno) {
		case ENOENT:
			break;
		default:
			isc_mem_put(mctx, conf, sizeof(*conf));
			return ISC_R_INVALIDFILE;
		}
	}

	if (ret != ISC_R_SUCCESS) {
		goto error;
	}

	/*
	 * Construct unified search list from domain or configured
	 * search list. Last specified is used.
	 */
	if (conf->domainname != NULL) {
		free_search(conf);
		ret = add_search(conf, conf->domainname);
	}

	/* If we don't find a nameserver fall back to localhost */
	if (conf->numns == 0U) {
		INSIST(ISC_LIST_EMPTY(conf->nameservers));

		/* XXX: should we catch errors? */
		(void)add_server(conf->mctx, "::1", &conf->nameservers);
		(void)add_server(conf->mctx, "127.0.0.1", &conf->nameservers);
	}

error:
	conf->magic = IRS_RESCONF_MAGIC;

	if (ret != ISC_R_SUCCESS) {
		irs_resconf_destroy(&conf);
	} else {
		if (fp == NULL) {
			ret = ISC_R_FILENOTFOUND;
		}
		*confp = conf;
	}

	return ret;
}

void
irs_resconf_destroy(irs_resconf_t **confp) {
	irs_resconf_t *conf = NULL;

	REQUIRE(confp != NULL);
	conf = *confp;
	*confp = NULL;
	REQUIRE(IRS_RESCONF_VALID(conf));

	free_search(conf);

	ISC_LIST_FOREACH (conf->nameservers, address, link) {
		ISC_LIST_UNLINK(conf->nameservers, address, link);
		isc_mem_put(conf->mctx, address, sizeof(*address));
	}

	if (conf->domainname != NULL) {
		isc_mem_free(conf->mctx, conf->domainname);
	}

	isc_mem_put(conf->mctx, conf, sizeof(*conf));
}

isc_sockaddrlist_t *
irs_resconf_getnameservers(irs_resconf_t *conf) {
	REQUIRE(IRS_RESCONF_VALID(conf));

	return &conf->nameservers;
}

irs_resconf_searchlist_t *
irs_resconf_getsearchlist(irs_resconf_t *conf) {
	REQUIRE(IRS_RESCONF_VALID(conf));

	return &conf->searchlist;
}

unsigned int
irs_resconf_getndots(irs_resconf_t *conf) {
	REQUIRE(IRS_RESCONF_VALID(conf));

	return (unsigned int)conf->ndots;
}

unsigned int
irs_resconf_getattempts(irs_resconf_t *conf) {
	REQUIRE(IRS_RESCONF_VALID(conf));

	return (unsigned int)conf->attempts;
}

unsigned int
irs_resconf_gettimeout(irs_resconf_t *conf) {
	REQUIRE(IRS_RESCONF_VALID(conf));

	return (unsigned int)conf->timeout;
}
