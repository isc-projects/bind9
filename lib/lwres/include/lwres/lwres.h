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

#ifndef LWRES_LWRES_H
#define LWRES_LWRES_H 1

#include <stdio.h>
#include <stddef.h>

#include <lwres/context.h>
#include <lwres/int.h>
#include <lwres/lang.h>
#include <lwres/list.h>
#include <lwres/lwpacket.h>
#include <lwres/result.h>

/*
 * Design notes:
 *
 * Each opcode has two structures and three functions which operate on each
 * structure.  For example, using the "no operation/ping" opcode as an
 * example:
 *
 *	lwres_nooprequest_t:
 *
 *		lwres_nooprequest_render() takes a lwres_nooprequest_t and
 *		and renders it into wire format, storing the allocated
 *		buffer information in a passed-in buffer.  When this buffer
 *		is no longer needed, it must be freed by
 *		lwres_context_freemem().  All other memory used by the
 *		caller must be freed manually, including the
 *		lwres_nooprequest_t passed in.
 *
 *		lwres_nooprequest_parse() takes a wire format message and
 *		breaks it out into a lwres_nooprequest_t.  The structure
 *		must be freed via lwres_nooprequest_free() when it is no longer
 *		needed.
 *
 *		lwres_nooprequest_free() releases into the lwres_context_t
 *		any space allocated during parsing.
 *
 *	lwres_noopresponse_t:
 *
 *		The functions used are similar to the three used for
 *		requests, just with different names.
 *
 * Typically, the client will use request_render, response_parse, and
 * response_free, while the daemon will use request_parse, response_render,
 * and request_free.
 *
 * The basic flow of a typical client is:
 *
 *	fill in a request_t, and call the render function.
 *
 *	Transmit the buffer returned to the daemon.
 *
 *	Wait for a response.
 *
 *	When a response is received, parse it into a response_t.
 *
 *	free the request buffer using lwres_context_freemem().
 *
 *	free the response structure and its associated buffer using
 *	response_free().
 */

/*
 * Helper macro to calculate a string's length.  Strings are encoded
 * using a 16-bit length, the string itself, and a trailing NUL.  The
 * length does not include this NUL character -- it is there merely to
 * help reduce copying on the receive side, since most strings are
 * printable character strings, and C needs the trailing NUL.
 */

#define LWRES_UDP_PORT		921	/* XXXMLG */
#define LWRES_RECVLENGTH	2048	/* XXXMLG */
#define LWRES_ADDR_MAXLEN	16	/* XXXMLG changing this breaks ABI */

/*
 * XXXMLG
 */
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001UL
#endif

/*
 * NO-OP
 */
#define LWRES_OPCODE_NOOP		0x00000000U

typedef struct {
	/* public */
	lwres_uint16_t			datalength;
	unsigned char		       *data;
} lwres_nooprequest_t;

typedef struct {
	/* public */
	lwres_uint16_t			datalength;
	unsigned char		       *data;
} lwres_noopresponse_t;

/*
 * GET ADDRESSES BY NAME
 */
#define LWRES_OPCODE_GETADDRSBYNAME	0x00010001U

typedef struct lwres_addr lwres_addr_t;
typedef LWRES_LIST(lwres_addr_t) lwres_addrlist_t;

struct lwres_addr {
	lwres_uint32_t			family;
	lwres_uint16_t			length;
	unsigned char			address[LWRES_ADDR_MAXLEN];
	LWRES_LINK(lwres_addr_t)	link;
};

typedef struct {
	/* public */
	lwres_uint32_t			addrtypes;
	lwres_uint16_t			namelen;
	char			       *name;
} lwres_gabnrequest_t;

typedef struct {
	/* public */
	lwres_uint16_t			naliases;
	lwres_uint16_t			naddrs;
	char			       *realname;
	char			      **aliases;
	lwres_uint16_t			realnamelen;
	lwres_uint16_t		       *aliaslen;
	lwres_addrlist_t		addrs;
	/* if base != NULL, it will be freed when this structure is freed. */
	void			       *base;
	size_t				baselen;
} lwres_gabnresponse_t;

/*
 * GET NAME BY ADDRESS
 */
#define LWRES_OPCODE_GETNAMEBYADDR	0x00010002U
typedef struct {
	/* public */
	lwres_addr_t			addr;
} lwres_gnbarequest_t;

typedef struct {
	/* public */
	lwres_uint16_t			naliases;
	char			       *realname;
	char			      **aliases;
	lwres_uint16_t			realnamelen;
	lwres_uint16_t		       *aliaslen;
	/* if base != NULL, it will be freed when this structure is freed. */
	void			       *base;
	size_t				baselen;
} lwres_gnbaresponse_t;


/*
 * resolv.conf DATA
 */

#define LWRES_CONFMAXNAMESERVERS 3	/* max 3 "nameserver" entries */
#define LWRES_CONFMAXSEARCH 6		/* max 6 domains in "search" entry */
#define LWRES_CONFMAXLINELEN 256	/* max size of a line */
#define LWRES_CONFMAXSORTLIST 10
typedef struct {
	lwres_context_t *lwctx;
	lwres_addr_t    nameservers[LWRES_CONFMAXNAMESERVERS];
	lwres_uint8_t	nsnext;		/* index for next free slot */

	char	       *domainname;

	char 	       *search[LWRES_CONFMAXSEARCH];
	lwres_uint8_t	searchnxt;	/* index for next free slot */

	struct {
		lwres_addr_t addr;
		/* mask has a non-zero 'family' and 'length' if set */
		lwres_addr_t mask;	
	} sortlist[LWRES_CONFMAXSORTLIST];
	lwres_uint8_t	sortlistnxt;

	lwres_uint8_t	resdebug;	/* non-zero if 'options debug' set */
	lwres_uint8_t	ndots;		/* set to n in 'options ndots:n' */
	lwres_uint8_t	no_tld_query;	/* non-zero if 'options no_tld_query' */
} lwres_conf_t;
	
#define LWRES_ADDRTYPE_V4		0x00000001U	/* ipv4 */
#define LWRES_ADDRTYPE_V6		0x00000002U	/* ipv6 */

#define LWRES_MAX_ALIASES		8		/* max # of aliases */
#define LWRES_MAX_ADDRS			32		/* max # of addrs */

LWRES_LANG_BEGINDECLS

lwres_result_t
lwres_gabnrequest_render(lwres_context_t *ctx, lwres_gabnrequest_t *req,
			 lwres_lwpacket_t *pkt, lwres_buffer_t *b);

lwres_result_t
lwres_gabnresponse_render(lwres_context_t *ctx, lwres_gabnresponse_t *req,
			  lwres_lwpacket_t *pkt, lwres_buffer_t *b);

lwres_result_t
lwres_gabnrequest_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			lwres_lwpacket_t *pkt, lwres_gabnrequest_t **structp);

lwres_result_t
lwres_gabnresponse_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			 lwres_lwpacket_t *pkt,
			 lwres_gabnresponse_t **structp);

void
lwres_gabnrequest_free(lwres_context_t *ctx, lwres_gabnrequest_t **structp);
/*
 * Frees any dynamically allocated memory for this structure.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp != NULL.
 *
 * Ensures:
 *
 *	*structp == NULL.
 *
 *	All memory allocated by this structure will be returned to the
 *	system via the context's free function.
 */

void
lwres_gabnresponse_free(lwres_context_t *ctx, lwres_gabnresponse_t **structp);
/*
 * Frees any dynamically allocated memory for this structure.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp != NULL.
 *
 * Ensures:
 *
 *	*structp == NULL.
 *
 *	All memory allocated by this structure will be returned to the
 *	system via the context's free function.
 */


lwres_result_t
lwres_gnbarequest_render(lwres_context_t *ctx, lwres_gnbarequest_t *req,
			 lwres_lwpacket_t *pkt, lwres_buffer_t *b);

lwres_result_t
lwres_gnbaresponse_render(lwres_context_t *ctx, lwres_gnbaresponse_t *req,
			  lwres_lwpacket_t *pkt, lwres_buffer_t *b);

lwres_result_t
lwres_gnbarequest_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			lwres_lwpacket_t *pkt, lwres_gnbarequest_t **structp);

lwres_result_t
lwres_gnbaresponse_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			 lwres_lwpacket_t *pkt,
			 lwres_gnbaresponse_t **structp);

void
lwres_gnbarequest_free(lwres_context_t *ctx, lwres_gnbarequest_t **structp);
/*
 * Frees any dynamically allocated memory for this structure.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp != NULL.
 *
 * Ensures:
 *
 *	*structp == NULL.
 *
 *	All memory allocated by this structure will be returned to the
 *	system via the context's free function.
 */

void
lwres_gnbaresponse_free(lwres_context_t *ctx, lwres_gnbaresponse_t **structp);
/*
 * Frees any dynamically allocated memory for this structure.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp != NULL.
 *
 * Ensures:
 *
 *	*structp == NULL.
 *
 *	All memory allocated by this structure will be returned to the
 *	system via the context's free function.
 */

lwres_result_t
lwres_nooprequest_render(lwres_context_t *ctx, lwres_nooprequest_t *req,
			 lwres_lwpacket_t *pkt, lwres_buffer_t *b);
/*
 * Allocate space and render into wire format a noop request packet.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	b != NULL, and points to a lwres_buffer_t.  The contents of the
 *	buffer structure will be initialized to contain the wire-format
 *	noop request packet.
 *
 *	Caller needs to fill in parts of "pkt" before calling:
 *		serial, maxrecv, result.
 *
 * Returns:
 *
 *	Returns 0 on success, non-zero on failure.
 *
 *	On successful return, *b will contain data about the wire-format
 *	packet.  It can be transmitted in any way, including lwres_sendblock().
 */

lwres_result_t
lwres_noopresponse_render(lwres_context_t *ctx, lwres_noopresponse_t *req,
			  lwres_lwpacket_t *pkt, lwres_buffer_t *b);

lwres_result_t
lwres_nooprequest_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			lwres_lwpacket_t *pkt, lwres_nooprequest_t **structp);
/*
 * Parse a noop request.  Note that to get here, the lwpacket must have
 * already been parsed and removed by the caller, otherwise it would be
 * pretty hard for it to know this is the right function to call.
 *
 * The function verifies bits of the header, but does not modify it.
 */

lwres_result_t
lwres_noopresponse_parse(lwres_context_t *ctx, lwres_buffer_t *b,
			 lwres_lwpacket_t *pkt,
			 lwres_noopresponse_t **structp);

void
lwres_nooprequest_free(lwres_context_t *ctx, lwres_nooprequest_t **structp);

void
lwres_noopresponse_free(lwres_context_t *ctx, lwres_noopresponse_t **structp);

/*
 * Frees any dynamically allocated memory for this structure.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp != NULL.
 *
 * Ensures:
 *
 *	*structp == NULL.
 *
 *	All memory allocated by this structure will be returned to the
 *	system via the context's free function.
 */

lwres_result_t
lwres_conf_parse(lwres_context_t *ctx, const char *filename);
/*
 * parses a resolv.conf-format file and puts the results into *confdata;
 *
 * Requires:
 *	confdata != NULL
 *	filename != NULL && strlen(filename) > 0
 *
 * Returns:
 *	LWRES_R_SUCCESS on a succesfull parse.
 *	Anything else on error.
 */

void
lwres_conf_free(lwres_context_t *ctx);
/*
 * Returns the data in confdata to the system.
 *
 * Requires:
 *	confdata != NULL
 *	that confdata had been previously passed to lwres_conf_parse()
 */

lwres_result_t
lwres_conf_print(lwres_context_t *ctx, FILE *fp);
/*
 * Prints a resolv.conf-format of confdata output to fp.
 */

void
lwres_conf_init(lwres_context_t *ctx);
/*
 * sets all internal fields to a default state. Used to initialize a new
 * lwres_conf_t structure (not reset a used on).
 */

void
lwres_conf_clear(lwres_context_t *ctx);
/*
 * frees all internally allocated memory in confdata. Uses the memory 
 * routines supplies by ctx (so that should probably be the same value as
 * given to lwres_conf_parse()).
 */

lwres_conf_t *
lwres_conf_get(lwres_context_t *ctx);
/*
 * returns a pointer to the current config structure.
 * Be extremely cautions in modifying the contents of this structure; it
 * needs an API to return the various bits of data, walk lists, etc.
 */

/*
 * Helper functions
 */

lwres_result_t
lwres_string_parse(lwres_buffer_t *b, char **c, lwres_uint16_t *len);

lwres_result_t
lwres_addr_parse(lwres_buffer_t *b, lwres_addr_t *addr);

lwres_result_t
lwres_getaddrsbyname(lwres_context_t *ctx, const char *name,
		     lwres_uint32_t addrtypes, lwres_gabnresponse_t **structp);

lwres_result_t
lwres_getnamebyaddr(lwres_context_t *ctx, lwres_uint32_t addrtype,
		    lwres_uint16_t addrlen, const unsigned char *addr,
		    lwres_gnbaresponse_t **structp);

LWRES_LANG_ENDDECLS

#endif /* LWRES_LWRES_H */
