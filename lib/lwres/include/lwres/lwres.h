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

#include <stddef.h>

#include <isc/lang.h>
#include <isc/int.h>

/*
 * Used to set various options such as timeout, authentication, etc
 */
typedef struct lwres_context lwres_context_t;

/*
 * NO-OP
 */
#define LWRES_OPCODE_NOOP		0x00000000U

typedef struct {
	/* public */
	isc_uint32_t		result;
	isc_uint16_t		datalength;
	unsigned char	       *data;
	/* private */
	isc_uint32_t		buflen;
	void		       *buffer;
} lwres_noop_t;

/*
 * GET ADDRESSES BY NAME
 */
#define LWRES_OPCODE_GETADDRSBYNAME	0x00010001U

typedef struct {
	isc_uint32_t		family;
	isc_uint16_t		length;
	unsigned char	       *address;
} lwres_addr_t;

typedef struct {
	/* public */
	isc_uint32_t		result;
	isc_uint16_t		naliases;
	isc_uint16_t		naddrs;
	char		       *real_name;
	char		      **aliases;
	lwres_addr_t	      **addrs;
	/* private */
	isc_uint32_t		buflen;
	void		       *buffer;  /* must be last to keep alignment */
	/* variable length data follows */
} lwres_getaddrsbyname_t;

/*
 * GET NAME BY ADDRESS
 */
#define LWRES_OPCODE_GETNAMEBYADDR	0x00010002U
typedef struct {
	/* public */
	isc_uint32_t		result;
	isc_uint16_t		naliases;
	char		       *real_name;
	char		      **aliases;
	/* private */
	isc_uint32_t		buflen;
	void		       *buffer;  /* must be last to keep alignment */
	/* variable length data follows */
} lwres_getnamebyaddr_t;

#define LWRES_ADDRTYPE_V4		0x00000001U	/* ipv4 */
#define LWRES_ADDRTYPE_V6		0x00000002U	/* ipv6 */

ISC_LANG_BEGINDECLS

typedef void *(*lwres_malloc_t)(void *arg, size_t length);
typedef void (*lwres_free_t)(void *arg, void *mem, size_t length);

int
lwres_getaddrsbyname(lwres_context_t *ctx,
		     char *name, isc_uint32_t addrtypes,
		     lwres_getaddrsbyname_t **structp);
/*
 * Makes a lwres call to look up all addresses associated with "name".
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp == NULL.
 *
 *	name != NULL, and be a null-terminated string.
 *
 *	addrtypes be a bitmask of the LWRES_ADDRTYPE_* constants representing
 *	the type of addresses wanted.
 *
 * Returns:
 *
 *	Returns 0 on success, non-zero on failure.
 *
 *	On successful return, *structp will be non-NULL, and will point to
 *	an allocated structure returning the data requested.  This structure
 *	must be freed using lwres_freegetaddrsbyname() when it is no longer
 *	needed.
 */

void
lwres_freegetaddrsbyname(lwres_context_t *ctx,
			 lwres_getaddrsbyname_t **structp);
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

int
lwres_getaddrsbyname_fromstruct(lwres_context_t *ctx,
				isc_uint8_t *buf, size_t len,
				lwres_getaddrsbyname_t *gabn);
/*
 * XXXMLG document
 */

int
lwres_getnamebyaddr(lwres_context_t *ctx, isc_uint32_t addrtype,
		    isc_uint16_t addrlen, unsigned char *addr,
		    lwres_getnamebyaddr_t **structp);
/*
 * Makes a lwres call to look up the hostnames associated with the address.
 *
 * Requires:
 *
 *	ctx != NULL, and be a context returned via lwres_contextcreate().
 *
 *	structp != NULL && *structp == NULL.
 *
 *	addr != NULL, and points to an address of length "addrlen"
 *
 *	addrtype have exactly one bit set, from the LWRES_ADDRTYPE_* constants.
 *
 * Returns:
 *
 *	Returns 0 on success, non-zero on failure.
 *
 *	On successful return, *structp will be non-NULL, and will point to
 *	an allocated structure returning the data requested.  This structure
 *	must be freed using lwres_freegetnamebyaddr() when it is no longer
 *	needed.
 */

void
lwres_freegetnamebyaddr(lwres_context_t *ctx,
			lwres_getnamebyaddr_t **structp);
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
 *	system via the ctx's free function.
 */

int
lwres_noop_render(lwres_context_t *ctx, isc_uint16_t datalength,
		  void *data, lwres_buffer_t *b);
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
 * Returns:
 *
 *	Returns 0 on success, non-zero on failure.
 *
 *	On successful return, *b will contain data about the wire-format
 *	packet.  It can be transmitted in any way, including lwres_sendblock().
 */

void
lwres_freenoop(lwres_context_t *ctx, lwres_noop_t **structp);
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

int
lwres_contextcreate(lwres_context_t **contextp, void *arg,
		    lwres_malloc_t malloc_function,
		    lwres_free_t free_function);
/*
 * Allocate a lwres context.  This is used in all lwres calls.
 *
 * Memory management can be replaced here by passing in two functions.
 * If one is non-NULL, they must both be non-NULL.  "arg" is passed to
 * these functions.
 *
 * If they are NULL, the standard malloc() and free() will be used.
 *
 * Requires:
 *
 *	contextp != NULL && contextp == NULL.
 *
 * Returns:
 *
 *	Returns 0 on success, non-zero on failure.
 */

void
lwres_freecontext(lwres_context_t **contextp);
/*
 * Frees all memory associated with a lwres context.
 *
 * Requires:
 *
 *	contextp != NULL && contextp == NULL.
 */

ISC_LANG_ENDDECLS

#endif /* LWRES_LWRES_H */
