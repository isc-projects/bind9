/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2008, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: context_p.h,v 1.19 2008/12/17 23:47:58 tbox Exp $ */

#ifndef LWRES_CONTEXT_P_H
#define LWRES_CONTEXT_P_H 1

/*! \file */

/*@{*/
/**
 * Helper functions, assuming the context is always called "ctx" in
 * the scope these functions are called from.
 */
#define CTXMALLOC(len)		ctx->malloc(ctx->arg, (len))
#define CTXFREE(addr, len)	ctx->free(ctx->arg, (addr), (len))
/*@}*/

#define LWRES_DEFAULT_TIMEOUT	120	/* 120 seconds for a reply */

/**
 * Not all the attributes here are actually settable by the application at
 * this time.
 */
struct lwres_context {
	unsigned int		timeout;	/*%< time to wait for reply */
	lwres_uint32_t		serial;		/*%< serial number state */

	/*
	 * For network I/O.
	 */
	int			sock;		/*%< socket to send on */
	lwres_addr_t		address;	/*%< address to send to */
	int			use_ipv4;	/*%< use IPv4 transaction */
	int			use_ipv6;	/*%< use IPv6 transaction */

	/*@{*/
	/*
	 * Function pointers for allocating memory.
	 */
	lwres_malloc_t		malloc;
	lwres_free_t		free;
	void		       *arg;
	/*@}*/

	/*%
	 * resolv.conf-like data
	 */
	lwres_conf_t		confdata;
};

#endif /* LWRES_CONTEXT_P_H */
