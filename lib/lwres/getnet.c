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

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>

#include <lwres/netdb.h>

#include "assert_p.h"

struct netent *
lwres_getnetbyname(const char *name) {

	/* XXX */
	UNUSED(name);
	return (NULL);
}

struct netent *
lwres_getnetbyaddr(unsigned long net, int type) {

	if (type == AF_INET) 
		return (NULL);

	/* XXX */
	UNUSED(net);
	return (NULL);
}

struct netent *
lwres_getnetent() {

	return (NULL);
}

void
lwres_setnetent(int stayopen) {
	
	UNUSED(stayopen);
	/* empty */
}

void
lwres_endnetent() {
	/* empty */
}

struct netent *
lwres_getnetbyname_r(const char *name, struct netent *resbuf, char *buf,
	       int buflen)
{
	return (NULL);
}

struct netent *
lwres_getnetbyaddr_r(long addr, int type, struct netent *resbuf, char *buf,
	       int buflen)
{
	return (NULL);
}

struct netent *
lwres_getnetent_r(struct netent *resbuf, char *buf, int buflen) {
	return (NULL);
}

void
lwres_setnetent_r(int stayopen) {
	(void)stayopen;
}

void
lwres_endnetent_r(void) {
	/* empty */
}
