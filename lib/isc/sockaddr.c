/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <isc/types.h>
#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/sockaddr.h>
#include <isc/mem.h>

isc_boolean_t
isc_sockaddr_equal(const isc_sockaddr_t *a, const isc_sockaddr_t *b)
{
	REQUIRE(a != NULL && b != NULL);

	if (a->length != b->length)
		return (ISC_FALSE);

	/*
	 * We don't just memcmp because the sin_zero field isn't always
	 * zero.
	 */

	if (a->type.sa.sa_family != b->type.sa.sa_family)
		return (ISC_FALSE);
	switch (a->type.sa.sa_family) {
	case AF_INET:
		if (memcmp(&a->type.sin.sin_addr, &b->type.sin.sin_addr,
			   sizeof a->type.sin.sin_addr) != 0)
			return (ISC_FALSE);
		if (a->type.sin.sin_port != b->type.sin.sin_port)
			return (ISC_FALSE);
		break;
	case AF_INET6:
		if (memcmp(&a->type.sin6.sin6_addr, &b->type.sin6.sin6_addr,
			   sizeof a->type.sin6.sin6_addr) != 0)
			return (ISC_FALSE);
		if (a->type.sin6.sin6_port != b->type.sin6.sin6_port)
			return (ISC_FALSE);
		break;
	default:
		if (memcmp(&a->type, &b->type, a->length) != 0)
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}


/*
 * Compare just the addresses (ignore ports)
 */
isc_boolean_t
isc_sockaddr_eqaddr(const isc_sockaddr_t *a, const isc_sockaddr_t *b)
{
	REQUIRE(a != NULL && b != NULL);

	if (a->length != b->length)
		return (ISC_FALSE);

	if (a->type.sa.sa_family != b->type.sa.sa_family)
		return (ISC_FALSE);
	switch (a->type.sa.sa_family) {
	case AF_INET:
		if (memcmp(&a->type.sin.sin_addr, &b->type.sin.sin_addr,
			   sizeof a->type.sin.sin_addr) != 0)
			return (ISC_FALSE);
		break;
	case AF_INET6:
		if (memcmp(&a->type.sin6.sin6_addr, &b->type.sin6.sin6_addr,
			   sizeof a->type.sin6.sin6_addr) != 0)
			return (ISC_FALSE);
		break;
	default:
		if (memcmp(&a->type, &b->type, a->length) != 0)
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

/*
 * Compare just a prefix of the addresses (ignore ports and
 * low address bits)
 */

isc_boolean_t
isc_sockaddr_eqaddrprefix(const isc_sockaddr_t *a, const isc_sockaddr_t *b,
			  unsigned int prefixlen)
{
	unsigned char *pa, *pb;
	unsigned int ipabytes; /* Length of whole IP address in bytes */
	unsigned int nbytes;   /* Number of significant whole bytes */
	unsigned int nbits;    /* Number of significant leftover bits */
	
	REQUIRE(a != NULL && b != NULL);

	if (a->length != b->length)
		return (ISC_FALSE);

	if (a->type.sa.sa_family != b->type.sa.sa_family)
		return (ISC_FALSE);

	switch (a->type.sa.sa_family) {
	case AF_INET:
		pa = (unsigned char *) &a->type.sin.sin_addr;
		pb = (unsigned char *) &b->type.sin.sin_addr;
		ipabytes = 4;
		break;
	case AF_INET6:
		pa = ((unsigned char *) &a->type.sin6.sin6_addr);
		pb = ((unsigned char *) &b->type.sin6.sin6_addr);
		ipabytes = 16;
		break;
	default:
		pa = pb = NULL; /* Avoid silly compiler warning. */
		ipabytes = 0; /* Ditto. */
		return (ISC_FALSE); /* XXX got a better idea? */
	}

	/* Don't crash if we get a pattern like 10.0.0.1/9999999. */
	if (prefixlen > ipabytes * 8)
		prefixlen = ipabytes * 8;

	nbytes = prefixlen / 8;
	nbits = prefixlen % 8;

	if (nbytes > 0) {
		if (memcmp(pa, pb, nbytes) != 0)
			return (ISC_FALSE);
	}
	if (nbits > 0) {
		unsigned int bytea, byteb, mask;
		INSIST(nbytes < ipabytes);
		INSIST(nbits < 8);
		bytea = pa[nbytes];
		byteb = pb[nbytes];
		mask = (0xFF << (8-nbits)) & 0xFF;
		if ((bytea & mask) != (byteb & mask))
			return (ISC_FALSE);
	}
	return (ISC_TRUE);
}

isc_result_t
isc_sockaddr_totext(const isc_sockaddr_t *sockaddr, isc_buffer_t *target) {
	char abuf[sizeof "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255"];
	unsigned int alen;
	char pbuf[sizeof "65000"];
	unsigned int plen;
	isc_region_t avail;
	const struct sockaddr *sa;
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;

	REQUIRE(sockaddr != NULL);

	sa = &sockaddr->type.sa;
	switch (sa->sa_family) {
	case AF_INET:
		sin = &sockaddr->type.sin;
		inet_ntop(sa->sa_family, &sin->sin_addr, abuf, sizeof abuf);
		sprintf(pbuf, "%u", ntohs(sin->sin_port));
		break;
	case AF_INET6:
		sin6 = &sockaddr->type.sin6;
		inet_ntop(sa->sa_family, &sin6->sin6_addr, abuf, sizeof abuf);
		sprintf(pbuf, "%u", ntohs(sin6->sin6_port));
		break;
	default:
		return (ISC_R_NOTIMPLEMENTED);
	}

	alen = strlen(abuf);
	plen = strlen(pbuf);

	isc_buffer_available(target, &avail);
	if (alen + 1 + plen + 1 > avail.length)
		return (ISC_R_NOSPACE);
	    
	isc_buffer_putmem(target, (unsigned char *) abuf, alen);
	isc_buffer_putmem(target, (unsigned char *)"#", 1);
	isc_buffer_putmem(target, (unsigned char *) pbuf, plen);

	/* Null terminate after used region. */
	isc_buffer_available(target, &avail);
	INSIST(avail.length >= 1);
	avail.base[0] = '\0';

	return (ISC_R_SUCCESS);
}

unsigned int
isc_sockaddr_hash(const isc_sockaddr_t *sockaddr, isc_boolean_t address_only) {
	unsigned int length;
	const unsigned char *s;
	unsigned int h = 0;
	unsigned int g;
	
	/*
	 * Provide a hash value for 'sockaddr'.
	 */

	REQUIRE(sockaddr != NULL);

	if (address_only) {
		switch (sockaddr->type.sa.sa_family) {
		case AF_INET:
			return (ntohl(sockaddr->type.sin.sin_addr.s_addr));
		case AF_INET6:
			s = (unsigned char *)&sockaddr->type.sin6.sin6_addr;
			length = sizeof sockaddr->type.sin6.sin6_addr;
			break;
		default:
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "unknown address family: %d\n",
					 (int)sockaddr->type.sa.sa_family);
			s = (unsigned char *)&sockaddr->type;
			length = sockaddr->length;
		}
	} else {
		s = (unsigned char *)&sockaddr->type;
		length = sockaddr->length;
	}

	while (length > 0) {
		h = ( h << 4 ) + *s;
		if ((g = ( h & 0xf0000000 )) != 0) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
		length--;
	}
	return (h);
}

void
isc_sockaddr_fromin(isc_sockaddr_t *sockaddr, const struct in_addr *ina,
		    in_port_t port)
{
	memset(sockaddr, 0, sizeof *sockaddr);
	sockaddr->type.sin.sin_family = AF_INET;
#ifdef ISC_PLATFORM_HAVESALEN
	sockaddr->type.sin.sin_len = sizeof sockaddr->type.sin;
#endif
	sockaddr->type.sin.sin_addr = *ina;
	sockaddr->type.sin.sin_port = htons(port);
	sockaddr->length = sizeof sockaddr->type.sin;
	ISC_LINK_INIT(sockaddr, link);
}

void
isc_sockaddr_fromin6(isc_sockaddr_t *sockaddr, const struct in6_addr *ina6,
		     in_port_t port)
{
	memset(sockaddr, 0, sizeof *sockaddr);
	sockaddr->type.sin6.sin6_family = AF_INET6;
#ifdef ISC_PLATFORM_HAVESALEN
	sockaddr->type.sin6.sin6_len = sizeof sockaddr->type.sin6;
#endif
	sockaddr->type.sin6.sin6_addr = *ina6;
	sockaddr->type.sin6.sin6_port = htons(port);
	sockaddr->length = sizeof sockaddr->type.sin6;
	ISC_LINK_INIT(sockaddr, link);
}

void
isc_sockaddr_v6fromin(isc_sockaddr_t *sockaddr, const struct in_addr *ina,
		      in_port_t port)
{
	memset(sockaddr, 0, sizeof *sockaddr);
	sockaddr->type.sin6.sin6_family = AF_INET6;
#ifdef ISC_PLATFORM_HAVESALEN
	sockaddr->type.sin6.sin6_len = sizeof sockaddr->type.sin6;
#endif
	sockaddr->type.sin6.sin6_addr.s6_addr[10] = 0xff;
	sockaddr->type.sin6.sin6_addr.s6_addr[11] = 0xff;
	memcpy(&sockaddr->type.sin6.sin6_addr.s6_addr[12], ina, 4);
	sockaddr->type.sin6.sin6_port = htons(port);
	sockaddr->length = sizeof sockaddr->type.sin6;
	ISC_LINK_INIT(sockaddr, link);
}

int
isc_sockaddr_pf(const isc_sockaddr_t *sockaddr) {

	/*
	 * Get the protocol family of 'sockaddr'.
	 */

#if (AF_INET == PF_INET && AF_INET6 == PF_INET6)
	/*
	 * Assume that PF_xxx == AF_xxx for all AF and PF.
	 */
	return (sockaddr->type.sa.sa_family);
#else
	switch (sockaddr->type.sa.sa_family) {
	case AF_INET:
		return (PF_INET);
	case AF_INET6:
		return (PF_INET);
	default:
		FATAL_ERROR(__FILE__, __LINE__, "unknown address family");
	}
#endif
}

void
isc_sockaddr_setport(isc_sockaddr_t *sockaddr, in_port_t port) {
	switch (sockaddr->type.sa.sa_family) {
	case AF_INET:
		sockaddr->type.sin.sin_port = htons(port);
		break;
	case AF_INET6:
		sockaddr->type.sin6.sin6_port = htons(port);
		break;
	default:
		FATAL_ERROR(__FILE__, __LINE__, "unknown address family");
	}
}

in_port_t
isc_sockaddr_getport(isc_sockaddr_t *sockaddr) {
	in_port_t port = 0;

	switch (sockaddr->type.sa.sa_family) {
	case AF_INET:
		port = ntohs(sockaddr->type.sin.sin_port);
		break;
	case AF_INET6:
		port = ntohs(sockaddr->type.sin6.sin6_port);
		break;
	default:
		FATAL_ERROR(__FILE__, __LINE__, "unknown address family");
	}

	return (port);
}
