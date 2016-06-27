/*
 * Copyright (C) 2002, 2004-2007, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*! \file */

#if defined(LIBC_SCCS) && !defined(lint)
static char rcsid[] =
	"$Id: netscope.c,v 1.13 2007/06/19 23:47:17 tbox Exp $";
#endif /* LIBC_SCCS and not lint */

#include <config.h>

#include <isc/string.h>
#include <isc/net.h>
#include <isc/netscope.h>
#include <isc/result.h>

isc_result_t
isc_netscope_pton(int af, char *scopename, void *addr, isc_uint32_t *zoneid) {
	char *ep;
#ifdef ISC_PLATFORM_HAVEIFNAMETOINDEX
	unsigned int ifid;
#endif
	struct in6_addr *in6;
	isc_uint32_t zone;
	isc_uint64_t llz;

	/* at this moment, we only support AF_INET6 */
	if (af != AF_INET6)
		return (ISC_R_FAILURE);

	in6 = (struct in6_addr *)addr;

	/*
	 * Basically, "names" are more stable than numeric IDs in terms of
	 * renumbering, and are more preferred.  However, since there is no
	 * standard naming convention and APIs to deal with the names.  Thus,
	 * we only handle the case of link-local addresses, for which we use
	 * interface names as link names, assuming one to one mapping between
	 * interfaces and links.
	 */
#ifdef ISC_PLATFORM_HAVEIFNAMETOINDEX
	if (IN6_IS_ADDR_LINKLOCAL(in6) &&
	    (ifid = if_nametoindex((const char *)scopename)) != 0)
		zone = (isc_uint32_t)ifid;
	else {
#endif
		llz = isc_string_touint64(scopename, &ep, 10);
		if (ep == scopename)
			return (ISC_R_FAILURE);

		/* check overflow */
		zone = (isc_uint32_t)(llz & 0xffffffffUL);
		if (zone != llz)
			return (ISC_R_FAILURE);
#ifdef ISC_PLATFORM_HAVEIFNAMETOINDEX
	}
#endif

	*zoneid = zone;
	return (ISC_R_SUCCESS);
}
