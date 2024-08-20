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

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#if HAVE_SYS_SYSCTL_H && !defined(__linux__)
#include <sys/sysctl.h>
#endif

#include <isc/log.h>
#include <isc/net.h>
#include <isc/once.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

/*%
 * Definitions about UDP port range specification.  This is a total mess of
 * portability variants: some use sysctl (but the sysctl names vary), some use
 * system-specific interfaces, some have the same interface for IPv4 and IPv6,
 * some separate them, etc...
 */

/*%
 * The last resort defaults: use all non well known port space
 */
#ifndef ISC_NET_PORTRANGELOW
#define ISC_NET_PORTRANGELOW 1024
#endif /* ISC_NET_PORTRANGELOW */
#ifndef ISC_NET_PORTRANGEHIGH
#define ISC_NET_PORTRANGEHIGH 65535
#endif /* ISC_NET_PORTRANGEHIGH */

#ifdef HAVE_SYSCTLBYNAME

/*%
 * sysctl variants
 */
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
#define USE_SYSCTL_PORTRANGE
#define SYSCTL_V4PORTRANGE_LOW	"net.inet.ip.portrange.hifirst"
#define SYSCTL_V4PORTRANGE_HIGH "net.inet.ip.portrange.hilast"
#define SYSCTL_V6PORTRANGE_LOW	"net.inet.ip.portrange.hifirst"
#define SYSCTL_V6PORTRANGE_HIGH "net.inet.ip.portrange.hilast"
#endif /* if defined(__FreeBSD__) || defined(__APPLE__) || \
	* defined(__DragonFly__) */

#ifdef __NetBSD__
#define USE_SYSCTL_PORTRANGE
#define SYSCTL_V4PORTRANGE_LOW	"net.inet.ip.anonportmin"
#define SYSCTL_V4PORTRANGE_HIGH "net.inet.ip.anonportmax"
#define SYSCTL_V6PORTRANGE_LOW	"net.inet6.ip6.anonportmin"
#define SYSCTL_V6PORTRANGE_HIGH "net.inet6.ip6.anonportmax"
#endif /* ifdef __NetBSD__ */

#else /* !HAVE_SYSCTLBYNAME */

#ifdef __OpenBSD__
#define USE_SYSCTL_PORTRANGE
#define SYSCTL_V4PORTRANGE_LOW \
	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_HIFIRSTAUTO }
#define SYSCTL_V4PORTRANGE_HIGH \
	{ CTL_NET, PF_INET, IPPROTO_IP, IPCTL_IPPORT_HILASTAUTO }
/* Same for IPv6 */
#define SYSCTL_V6PORTRANGE_LOW	SYSCTL_V4PORTRANGE_LOW
#define SYSCTL_V6PORTRANGE_HIGH SYSCTL_V4PORTRANGE_HIGH
#endif /* ifdef __OpenBSD__ */

#endif /* HAVE_SYSCTLBYNAME */

static isc_result_t ipv4_result = ISC_R_SUCCESS;
static isc_result_t ipv6_result = ISC_R_SUCCESS;

isc_result_t
isc_net_probeipv4(void) {
	return ipv4_result;
}

isc_result_t
isc_net_probeipv6(void) {
	return ipv6_result;
}

#if defined(USE_SYSCTL_PORTRANGE)
#if defined(HAVE_SYSCTLBYNAME)
static isc_result_t
getudpportrange_sysctl(int af, in_port_t *low, in_port_t *high) {
	int port_low, port_high;
	size_t portlen;
	const char *sysctlname_lowport, *sysctlname_hiport;

	if (af == AF_INET) {
		sysctlname_lowport = SYSCTL_V4PORTRANGE_LOW;
		sysctlname_hiport = SYSCTL_V4PORTRANGE_HIGH;
	} else {
		sysctlname_lowport = SYSCTL_V6PORTRANGE_LOW;
		sysctlname_hiport = SYSCTL_V6PORTRANGE_HIGH;
	}
	portlen = sizeof(port_low);
	if (sysctlbyname(sysctlname_lowport, &port_low, &portlen, NULL, 0) < 0)
	{
		return ISC_R_FAILURE;
	}
	portlen = sizeof(port_high);
	if (sysctlbyname(sysctlname_hiport, &port_high, &portlen, NULL, 0) < 0)
	{
		return ISC_R_FAILURE;
	}
	if ((port_low & ~0xffff) != 0 || (port_high & ~0xffff) != 0) {
		return ISC_R_RANGE;
	}

	*low = (in_port_t)port_low;
	*high = (in_port_t)port_high;

	return ISC_R_SUCCESS;
}
#else  /* !HAVE_SYSCTLBYNAME */
static isc_result_t
getudpportrange_sysctl(int af, in_port_t *low, in_port_t *high) {
	int mib_lo4[4] = SYSCTL_V4PORTRANGE_LOW;
	int mib_hi4[4] = SYSCTL_V4PORTRANGE_HIGH;
	int mib_lo6[4] = SYSCTL_V6PORTRANGE_LOW;
	int mib_hi6[4] = SYSCTL_V6PORTRANGE_HIGH;
	int *mib_lo, *mib_hi, miblen;
	int port_low, port_high;
	size_t portlen;

	if (af == AF_INET) {
		mib_lo = mib_lo4;
		mib_hi = mib_hi4;
		miblen = sizeof(mib_lo4) / sizeof(mib_lo4[0]);
	} else {
		mib_lo = mib_lo6;
		mib_hi = mib_hi6;
		miblen = sizeof(mib_lo6) / sizeof(mib_lo6[0]);
	}

	portlen = sizeof(port_low);
	if (sysctl(mib_lo, miblen, &port_low, &portlen, NULL, 0) < 0) {
		return ISC_R_FAILURE;
	}

	portlen = sizeof(port_high);
	if (sysctl(mib_hi, miblen, &port_high, &portlen, NULL, 0) < 0) {
		return ISC_R_FAILURE;
	}

	if ((port_low & ~0xffff) != 0 || (port_high & ~0xffff) != 0) {
		return ISC_R_RANGE;
	}

	*low = (in_port_t)port_low;
	*high = (in_port_t)port_high;

	return ISC_R_SUCCESS;
}
#endif /* HAVE_SYSCTLBYNAME */
#endif /* USE_SYSCTL_PORTRANGE */

isc_result_t
isc_net_getudpportrange(int af, in_port_t *low, in_port_t *high) {
	int result = ISC_R_FAILURE;
#if !defined(USE_SYSCTL_PORTRANGE) && defined(__linux)
	FILE *fp;
#endif /* if !defined(USE_SYSCTL_PORTRANGE) && defined(__linux) */

	REQUIRE(low != NULL && high != NULL);

#if defined(USE_SYSCTL_PORTRANGE)
	result = getudpportrange_sysctl(af, low, high);
#elif defined(__linux)

	UNUSED(af);

	/*
	 * Linux local ports are address family agnostic.
	 */
	fp = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
	if (fp != NULL) {
		int n;
		unsigned int l, h;

		n = fscanf(fp, "%u %u", &l, &h);
		if (n == 2 && (l & ~0xffff) == 0 && (h & ~0xffff) == 0) {
			*low = l;
			*high = h;
			result = ISC_R_SUCCESS;
		}
		fclose(fp);
	}
#else  /* if defined(USE_SYSCTL_PORTRANGE) */
	UNUSED(af);
#endif /* if defined(USE_SYSCTL_PORTRANGE) */

	if (result != ISC_R_SUCCESS) {
		*low = ISC_NET_PORTRANGELOW;
		*high = ISC_NET_PORTRANGEHIGH;
	}

	return ISC_R_SUCCESS; /* we currently never fail in this function */
}

void
isc_net_disableipv4(void) {
	if (ipv4_result == ISC_R_SUCCESS) {
		ipv4_result = ISC_R_DISABLED;
	}
}

void
isc_net_disableipv6(void) {
	if (ipv6_result == ISC_R_SUCCESS) {
		ipv6_result = ISC_R_DISABLED;
	}
}

void
isc_net_enableipv4(void) {
	if (ipv4_result == ISC_R_DISABLED) {
		ipv4_result = ISC_R_SUCCESS;
	}
}

void
isc_net_enableipv6(void) {
	if (ipv6_result == ISC_R_DISABLED) {
		ipv6_result = ISC_R_SUCCESS;
	}
}
