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

#include <inttypes.h>
#include <sys/stat.h>

#include <isc/os.h>
#include <isc/types.h>
#include <isc/util.h>
#include <isc/uv.h>

#include "os_p.h"
#include "thread_p.h"

static unsigned int isc__os_ncpus = 0;
static unsigned long isc__os_cacheline = ISC_OS_CACHELINE_SIZE;
static mode_t isc__os_umask = 0;

/*
 * The affinity support for non-Linux is in the review in the upstream
 * yet, but will be included in the upcoming version of libuv.
 */
#if (UV_VERSION_HEX >= UV_VERSION(1, 44, 0) && defined(__linux__)) || \
	UV_VERSION_HEX > UV_VERSION(1, 48, 0)

static void
ncpus_initialize(void) {
	isc__os_ncpus = uv_available_parallelism();
}

#else /* UV_VERSION_HEX >= UV_VERSION(1, 44, 0) */

#include <sys/param.h> /* for NetBSD */
#if HAVE_SYS_SYSCTL_H && !defined(__linux__)
#include <sys/sysctl.h>
#endif
#include <sys/types.h> /* for OpenBSD */
#include <unistd.h>

static int
sysconf_ncpus(void) {
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	return (int)ncpus;
}

#if HAVE_SYSCTLBYNAME
static int
sysctlbyname_ncpus(void) {
	int ncpu;
	size_t len = sizeof(ncpu);
	static const char *mib[] = {
		"hw.activecpu",
		"hw.logicalcpu",
		"hw.ncpu",
	};

	for (size_t i = 0; i < ARRAY_SIZE(mib); i++) {
		int r = sysctlbyname(mib[i], &ncpu, &len, NULL, 0);
		if (r != -1) {
			return ncpu;
		}
	}
	return -1;
}
#endif /* HAVE_SYSCTLBYNAME */

#if HAVE_SYS_SYSCTL_H && !defined(__linux__)
static int
sysctl_ncpus(void) {
	int ncpu;
	size_t len = sizeof(ncpu);
	static int mib[][2] = {
#ifdef HW_NCPUONLINE
		{ CTL_HW, HW_NCPUONLINE },
#endif
		{ CTL_HW, HW_NCPU },
	};

	for (size_t i = 0; i < ARRAY_SIZE(mib); i++) {
		int r = sysctl(mib[i], ARRAY_SIZE(mib[i]), &ncpu, &len, NULL,
			       0);
		if (r != -1) {
			return ncpu;
		}
	}
	return -1;
}
#endif /* HAVE_SYS_SYSCTL_H */

#if defined(HAVE_SCHED_GETAFFINITY)
#include <sched.h>

/*
 * Administrators may wish to constrain the set of cores that BIND runs
 * on via the 'taskset' or 'numactl' programs (or equivalent on other
 * O/S), for example to achieve higher (or more stable) performance by
 * more closely associating threads with individual NIC rx queues. If
 * the admin has used taskset, it follows that BIND ought to
 * automatically use the given number of CPUs rather than the system
 * wide count.
 */
static int
sched_affinity_ncpus(void) {
	cpu_set_t cpus;
	int r = sched_getaffinity(0, sizeof(cpus), &cpus);
	if (r != -1) {
		return CPU_COUNT(&cpus);
	}
	return -1;
}
#endif

/*
 * Affinity detecting variant of sched_affinity_cpus() for FreeBSD
 */
#if defined(HAVE_CPUSET_GETAFFINITY)
#include <sys/cpuset.h>
#include <sys/param.h>

static int
cpuset_affinity_ncpus(void) {
	cpuset_t cpus;
	int r = cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
				   sizeof(cpus), &cpus);
	if (r != -1) {
		return CPU_COUNT(&cpus);
	}
	return -1;
}
#endif

static void
ncpus_initialize(void) {
#if defined(HAVE_CPUSET_GETAFFINITY)
	if (isc__os_ncpus <= 0) {
		isc__os_ncpus = cpuset_affinity_ncpus();
	}
#endif
#if defined(HAVE_SCHED_GETAFFINITY)
	if (isc__os_ncpus <= 0) {
		isc__os_ncpus = sched_affinity_ncpus();
	}
#endif
#if HAVE_SYSCTLBYNAME
	if (isc__os_ncpus <= 0) {
		isc__os_ncpus = sysctlbyname_ncpus();
	}
#endif
#if HAVE_SYS_SYSCTL_H && !defined(__linux__)
	if (isc__os_ncpus <= 0) {
		isc__os_ncpus = sysctl_ncpus();
	}
#endif
	if (isc__os_ncpus <= 0) {
		isc__os_ncpus = sysconf_ncpus();
	}
	if (isc__os_ncpus <= 0) {
		isc__os_ncpus = 1;
	}
}

#endif /* UV_VERSION_HEX >= UV_VERSION(1, 38, 0) */

static void
umask_initialize(void) {
	isc__os_umask = umask(0);
	(void)umask(isc__os_umask);
}

unsigned int
isc_os_ncpus(void) {
	return isc__os_ncpus;
}

unsigned long
isc_os_cacheline(void) {
	return isc__os_cacheline;
}

mode_t
isc_os_umask(void) {
	return isc__os_umask;
}

void
isc__os_initialize(void) {
	umask_initialize();
	ncpus_initialize();
#if defined(_SC_LEVEL1_DCACHE_LINESIZE)
	long s = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	if (s > 0 && (unsigned long)s > isc__os_cacheline) {
		isc__os_cacheline = s;
	}
#endif

	pthread_attr_init(&isc__thread_attr);

	size_t stacksize = isc_thread_getstacksize();
	if (stacksize != 0 && stacksize < THREAD_MINSTACKSIZE) {
		isc_thread_setstacksize(THREAD_MINSTACKSIZE);
	}
}

void
isc__os_shutdown(void) {
	pthread_attr_destroy(&isc__thread_attr);
}
