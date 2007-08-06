/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: os.c,v 1.10 2001/02/17 01:23:43 gson Exp $ */

#include <config.h>

#include <isc/os.h>


#ifdef HAVE_SYSCONF

#include <unistd.h>

static inline long
sysconf_ncpus(void) {
#if defined(_SC_NPROCESSORS_ONLN)
	return sysconf((_SC_NPROCESSORS_ONLN));
#elif defined(_SC_NPROC_ONLN)
	return sysconf((_SC_NPROC_ONLN));
#else
	return (0);
#endif
}
#endif /* HAVE_SYSCONF */


#ifdef __hpux

#include <sys/pstat.h>

static inline int
hpux_ncpus(void) {
	struct pst_dynamic psd;
	if (pstat_getdynamic(&psd, sizeof(psd), 1, 0) != -1)
		return (psd.psd_proc_cnt);
	else
		return (0);
}

#endif /* __hpux */


unsigned int
isc_os_ncpus(void) {
	long ncpus = 0;

#ifdef __hpux
	ncpus = hpux_ncpus();
#elif defined(HAVE_SYSCONF)
	ncpus = sysconf_ncpus();
#endif

	if (ncpus <= 0)
		ncpus = 1;

	return ((unsigned int)ncpus);
}
