/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: mutex.c,v 1.1 2000/12/29 01:29:56 bwelling Exp $ */

#include <config.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include <isc/mutex.h>
#include <isc/util.h>

#if ISC_MUTEX_PROFILE

struct mutexstats {
	const char *file;
	int line;
	isc_uint64_t us;
	isc_uint32_t count;
};

#define TABLESIZE (8 * 1024)
static struct mutexstats stats[TABLESIZE];
static pthread_mutex_t statslock = PTHREAD_MUTEX_INITIALIZER;

#define tvdiff(tv2, tv1) \
	((((tv2).tv_sec - (tv1).tv_sec) * 1000000) + \
	 (tv2).tv_usec - (tv1).tv_usec)


isc_result_t
isc_mutex_lockprofile(isc_mutex_t *mp, const char * file, int line) {
	struct timeval tv1, tv2;
	int ret;
	int realline;
	unsigned int diff;

	UNUSED(file);

	gettimeofday(&tv1, NULL);
	ret = pthread_mutex_lock(mp);
	gettimeofday(&tv2, NULL);
	if (ret != 0)
		return (ISC_R_UNEXPECTED);
	diff = tvdiff(tv2, tv1);
	if (diff == 0)
		return (ISC_R_SUCCESS);
	RUNTIME_CHECK(pthread_mutex_lock(&statslock) == 0);
	INSIST(line >= 0 && line < TABLESIZE);
	realline = line;
	while (stats[line].file != NULL && stats[line].file != file) {
		line++;
		INSIST(line < TABLESIZE);
	}
	if (stats[line].file == NULL) {
		stats[line].file = file;
		stats[line].line = realline;
		stats[line].us = 0;
		stats[line].count = 0;
	}
	stats[line].us += diff;
	stats[line].count++;
	RUNTIME_CHECK(pthread_mutex_unlock(&statslock) == 0);

	return (ISC_R_SUCCESS);
}

void
isc_mutex_statsprofile(FILE *fp) {
	int i;
	fprintf(fp, "Mutex stats (in us)\n");
	for (i = 0; i < TABLESIZE; i++) {
		if (stats[i].file == NULL)
			continue;
		fprintf(fp, "%14s %6d: %10lluus %10u %10llu\n",
			stats[i].file, stats[i].line, stats[i].us,
			stats[i].count, stats[i].us / stats[i].count);
	}
}

#endif /* ISC_MUTEX_PROFILE */
