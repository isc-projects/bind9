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

/* $Id: mutex.c,v 1.2 2001/01/04 22:37:36 neild Exp $ */

#include <config.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include <isc/mutex.h>
#include <isc/util.h>

#if ISC_MUTEX_PROFILE

/* Operations on timespecs */
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#define timespecadd(vvp, uvp)                                           \
        do {                                                            \
                (vvp)->tv_sec += (uvp)->tv_sec;                         \
                (vvp)->tv_nsec += (uvp)->tv_nsec;                       \
                if ((vvp)->tv_nsec >= 1000000) {                     \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_nsec -= 1000000;                   \
                }                                                       \
        } while (0)
#define timespecsub(vvp, uvp)                                           \
        do {                                                            \
                (vvp)->tv_sec -= (uvp)->tv_sec;                         \
                (vvp)->tv_nsec -= (uvp)->tv_nsec;                       \
                if ((vvp)->tv_nsec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_nsec += 1000000;                   \
                }                                                       \
        } while (0)

#define timespec timeval
#define tv_nsec tv_usec
#define clock_gettime(a, b) gettimeofday((b), NULL)


#define ISC_MUTEX_MAX_LOCKERS 32

typedef struct {
	const char *		file;
	int			line;
	unsigned		count;
	struct timespec		locked_total;
	struct timespec		wait_total;
} isc_mutex_locker_t;

struct isc_mutex_stats {
	const char *		file;	/* File mutex was created in. */
	int 			line;	/* Line mutex was created on. */
	unsigned		count;
	struct timespec		lock_t;
	struct timespec		locked_total;
	struct timespec		wait_total;
	isc_mutex_locker_t *	cur_locker;
	isc_mutex_locker_t	lockers[ISC_MUTEX_MAX_LOCKERS];
};

#define TABLESIZE (8 * 1024)
static isc_mutex_stats_t stats[TABLESIZE];
static isc_boolean_t stats_init = ISC_FALSE;
static pthread_mutex_t statslock = PTHREAD_MUTEX_INITIALIZER;


isc_result_t
isc_mutex_init_profile(isc_mutex_t *mp, const char *file, int line) {
	int i;

	if (pthread_mutex_init(&mp->mutex, NULL) != 0)
		return ISC_R_UNEXPECTED;

	RUNTIME_CHECK(pthread_mutex_lock(&statslock) == 0);

	if (stats_init == ISC_FALSE) {
		for (i = 0; i < TABLESIZE; i++) {
			stats[i].file = NULL;
		}
		stats_init = ISC_TRUE;
	}

	mp->stats = NULL;
	for (i = 0; i < TABLESIZE; i++) {
		if (stats[i].file == NULL) {
			mp->stats = &stats[i];
			break;
		}
	}
	RUNTIME_CHECK(mp->stats != NULL);

	RUNTIME_CHECK(pthread_mutex_unlock(&statslock) == 0);

	mp->stats->file = file;
	mp->stats->line = line;
	mp->stats->count = 0;
	timespecclear(&mp->stats->locked_total);
	timespecclear(&mp->stats->wait_total);
	for (i = 0; i < ISC_MUTEX_MAX_LOCKERS; i++) {
		mp->stats->lockers[i].file = NULL;
		mp->stats->lockers[i].line = 0;
		mp->stats->lockers[i].count = 0;
		timespecclear(&mp->stats->lockers[i].locked_total);
		timespecclear(&mp->stats->lockers[i].wait_total);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
isc_mutex_lock_profile(isc_mutex_t *mp, const char *file, int line) {
	struct timespec prelock_t;
	struct timespec postlock_t;
	isc_mutex_locker_t *locker = NULL;
	int i;

	for (i = 0; i < ISC_MUTEX_MAX_LOCKERS; i++) {
		if (mp->stats->lockers[i].file == NULL) {
			locker = &mp->stats->lockers[i];
			locker->file = file;
			locker->line = line;
			break;
		} else if (mp->stats->lockers[i].file == file &&
			   mp->stats->lockers[i].line == line) {
			locker = &mp->stats->lockers[i];
			break;
		}
	}

	clock_gettime(CLOCK_REALTIME, &prelock_t);

	if (pthread_mutex_lock(&mp->mutex) != 0)
		return (ISC_R_UNEXPECTED);

	clock_gettime(CLOCK_REALTIME, &postlock_t);
	mp->stats->lock_t = postlock_t;

	timespecsub(&postlock_t, &prelock_t);

	mp->stats->count++;
	timespecadd(&mp->stats->wait_total, &postlock_t);

	if (locker != NULL) {
		locker->count++;
		timespecadd(&locker->wait_total, &postlock_t);
	}

	mp->stats->cur_locker = locker;

	return ISC_R_SUCCESS;
}

isc_result_t
isc_mutex_unlock_profile(isc_mutex_t *mp, const char *file, int line) {
	struct timespec unlock_t;

	UNUSED(file);
	UNUSED(line);

	if (mp->stats->cur_locker != NULL) {
		clock_gettime(CLOCK_REALTIME, &unlock_t);
		timespecsub(&unlock_t, &mp->stats->lock_t);
		timespecadd(&mp->stats->locked_total, &unlock_t);
		timespecadd(&mp->stats->cur_locker->locked_total, &unlock_t);
		mp->stats->cur_locker = NULL;
	}

	return ((pthread_mutex_unlock((&mp->mutex)) == 0) ? \
		ISC_R_SUCCESS : ISC_R_UNEXPECTED);
}


void
isc_mutex_statsprofile(FILE *fp) {
	isc_mutex_locker_t *locker;
	int i, j;
	fprintf(fp, "Mutex stats (in us)\n");
	for (i = 0; i < TABLESIZE; i++) {
		if (stats[i].file == NULL)
			continue;
		fprintf(fp, "%-12s %4d: %10u  %lu.%06lu %lu.%06lu\n",
			stats[i].file, stats[i].line, stats[i].count,
			stats[i].locked_total.tv_sec,
			stats[i].locked_total.tv_nsec,
			stats[i].wait_total.tv_sec,
			stats[i].wait_total.tv_nsec
			);
		for (j = 0; j < ISC_MUTEX_MAX_LOCKERS; j++) {
			locker = &stats[i].lockers[j];
			if (locker->file == NULL)
				continue;
			fprintf(fp, " %-11s %4d: %10u  %lu.%06lu %lu.%06lu\n",
				locker->file, locker->line, locker->count,
				locker->locked_total.tv_sec,
				locker->locked_total.tv_nsec,
				locker->wait_total.tv_sec,
				locker->wait_total.tv_nsec
				);
		}
	}
}


#if 0
/*** Original profiling code ***/

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
#endif

#endif /* ISC_MUTEX_PROFILE */
