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

/* $Id: file.c,v 1.35 2001/06/08 21:53:49 tale Exp $ */

#include <config.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>		/* Required for utimes on some platforms. */
#include <unistd.h>		/* Required for mkstemp on NetBSD. */

#include <sys/stat.h>
#include <sys/time.h>

#include <isc/file.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include "errno2result.h"

/*
 * XXXDCL As the API for accessing file statistics undoubtedly gets expanded,
 * it might be good to provide a mechanism that allows for the results
 * of a previous stat() to be used again without having to do another stat,
 * such as perl's mechanism of using "_" in place of a file name to indicate
 * that the results of the last stat should be used.  But then you get into
 * annoying MP issues.   BTW, Win32 has stat().
 */
static isc_result_t
file_stats(const char *file, struct stat *stats) {
	isc_result_t result = ISC_R_SUCCESS;

	if (stat(file, stats) != 0)
		result = isc__errno2result(errno);

	return (result);
}

isc_result_t
isc_file_getmodtime(const char *file, isc_time_t *time) {
	isc_result_t result;
	struct stat stats;

	REQUIRE(file != NULL && time != NULL);

	result = file_stats(file, &stats);

	if (result == ISC_R_SUCCESS)
		/*
		 * XXXDCL some operating systems provide nanoseconds, too,
		 * such as BSD/OS via st_mtimespec.
		 */
		isc_time_set(time, stats.st_mtime, 0);

	return (result);
}

isc_result_t
isc_file_settime(const char *file, isc_time_t *time) {
	struct timeval times[2];

	REQUIRE(file != NULL && time != NULL);

	/*
	 * tv_sec is at least a 32 bit quantity on all platforms we're
	 * dealing with, but it is signed on most (all?) of them,
	 * so we need to make sure the high bit isn't set.  This unfortunately
	 * loses when either:
	 *   * tv_sec becomes a signed 64 bit integer but long is 32 bits
	 *	and isc_time_seconds > LONG_MAX, or
	 *   * isc_time_seconds is changed to be > 32 bits but long is 32 bits
	 *      and isc_time_seconds has at least 33 significant bits.
	 */
	times[0].tv_sec = times[1].tv_sec = (long)isc_time_seconds(time);

	/*
	 * Here is the real check for the high bit being set.
	 */
	if ((times[0].tv_sec &
	     (1ULL << (sizeof(times[0].tv_sec) * CHAR_BIT - 1))) != 0)
		return (ISC_R_RANGE);

	/*
	 * isc_time_nanoseconds guarantees a value that divided by 1000 will
	 * fit into the minimum possible size tv_usec field.  Unfortunately,
	 * we don't know what that type is so can't cast directly ... but
	 * we can at least cast to signed so the IRIX compiler shuts up.
	 */
	times[0].tv_usec = times[1].tv_usec =
		(isc_int32_t)(isc_time_nanoseconds(time) / 1000);

	if (utimes(file, times) < 0)
		return (isc__errno2result(errno));

	return (ISC_R_SUCCESS);

}

#undef TEMPLATE
#define TEMPLATE "tmp-XXXXXXXXXX" /* 14 characters. */

isc_result_t
isc_file_mktemplate(const char *path, char *buf, size_t buflen) {
	return (isc_file_template(path, TEMPLATE, buf, buflen));
}

isc_result_t
isc_file_template(const char *path, const char *templet, char *buf,
			size_t buflen) {
	char *s;

	REQUIRE(buf != NULL);

	s = strrchr(templet, '/');
	if (s != NULL)
		templet = s + 1;

	s = strrchr(path, '/');

	if (s != NULL) {
		if ((s - path + 1 + strlen(templet) + 1) > buflen)
			return (ISC_R_NOSPACE);

		strncpy(buf, path, s - path + 1);
		buf[s - path + 1] = '\0';
		strcat(buf, templet);
	} else {
		if ((strlen(templet) + 1) > buflen)
			return (ISC_R_NOSPACE);

		strcpy(buf, templet);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_file_renameunique(const char *file, char *templet) {
	int fd = -1;
	int res = 0;
	isc_result_t result = ISC_R_SUCCESS;

	fd = mkstemp(templet);
	if (fd == -1) {
		result = isc__errno2result(errno);
	}
	if (result == ISC_R_SUCCESS) {
		res = rename(file, templet);
		if (res != 0) {
			result = isc__errno2result(errno);
			(void)unlink(templet);
		}
	}
	if (fd != -1)
		close(fd);
	return (result);
}

isc_result_t
isc_file_openunique(char *templet, FILE **fp) {
	int fd;
	FILE *f;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(templet != NULL);
	REQUIRE(fp != NULL && *fp == NULL);

	/*
	 * Win32 does not have mkstemp.
	 */
	fd = mkstemp(templet);

	if (fd == -1)
		result = isc__errno2result(errno);
	if (result == ISC_R_SUCCESS) {
		f = fdopen(fd, "w+");
		if (f == NULL) {
			result = isc__errno2result(errno);
			(void)remove(templet);
			(void)close(fd);

		} else
			*fp = f;
	}

	return (result);
}

isc_result_t
isc_file_remove(const char *filename) {
	int r;

	r = unlink(filename);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (isc__errno2result(errno));
}

isc_result_t
isc_file_rename(const char *oldname, const char *newname) {
	int r;

	r = rename(oldname, newname);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (isc__errno2result(errno));
}

isc_boolean_t
isc_file_exists(const char *pathname) {
	struct stat stats;

	return (ISC_TF(file_stats(pathname, &stats) == ISC_R_SUCCESS));
}

isc_boolean_t
isc_file_isabsolute(const char *filename) {
	return (ISC_TF(filename[0] == '/'));
}

isc_boolean_t
isc_file_iscurrentdir(const char *filename) {
	return (ISC_TF(filename[0] == '.' && filename[1] == '\0'));
}

const char *
isc_file_basename(const char *filename) {
	char *s;

	s = strrchr(filename, '/');
	if (s == NULL)
		return (filename);

	return (s + 1);
}

isc_result_t
isc_file_progname(const char *filename, char *buf, size_t buflen) {
	const char *base = isc_file_basename(filename);
	size_t len = strlen(base) + 1;

	if (len > buflen)
		return (ISC_R_NOSPACE);
	memcpy(buf, base, len);

	return (ISC_R_SUCCESS);
}
