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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include <isc/assertions.h>
#include <isc/file.h>
#include <isc/result.h>

/*
 * XXXDCL As the API for accessing file statistics undoubtedly gets expanded,
 * it might be good to provide a mechanism that allows for the results
 * of a previous stat() to be used again without having to do another stat.
 * Such as perl's mechanism of using "_" in place of a file name to indicate
 * that the results of the last stat should be used.  But then you get into
 * annoying MP issues.   BTW, Win32 has stat().
 */
static isc_result_t
file_stats(const char *file, struct stat *stats) {
	isc_result_t result = ISC_R_SUCCESS;

	if (stat(file, stats) != 0) {
		switch (errno) {
		case ENOTDIR:
		case ENOENT:
			result = ISC_R_NOTFOUND;
			break;
		case ELOOP:
		case EINVAL:
		case ENAMETOOLONG:
			result = ISC_R_INVALIDFILE;
			break;
		case EACCES:
			result = ISC_R_NOPERM;
			break;
		case EIO:
			result = ISC_R_IOERROR;
			break;
		case EFAULT:
		default:
			result = ISC_R_UNEXPECTED;
			break;
		}
	}

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

#undef TEMPLATE
#define TEMPLATE "tmp-XXXXXXXXXX" /* 14 characters. */

isc_result_t
isc_file_mktemplate(const char *path, char *buf, size_t buflen) {
	char *s;

	REQUIRE(buf != NULL);

	s = strrchr(path, '/');

	if (s != NULL) {
		if ((s - path + 1 + sizeof(TEMPLATE)) > buflen)
			return (ISC_R_NOSPACE);

		strncpy(buf, path, s - path + 1);
		buf[s - path + 1] = '\0';
		strcat(buf, TEMPLATE);

	} else {
		if (sizeof(TEMPLATE) > buflen)
			return (ISC_R_NOSPACE);

		strcpy(buf, TEMPLATE);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_file_openunique(char *template, FILE **fp) {
	int fd;
	FILE *f;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(template != NULL);
	REQUIRE(fp != NULL && *fp == NULL);

	/*
	 * Win32 does not have mkstemp.
	 */
	fd = mkstemp(template);

	if (fd == -1)
		switch (errno) {
		case ENOTDIR:
		case ELOOP:
		case EINVAL:
		case ENAMETOOLONG:
			result = ISC_R_INVALIDFILE;
			break;
		case EACCES:
			result = ISC_R_NOPERM;
			break;
		case EEXIST:
			result = ISC_R_EXISTS;
			break;
		case EIO:
			result = ISC_R_IOERROR;
			break;
		default:
			result = ISC_R_UNEXPECTED;
		}

	if (result == ISC_R_SUCCESS) {
		f = fdopen(fd, "w+");
		if (f == NULL) {
			if (errno == ENOMEM)
				result = ISC_R_NOMEMORY;
			else
				result = ISC_R_UNEXPECTED;

			(void)remove(template);
			(void)close(fd);

		} else
			*fp = f;
	}

	return (result);
}
