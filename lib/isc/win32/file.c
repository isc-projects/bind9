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

/* $Id: file.c,v 1.15 2001/07/12 05:58:26 mayer Exp $ */

#include <config.h>

#undef rename
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <io.h>
#include <process.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utime.h>

#include <isc/file.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/util.h>
#include <isc/stat.h>

#include "errno2result.h"

/*
 * Emulate UNIX mkstemp, which returns an open FD to the new file
 *
 */
static int
gettemp(char *path, int *doopen) {
	char *start, *trv;
	struct stat sbuf;
	int pid;

	trv = strrchr(path, 'X');
	trv++;
	pid = getpid();
	/* extra X's get set to 0's */
	while (*--trv == 'X') {
		*trv = (pid % 10) + '0';
		pid /= 10;
	}
	/*
	 * check the target directory; if you have six X's and it
	 * doesn't exist this runs for a *very* long time.
	 */
	for (start = trv + 1;; --trv) {
		if (trv <= path)
			break;
		if (*trv == '\\') {
			*trv = '\0';
			if (stat(path, &sbuf))
				return (0);
			if (!S_ISDIR(sbuf.st_mode)) {
				errno = ENOTDIR;
				return (0);
			}
			*trv = '\\';
			break;
		}
	}

	for (;;) {
		if (doopen) {
			if ((*doopen =
			    open(path, O_CREAT|O_EXCL|O_RDWR,
				 _S_IREAD | _S_IWRITE)) >= 0)
				return (1);
			if (errno != EEXIST)
				return (0);
		} else if (stat(path, &sbuf))
			return (errno == ENOENT ? 1 : 0);

		/* tricky little algorithm for backward compatibility */
		for (trv = start;;) {
			if (!*trv)
				return (0);
			if (*trv == 'z')
				*trv++ = 'a';
			else {
				if (isdigit(*trv))
					*trv = 'a';
				else
					++*trv;
				break;
			}
		}
	}
	/*NOTREACHED*/
}

int
mkstemp(char *path) {
	int fd;

	return (gettemp(path, &fd) ? fd : -1);
}

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

	REQUIRE(file != NULL);
	REQUIRE(stats != NULL);

	if (stat(file, stats) != 0)
		result = isc__errno2result(errno);

	return (result);
}

/*
 * isc_file_safemovefile is needed to be defined here to ensure that
 * any file with the new name is renamed to a backup name and then the
 * rename is done. If all goes well then the backup can be deleted,
 * otherwise it gets renamed back.
 */

int
isc_file_safemovefile(const char *oldname, const char *newname) {
	BOOL filestatus;
	char buf[512];
	struct stat sbuf;
	BOOL exists = FALSE;
	int tmpfd;

	/*
	 * Make sure we have something to do
	 */
	if (stat(oldname, &sbuf) != 0) {
		errno = ENOENT;
		return (-1);
	}

	/*
	 * Rename to a backup the new file if it still exists
	 */
	if (stat(newname, &sbuf) == 0) {
		exists = TRUE;
		strcpy(buf, newname);
		strcat(buf, ".XXXXX");
		tmpfd = mkstemp(buf);
		if (tmpfd > 0)
			_close(tmpfd);
		DeleteFile(buf);
		_chmod(newname, _S_IREAD | _S_IWRITE);

		filestatus = MoveFile(newname, buf);
	}
	/* Now rename the file to the new name
	 */
	_chmod(oldname, _S_IREAD | _S_IWRITE);

	filestatus = MoveFile(oldname, newname);
	if (filestatus == 0) {
		/*
		 * Try to rename the backup back to the original name
		 * if the backup got created
		 */
		if (exists == TRUE) {
			filestatus = MoveFile(buf, newname);
			if (filestatus == 0) {
				errno = EACCES;
			}
		}
		return (-1);
	}

	/*
	 * Delete the backup file if it got created
	 */
	if (exists == TRUE)
		filestatus = DeleteFile(buf);
	return (0);
}

isc_result_t
isc_file_getmodtime(const char *file, isc_time_t *time) {
	isc_result_t result;
	struct stat stats;

	REQUIRE(file != NULL);
	REQUIRE(time != NULL);

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
	struct utimbuf timem;

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
	timem.actime = timem.modtime = (long)isc_time_seconds(time);

	/*
	 * Here is the real check for the high bit being set.
	 */
	if ((timem.actime &
	     (1UL << (sizeof(timem.actime) * CHAR_BIT - 1))) != 0)
		return (ISC_R_RANGE);

	if (utime(file, &timem) < 0)
		return (isc__errno2result(errno));

	return (ISC_R_SUCCESS);

}

#undef TEMPLATE
#define TEMPLATE "XXXXXXXXXX.tmp" /* 14 characters. */

isc_result_t
isc_file_mktemplate(const char *path, char *buf, size_t buflen) {
	return (isc_file_template(path, TEMPLATE, buf, buflen));
}

isc_result_t
isc_file_template(const char *path, const char *templet, char *buf,
			size_t buflen) {
	char *s;

	REQUIRE(path != NULL);
	REQUIRE(templet != NULL);
	REQUIRE(buf != NULL);

	s = strrchr(templet, '\\');
	if (s != NULL)
		templet = s + 1;

	s = strrchr(path, '\\');

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

	REQUIRE(file != NULL);
	REQUIRE(templet != NULL);

	fd = mkstemp(templet);
	if (fd == -1)
		result = isc__errno2result(errno);

	if (result == ISC_R_SUCCESS) {
		res = isc_file_safemovefile(file, templet);
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
	 * Win32 does not have mkstemp. Using emulation above.
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

	REQUIRE(filename != NULL);

	r = unlink(filename);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (isc__errno2result(errno));
}

isc_result_t
isc_file_rename(const char *oldname, const char *newname) {
	int r;

	REQUIRE(oldname != NULL);
	REQUIRE(newname != NULL);

	r = isc_file_safemovefile(oldname, newname);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (isc__errno2result(errno));
}

isc_boolean_t
isc_file_exists(const char *pathname) {
	struct stat stats;

	REQUIRE(pathname != NULL);

	return (ISC_TF(file_stats(pathname, &stats) == ISC_R_SUCCESS));
}

isc_boolean_t
isc_file_isabsolute(const char *filename) {
	REQUIRE(filename != NULL);
	/*
	 * Look for c:\path\... style, c:/path/... or \\computer\shar\path...
	 * the UNC style file specs
	 */
	if ((filename[0] == '\\') && (filename[1] == '\\'))
		return (ISC_TRUE);
	if (isalpha(filename[0]) != 0 && filename[1] == ':' && filename[2] == '\\')
		return (ISC_TRUE);
	if (isalpha(filename[0]) != 0 && filename[1] == ':' && filename[2] == '/')
		return (ISC_TRUE);
	return (ISC_FALSE);
}

isc_boolean_t
isc_file_iscurrentdir(const char *filename) {
	REQUIRE(filename != NULL);
	return (ISC_TF(filename[0] == '.' && filename[1] == '\0'));
}

const char *
isc_file_basename(const char *filename) {
	char *s;

	REQUIRE(filename != NULL);

	s = strrchr(filename, '\\');
	if (s == NULL)
		return (filename);
	return (s + 1);
}

isc_result_t
isc_file_progname(const char *filename, char *progname, size_t namelen) {
	const char *s;
	char *p;
	size_t len;

	REQUIRE(filename != NULL);
	REQUIRE(progname != NULL);

	/*
	 * Strip the path from the name
	 */
	s = isc_file_basename(filename);
	if (s == NULL) {
		return (ISC_R_NOSPACE);
	}

	/*
	 * Strip any and all suffixes
	 */
	p = strchr(s, '.');
	if (p == NULL) {
		if (namelen <= strlen(s))
			return (ISC_R_NOSPACE);

		strcpy(progname, s);
		return (ISC_R_SUCCESS);
	}

	/* 
	 * Copy the result to the buffer
	 */
	len = p - s;
	if (len >= namelen)
		return (ISC_R_NOSPACE);

	strncpy(progname, s, len);
	progname[len] = '\0';
	return (ISC_R_SUCCESS);
}
