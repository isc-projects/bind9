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

#include <config.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>            /* Required for mkstemp on NetBSD. */

#include <sys/stat.h>

#include <isc/file.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

/*
 * Convert a POSIX errno value into an isc_result_t.  The
 * list of supported errno values is not complete; new users
 * of this function should add any expected errors that are
 * not already there.
 */
static isc_result_t
posix_result(int posixerrno) {
	switch (posixerrno) {
	case ENOTDIR:
	case ELOOP:
	case EINVAL:
	case ENAMETOOLONG:
	case EBADF:
		return (ISC_R_INVALIDFILE);
	case ENOENT:
		return (ISC_R_FILENOTFOUND);
	case EACCES:
		return (ISC_R_NOPERM);
	case EEXIST:
		return (ISC_R_FILEEXISTS);
	case EIO:
		return (ISC_R_IOERROR);
	case ENOMEM:
		return (ISC_R_NOMEMORY);
	default:
		return (ISC_R_UNEXPECTED);
	}
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
	
	if (stat(file, stats) != 0)
		result = posix_result(errno);
		
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
		result = posix_result(errno);
	if (result == ISC_R_SUCCESS) {
		f = fdopen(fd, "w+");
		if (f == NULL) {
			result = posix_result(errno);
			(void)remove(templet);
			(void)close(fd);

		} else
			*fp = f;
	}

	return (result);
}

isc_result_t
isc_file_fopen(const char *filename, const char *mode, FILE **fp) {
	FILE *f;
	
	f = fopen(filename, mode);
	if (f == NULL)
		return (posix_result(errno));
	*fp = f;
	return (ISC_R_SUCCESS);
}

isc_result_t
isc_file_fclose(FILE *f) {
	int r;

	r = fclose(f);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (posix_result(errno));
}

isc_result_t
isc_file_fseek(FILE *f, long offset, int whence) {
	int r;

	r = fseek(f, offset, whence);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (posix_result(errno));
}

isc_result_t
isc_file_fread(void *ptr, size_t size, size_t nmemb, FILE *f, size_t *nret) {
	isc_result_t result = ISC_R_SUCCESS;
	size_t r;
	
	clearerr(f);
	r = fread(ptr, size, nmemb, f);
	if (r != nmemb) {
		if (feof(f))
			result = ISC_R_EOF;
		else
			result = posix_result(errno);
	}
	if (nret != NULL)
		*nret = r;
	return (result);
}

isc_result_t
isc_file_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f, size_t *nret) {
	isc_result_t result = ISC_R_SUCCESS;
	size_t r;
	
	clearerr(f);
	r = fwrite(ptr, size, nmemb, f);
	if (r != nmemb)
		result = posix_result(errno);
	if (nret != NULL)
		*nret = r;
	return (result);
}

isc_result_t
isc_file_fflush(FILE *f) {
	int r;
	
	r = fflush(f);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (posix_result(errno));
}

isc_result_t
isc_file_ffsync(FILE *f) {
	int r;
	
	r = fsync(fileno(f));
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (posix_result(errno));
}

isc_result_t
isc_file_remove(const char *filename) {
	int r;
	
	r = unlink(filename);
	if (r == 0)
		return (ISC_R_SUCCESS);
	else
		return (posix_result(errno));
}
