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

#ifndef ISC_FILE_H
#define ISC_FILE_H 1

#include <stdio.h>

#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

isc_result_t
isc_file_getmodtime(const char *file, isc_time_t *time);
/*
 * Get the time of last modication of a file.
 *
 * Notes:
 *	The time that is set is relative to the (OS-specific) epoch, as are
 *	all isc_time_t structures.
 *
 * Requires:
 *	file != NULL.
 *	time != NULL.
 *
 * Ensures:
 *	If the file could not be accessed, 'time' is unchanged.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *		Success.
 *	ISC_R_NOTFOUND
 *		No such file exists.
 *	ISC_R_INVALIDFILE
 *		The path specified was not usable by the operating system.
 *	ISC_R_NOPERM
 *		The file's metainformation could not be retrieved because
 *		permission was denied to some part of the file's path.
 *	ISC_R_EIO
 *		Hardware error interacting with the filesystem.
 *	ISC_R_UNEXPECTED
 *		Something totally unexpected happened.
 *	
 */

isc_result_t
isc_file_mktemplate(const char *path, char *buf, size_t buflen);
/*
 * Generate a template string suitable for use with isc_file_openunique.
 *
 * Notes:
 *	This function is intended to make creating temporary files
 *	portable between different operating systems.
 *
 *	The path is prepended to an implementation-defined string and
 *	placed into buf.  The string has no path characters in it,
 *	and its maximum length is 14 characters plus a NUL.  Thus
 *	buflen should be at least strlen(path) + 15 characters or
 *	an error will be returned.
 *
 * Requires:
 *	buf != NULL.
 *
 * Ensures:
 *	If result == ISC_R_SUCCESS:
 *		buf contains a string suitable for use as the template argument
 *		to isc_file_openunique.
 *
 *	If result != ISC_R_SUCCESS:
 *		buf is unchanged.
 *
 * Returns:
 *	ISC_R_SUCCESS 	Success.
 *	ISC_R_NOSPACE	buflen indicates buf is too small for the catenation
 *				of the path with the internal template string.
 */


isc_result_t
isc_file_openunique(char *templet, FILE **fp);
/*
 * Create and open a file with a unique name based on 'templet'.
 * 
 * Notes:
 *	'template' is a reserved work in C++.  If you want to complain
 *	about the spelling of 'templet', first look it up in the
 *	Merriam-Webster English dictionary. (http://www.m-w.com/)
 *
 *	This function works by using the template to generate file names.
 *	The template must be a writable string, as it is modified in place.
 *	Trailing X characters in the file name (full file name on Unix,
 *	basename on Win32 -- eg, tmp-XXXXXX vs XXXXXX.tmp, respectively)
 *	are replaced with ASCII characters until a non-existent filename
 *	is found.  If the template does not include pathname information,
 *	the files in the working directory of the program are searched.
 *
 *	isc_file_mktemplate is a good, portable way to get a template.
 *
 * Requires:
 *	'fp' is non-NULL and '*fp' is NULL.
 *
 *	'template' is non-NULL, and of a form suitable for use by
 *	the system as described above.
 *
 * Ensures:
 *	If result is ISC_R_SUCCESS:
 *		*fp points to an stream opening in stdio's "w+" mode.
 *
 *	If result is not ISC_R_SUCCESS:
 *		*fp is NULL.
 *
 *		No file is open.  Even if one was created (but unable
 *		to be reopened as a stdio FILE pointer) then it has been
 *		removed.
 *
 *	This function does *not* ensure that the template string has not been
 *	modified, even if the operation was unsuccessful.
 *
 * Returns:
 *	ISC_R_SUCCESS
 *		Success.
 *	ISC_R_EXISTS
 *		No file with a unique name could be created based on the
 *		template.
 *	ISC_R_INVALIDFILE
 *		The path specified was not usable by the operating system.
 *	ISC_R_NOPERM
 *		The file could not be created because permission was denied
 *		to some part of the file's path.
 *	ISC_R_EIO
 *		Hardware error interacting with the filesystem.
 *	ISC_R_UNEXPECTED
 *		Something totally unexpected happened.
 */


isc_result_t
isc_file_fopen(const char *filename, const char *mode, FILE **fp);

isc_result_t
isc_file_fclose(FILE *f);

isc_result_t
isc_file_fseek(FILE *f, long offset, int whence);

isc_result_t
isc_file_fread(void *ptr, size_t size, size_t nmemb, FILE *f,
	       size_t *nret);

isc_result_t
isc_file_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f,
		size_t *nret);

isc_result_t
isc_file_fflush(FILE *f);

/*
 * These functions are wrappers around the corresponding
 * stdio functions, returning a detailed error code in the
 * form of an an isc_result_t.  ANSI C does not guarantee
 * that stdio functions set errno, hence these functions 
 * must use platform dependent methods (e.g., the POSIX errno)
 * to construct the error code.
 */

isc_result_t
isc_file_ffsync(FILE *f);
/*
 * Invoke fsync() on the file descriptor underlying
 * an stdio stream, or an equivalent system-dependent
 * operation.  Note that this function has no direct
 * counterpart in the stdio library.
 */

isc_result_t
isc_file_remove(const char *filename);
/*
 * Remove the file named by 'filename'.
 */

/*
 * XXX We should also have a isc_file_writeeopen() function
 * for safely open a file in a publicly writable directory
 * (see write_open() in BIND 8's ns_config.c).
 */


ISC_LANG_ENDDECLS

#endif /* ISC_FILE_H */
