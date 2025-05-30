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

#pragma once

/*! \file isc/file.h */

#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>

#include <isc/types.h>

isc_result_t
isc_file_settime(const char *file, isc_time_t *time);

isc_result_t
isc_file_mode(const char *file, mode_t *modep);

isc_result_t
isc_file_getmodtime(const char *file, isc_time_t *time);
/*!<
 * \brief Get the time of last modification of a file.
 *
 * Notes:
 *\li	The time that is set is relative to the (OS-specific) epoch, as are
 *	all isc_time_t structures.
 *
 * Requires:
 *\li	file != NULL.
 *\li	time != NULL.
 *
 * Ensures:
 *\li	If the file could not be accessed, 'time' is unchanged.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *		Success.
 *\li	#ISC_R_NOTFOUND
 *		No such file exists.
 *\li	#ISC_R_INVALIDFILE
 *		The path specified was not usable by the operating system.
 *\li	#ISC_R_NOPERM
 *		The file's metainformation could not be retrieved because
 *		permission was denied to some part of the file's path.
 *\li	#ISC_R_IOERROR
 *		Hardware error interacting with the filesystem.
 *\li	#ISC_R_UNEXPECTED
 *		Something totally unexpected happened.
 *
 */

isc_result_t
isc_file_mktemplate(const char *path, char *buf, size_t buflen);
/*!<
 * \brief Generate a template string suitable for use with
 * isc_file_openunique().
 *
 * Notes:
 *\li	This function is intended to make creating temporary files
 *	portable between different operating systems.
 *
 *\li	The path is prepended to an implementation-defined string and
 *	placed into buf.  The string has no path characters in it,
 *	and its maximum length is 14 characters plus a NUL.  Thus
 *	buflen should be at least strlen(path) + 15 characters or
 *	an error will be returned.
 *
 * Requires:
 *\li	buf != NULL.
 *
 * Ensures:
 *\li	If result == #ISC_R_SUCCESS:
 *		buf contains a string suitable for use as the template argument
 *		to isc_file_openunique().
 *
 *\li	If result != #ISC_R_SUCCESS:
 *		buf is unchanged.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS 	Success.
 *\li	#ISC_R_NOSPACE	buflen indicates buf is too small for the catenation
 *				of the path with the internal template string.
 */

isc_result_t
isc_file_openunique(char *templet, FILE **fp);
isc_result_t
isc_file_openuniqueprivate(char *templet, FILE **fp);
isc_result_t
isc_file_openuniquemode(char *templet, int mode, FILE **fp);
/*!<
 * \brief Create and open a file with a unique name based on 'templet'.
 *
 * Notes:
 *\li	'template' is a reserved work in C++.  If you want to complain
 *	about the spelling of 'templet', first look it up in the
 *	Merriam-Webster English dictionary. (http://www.m-w.com/)
 *
 *\li	This function works by using the template to generate file names.
 *	The template must be a writable string, as it is modified in place.
 *	Trailing X characters in the file name (full file name on Unix,
 *	basename on Win32 -- eg, tmp-XXXXXX vs XXXXXX.tmp, respectively)
 *	are replaced with ASCII characters until a non-existent filename
 *	is found.  If the template does not include pathname information,
 *	the files in the working directory of the program are searched.
 *
 *\li	isc_file_mktemplate is a good, portable way to get a template.
 *
 * Requires:
 *\li	'fp' is non-NULL and '*fp' is NULL.
 *
 *\li	'template' is non-NULL, and of a form suitable for use by
 *	the system as described above.
 *
 * Ensures:
 *\li	If result is #ISC_R_SUCCESS:
 *		*fp points to an stream opening in stdio's "w+" mode.
 *
 *\li	If result is not #ISC_R_SUCCESS:
 *		*fp is NULL.
 *
 *		No file is open.  Even if one was created (but unable
 *		to be reopened as a stdio FILE pointer) then it has been
 *		removed.
 *
 *\li	This function does *not* ensure that the template string has not been
 *	modified, even if the operation was unsuccessful.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *		Success.
 *\li	#ISC_R_EXISTS
 *		No file with a unique name could be created based on the
 *		template.
 *\li	#ISC_R_INVALIDFILE
 *		The path specified was not usable by the operating system.
 *\li	#ISC_R_NOPERM
 *		The file could not be created because permission was denied
 *		to some part of the file's path.
 *\li	#ISC_R_IOERROR
 *		Hardware error interacting with the filesystem.
 *\li	#ISC_R_UNEXPECTED
 *		Something totally unexpected happened.
 */

isc_result_t
isc_file_remove(const char *filename);
/*!<
 * \brief Remove the file named by 'filename'.
 */

isc_result_t
isc_file_rename(const char *oldname, const char *newname);
/*!<
 * \brief Rename the file 'oldname' to 'newname'.
 */

bool
isc_file_exists(const char *pathname);
/*!<
 * \brief Return #true if the calling process can tell that the given file
 * exists. Will not return true if the calling process has insufficient
 * privileges to search the entire path.
 */

bool
isc_file_isabsolute(const char *filename);
/*!<
 * \brief Return #true if the given file name is absolute.
 */

isc_result_t
isc_file_isplainfile(const char *name);

isc_result_t
isc_file_isplainfilefd(int fd);
/*!<
 * \brief Check that the file is a plain file
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *		Success. The file is a plain file.
 *\li	#ISC_R_INVALIDFILE
 *		The path specified was not usable by the operating system.
 *\li	#ISC_R_FILENOTFOUND
 *		The file does not exist. This return code comes from
 *		errno=ENOENT when stat returns -1. This code is mentioned
 *		here, because in logconf.c, it is the one rcode that is
 *		permitted in addition to ISC_R_SUCCESS. This is done since
 *		the next call in logconf.c is to isc_stdio_open(), which
 *		will create the file if it can.
 *\li	other ISC_R_* errors translated from errno
 *		These occur when stat returns -1 and an errno.
 */

isc_result_t
isc_file_isdirectory(const char *name);
/*!<
 * \brief Check that 'name' exists and is a directory.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS
 *		Success, file is a directory.
 *\li	#ISC_R_INVALIDFILE
 *		File is not a directory.
 *\li	#ISC_R_FILENOTFOUND
 *		File does not exist.
 *\li	other ISC_R_* errors translated from errno
 *		These occur when stat returns -1 and an errno.
 */

bool
isc_file_iscurrentdir(const char *filename);
/*!<
 * \brief Return #true if the given file name is the current directory (".").
 */

bool
isc_file_ischdiridempotent(const char *filename);
/*%<
 * Return #true if calling chdir(filename) multiple times will give
 * the same result as calling it once.
 */

const char *
isc_file_basename(const char *filename);
/*%<
 * Return the final component of the path in the file name.
 */

void
isc_file_progname(const char *filename, char *buf, size_t buflen);
/*!<
 * \brief Given an operating system specific file name "filename"
 * referring to a program, return the canonical program name.
 *
 * Any directory prefix or executable file name extension (if
 * used on the OS in case) is stripped.  On systems where program
 * names are case insensitive, the name is canonicalized to all
 * lower case.  The name is written to 'buf', an array of 'buflen'
 * chars, and null terminated.
 */

isc_result_t
isc_file_template(const char *path, const char *templet, char *buf,
		  size_t buflen);
/*%<
 * Create an OS specific template using 'path' to define the directory
 * 'templet' to describe the filename and store the result in 'buf'
 * such that path can be renamed to buf atomically.
 */

isc_result_t
isc_file_renameunique(const char *file, char *templet);
/*%<
 * Rename 'file' using 'templet' as a template for the new file name.
 */

isc_result_t
isc_file_absolutepath(const char *filename, char *path, size_t pathlen);
/*%<
 * Given a file name, return the fully qualified path to the file.
 */

/*
 * XXX We should also have a isc_file_writeeopen() function
 * for safely open a file in a publicly writable directory
 * (see write_open() in BIND 8's ns_config.c).
 */

isc_result_t
isc_file_truncate(const char *filename, off_t size);
/*%<
 * Truncate/extend the file specified to 'size' bytes.
 */

isc_result_t
isc_file_safecreate(const char *filename, FILE **fp);
/*%<
 * Open 'filename' for writing, truncating if necessary.  Ensure that
 * if it existed it was a normal file.  If creating the file, ensure
 * that only the owner can read/write it.
 */

isc_result_t
isc_file_splitpath(isc_mem_t *mctx, const char *path, char **dirname,
		   char const **basename);
/*%<
 * Split a path into dirname and basename.  If 'path' contains no slash,
 * then '*dirname' is set to ".".
 *
 * Allocates memory for '*dirname', which can be freed with isc_mem_free().
 *
 * Returns:
 * - ISC_R_SUCCESS on success
 * - ISC_R_INVALIDFILE if 'path' is empty or ends with '/'
 */

isc_result_t
isc_file_getsize(const char *file, off_t *size);
/*%<
 * Return the size of the file (stored in the parameter pointed
 * to by 'size') in bytes.
 *
 * Returns:
 * - ISC_R_SUCCESS on success
 */

isc_result_t
isc_file_getsizefd(int fd, off_t *size);
/*%<
 * Return the size of the file (stored in the parameter pointed
 * to by 'size') in bytes.
 *
 * Returns:
 * - ISC_R_SUCCESS on success
 */

isc_result_t
isc_file_sanitize(const char *dir, const char *base, const char *ext,
		  char *path, size_t length);
/*%<
 * Generate a sanitized filename, such as for MKEYS or NZF files.
 *
 * Historically, MKEYS and NZF files used SHA256 hashes of the view
 * name for the filename; this was to deal with the possibility of
 * forbidden characters such as "/" being in a view name, and to
 * avoid problems with case-insensitive file systems.
 *
 * Given a basename 'base' and an extension 'ext', this function checks
 * for the existence of file using the old-style name format in directory
 * 'dir'. If found, it returns the path to that file.  If there is no
 * file already in place, a new pathname is generated; if the basename
 * contains any excluded characters, then a truncated SHA256 hash is
 * used, otherwise the basename is used.  The path name is copied
 * into 'path', which must point to a buffer of at least 'length'
 * bytes.
 *
 * Requires:
 * - base != NULL
 * - path != NULL
 *
 * Returns:
 * - ISC_R_SUCCESS on success
 * - ISC_R_NOSPACE if the resulting path would be longer than 'length'
 */

bool
isc_file_isdirwritable(const char *path);
/*%<
 *	Return true if the path is a directory and is writable
 */
