/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <isc/errno.h>
#include <isc/glob.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#if HAVE_GLOB_H
#include <glob.h>
#elif defined(_WIN32)
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include <isc/list.h>
#define GLOB_ERR     0x0004 /* Return on error. */
#define GLOB_NOSPACE (-1)
#define GLOB_NOMATCH (-3)

/* custom glob implementation for windows */
static int
glob(const char *pattern, int flags, void *unused, glob_t *pglob);

static void
globfree(glob_t *pglob);

#else
#error "Required header missing: glob.h"
#endif

isc_result_t
isc_glob(const char *pattern, glob_t *pglob) {
	REQUIRE(pattern != NULL);
	REQUIRE(*pattern != '\0');
	REQUIRE(pglob != NULL);

	int rc = glob(pattern, GLOB_ERR, NULL, pglob);

	switch (rc) {
	case 0:
		return (ISC_R_SUCCESS);

	case GLOB_NOMATCH:
		return (ISC_R_FILENOTFOUND);

	case GLOB_NOSPACE:
		return (ISC_R_NOMEMORY);

	default:
		return (errno != 0 ? isc_errno_toresult(errno) : ISC_R_IOERROR);
	}
}

void
isc_globfree(glob_t *pglob) {
	REQUIRE(pglob != NULL);
	globfree(pglob);
}

#if defined(_WIN32)

typedef struct file_path file_path_t;

struct file_path {
	char *path;
	ISC_LINK(file_path_t) link;
};

typedef ISC_LIST(file_path_t) file_list_t;

/* map a winapi error to a convenient errno code */
static int
map_error(DWORD win_err_code) {
	switch (win_err_code) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
		return (GLOB_NOMATCH);
	case ERROR_ACCESS_DENIED:
		return (EACCES);
	case ERROR_NOT_ENOUGH_MEMORY:
		return (GLOB_NOSPACE);
	default:
		return (EIO);
	}
}

/* add file in directory dir, that matches glob expression
 * provided in function glob(), to the linked list fl */
static void
append_file(isc_mem_t *mctx, file_list_t *fl, const char *dir, const char *file,
	    size_t full_path_len) {
	file_path_t *fp = isc_mem_get(mctx, sizeof(file_path_t));
	fp->path = isc_mem_get(mctx, full_path_len + 1);
	_snprintf(fp->path, full_path_len + 1, "%s%s", dir, file);

	ISC_LINK_INIT(fp, link);
	ISC_LIST_PREPEND(*fl, fp, link);
}

/* sort files alphabetically case insensitive on windows */
static int
path_cmp(const void *path1, const void *path2) {
	return _stricmp((const char *)path1, (const char *)path2);
}

static int
glob(const char *pattern, int flags, void *unused, glob_t *pglob) {
	char path[MAX_PATH];
	WIN32_FIND_DATAA find_data;
	int ec;
	HANDLE hnd;

	REQUIRE(pattern != NULL);
	REQUIRE(pglob != NULL);

	UNUSED(flags);
	UNUSED(unused);

	pglob->mctx = NULL;
	pglob->gl_pathc = 0;
	pglob->gl_pathv = NULL;

	hnd = FindFirstFileA(pattern, &find_data);
	if (hnd == INVALID_HANDLE_VALUE) {
		return (map_error(GetLastError()));
	}

	path[MAX_PATH - 1] = 0;
	strncpy(path, pattern, MAX_PATH);
	if (path[MAX_PATH - 1] != 0) {
		errno = ENAMETOOLONG;
		goto fail;
	}

	// strip filename from path.
	size_t dir_len = strlen(path);
	while (dir_len > 0 && path[dir_len - 1] != '/' &&
	       path[dir_len - 1] != '\\') {
		dir_len--;
	}

	path[dir_len] = '\0';

	isc_mem_create(&pglob->mctx);
	pglob->reserved = isc_mem_get(pglob->mctx, sizeof(file_list_t));
	ISC_LIST_INIT(*(file_list_t *)pglob->reserved);

	size_t entries = 0;

	do {
		size_t file_len = strlen(find_data.cFileName);
		size_t full_path_len = dir_len + file_len;

		if (full_path_len > MAX_PATH) {
			errno = ENAMETOOLONG;
			goto fail;
		}

		append_file(pglob->mctx, (file_list_t *)pglob->reserved, path,
			    find_data.cFileName, full_path_len);

		entries++;
	} while (FindNextFileA(hnd, &find_data));

	FindClose(hnd);

	pglob->gl_pathv = isc_mem_get(pglob->mctx,
				      (entries + 1) * sizeof(char *));
	pglob->gl_pathv[entries] = NULL;
	pglob->gl_pathc = entries;

	file_list_t *fl = (file_list_t *)pglob->reserved;

	size_t e = 0;
	file_path_t *fp;
	for (fp = ISC_LIST_HEAD(*fl); fp != NULL; fp = ISC_LIST_NEXT(fp, link))
	{
		pglob->gl_pathv[e++] = fp->path;
	}

	qsort(pglob->gl_pathv, pglob->gl_pathc, sizeof(char *), path_cmp);

	return (0);

fail:
	ec = errno;

	FindClose(hnd);

	if (pglob->mctx) {
		globfree(pglob);
	}

	return ec;
}

void
globfree(glob_t *pglob) {
	REQUIRE(pglob != NULL);
	REQUIRE(pglob->mctx != NULL);

	/* first free memory used by char ** gl_pathv */
	if (pglob->gl_pathv) {
		isc_mem_put(pglob->mctx, pglob->gl_pathv,
			    (pglob->gl_pathc + 1) * sizeof(char *));
		pglob->gl_pathv = NULL;
	}

	file_list_t *fl = (file_list_t *)pglob->reserved;
	file_path_t *p, *next;

	/* next free each individual file path string + nodes in list */
	for (p = ISC_LIST_HEAD(*fl); p != NULL; p = next) {
		next = ISC_LIST_NEXT(p, link);
		isc_mem_put(pglob->mctx, p->path, strlen(p->path) + 1);
		isc_mem_put(pglob->mctx, p, sizeof(file_path_t));
	}

	/* free linked list of files */
	isc_mem_put(pglob->mctx, pglob->reserved, sizeof(file_list_t));
	pglob->reserved = NULL;
	pglob->gl_pathc = 0;
	pglob->gl_pathv = NULL;

	isc_mem_destroy(&pglob->mctx);
	pglob->mctx = NULL;
}

#endif /* defined(_WIN32) */
