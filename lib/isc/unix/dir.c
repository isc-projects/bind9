/*
 * Copyright (C) 1999  Internet Software Consortium.
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

/* $Id: dir.c,v 1.1 1999/09/23 17:31:58 tale Exp $ */

/* Principal Authors: DCL */

#include <errno.h>

#include <isc/dir.h>
#include <isc/assertions.h>

#define ISC_DIR_MAGIC		0x4449522aU	/* DIR*. */
#define VALID_DIR(dir)		((dir) != NULL && \
				 (dir)->magic == ISC_DIR_MAGIC)

void
isc_dir_init(isc_dir_t *dir) {
	REQUIRE(dir != NULL);

	dir->entry.name[0] = '\0';
	dir->entry.length = 0;

	dir->handle = NULL;

	dir->magic = ISC_DIR_MAGIC;
}

/*
 * Allocate workspace and open directory stream. If either one fails, 
 * NULL will be returned.
 */
isc_result_t
isc_dir_open(const char *dirname, isc_dir_t *dir) {
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(dirname != NULL);
	REQUIRE(VALID_DIR(dir));

	/*
	 * Open stream.
	 */
	dir->handle = opendir(dirname);

	if (dir->handle == NULL) {
		if (errno == ENOMEM)
			result = ISC_R_NOMEMORY;
		else if (errno == EPERM)
			result = ISC_R_NOPERM;
		else if (errno == ENOENT)
			result = ISC_R_NOTFOUND;

	}

	return (result);
}

/*
 * Return previously retrieved file or get next one.  Unix's dirent has
 * separate open and read functions, but the Win32 and DOS interfaces open
 * the dir stream and reads the first file in one operation.
 */
isc_result_t
isc_dir_read(isc_dir_t *dir) {
	struct dirent *entry;

	REQUIRE(VALID_DIR(dir) && dir->handle != NULL);

	/*
	 * Fetch next file in directory.
	 */
	entry = readdir(dir->handle);

	if (entry == NULL)
		return (ISC_R_NOMORE);

	/*
	 * Make sure that the space for the name is long enough. 
	 */
	INSIST(sizeof(dir->entry.name) > strlen(entry->d_name));

	strcpy(dir->entry.name, entry->d_name);
	dir->entry.length = entry->d_namlen;

	return (ISC_R_SUCCESS);
}

/*
 * Close directory stream.
 */
void
isc_dir_close(isc_dir_t *dir) {
       REQUIRE(VALID_DIR(dir) && dir->handle != NULL);

       closedir(dir->handle);
       dir->handle = NULL;
}

/*
 * Reposition directory stream at start.
 */
isc_result_t
isc_dir_reset(isc_dir_t *dir) {
	REQUIRE(VALID_DIR(dir) && dir->handle != NULL);

	rewinddir(dir->handle);

	return (ISC_R_SUCCESS);
}
