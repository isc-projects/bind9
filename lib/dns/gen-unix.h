
/*
 * This file is responsible for defining two operations that are not
 * directly portable between Unix-like systems and Windows NT, option
 * parsing and directory scanning.  It is here because it was decided
 * that the "gen" build utility was not to depend on libisc.a, so
 * the functions delcared in isc/commandline.h and isc/dir.h could not 
 * be used.
 *
 * The commandline stuff is really just a wrapper around getopt().
 * The dir stuff was shrunk to fit the needs of gen.c.
 */

#include <dirent.h>
#include <unistd.h>

#include <isc/boolean.h>

#define isc_commandline_parse		getopt
#define isc_commandline_argument 	optarg

typedef struct {
	DIR *handle;
	char *filename;
} isc_dir_t;

static isc_boolean_t
start_directory(const char *path, isc_dir_t *dir) {
	dir->handle = opendir(path);

	if (dir->handle != NULL)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);

}

static isc_boolean_t
next_file(isc_dir_t *dir) {
	struct dirent *dirent;

	dir->filename = NULL;

	if (dir->handle != NULL) {
		dirent = readdir(dir->handle);
		if (dirent != NULL)
			dir->filename = dirent->d_name;
	}

	if (dir->filename != NULL)
		return (ISC_TRUE);
	else
		return (ISC_FALSE);
}

static void
end_directory(isc_dir_t *dir) {
	if (dir->handle != NULL)
		closedir(dir->handle);

	dir->handle = NULL;
}

