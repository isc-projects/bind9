/*
 * Copyright
 */

/* $Id: os.h,v 1.2 2001/08/03 23:06:46 gson Exp $ */

#ifndef RNDC_OS_H
#define RNDC_OS_H 1

#include <isc/lang.h>
#include <stdio.h>

/*
 * OS specific paths that may be overriden at runtime by rndc_os_init().
 */


ISC_LANG_BEGINDECLS

FILE *safe_create(const char *filename);
/*
 * Create and open 'filename' for writing.
 * Return NULL if 'filename' already exists.
 */

int set_user(FILE *fd, const char *user);
/*
 * Set the owner of the file refernced by 'fd' to 'user'.
 * Returns:
 *   0 		success
 *   -1 	insufficient permissions, or 'user' does not exist.
 */

ISC_LANG_ENDDECLS

#endif
