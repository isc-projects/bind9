/*
 * Copyright
 */

/* $Id: os.h,v 1.1 2001/08/03 05:56:22 marka Exp $ */

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
 * Create and open 'filename' for writing.  Fail if 'filename' exist.
 */

int set_user(FILE *fd, const char *user);
/*
 * Set the owner of the file refernced by 'fd' to 'user'.
 * Fail is insufficient permissions or 'user' does not exist.
 */

ISC_LANG_ENDDECLS

#endif
