/*
 * Copyright
 */

/* $Id: os.h,v 1.3 2001/08/06 04:25:07 marka Exp $ */

#ifndef RNDC_OS_H
#define RNDC_OS_H 1

#include <isc/lang.h>
#include <stdio.h>

ISC_LANG_BEGINDECLS

FILE *safe_create(const char *filename);
/*
 * Open 'filename' for writing, truncate if necessary.  If the file was
 * created ensure that only the owner can read/write it.
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
