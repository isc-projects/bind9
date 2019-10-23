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

#ifndef ISC_GLOB_H
#define ISC_GLOB_H

#include <isc/lang.h>
#include <isc/result.h>

#if HAVE_GLOB_H
#include <glob.h>
#else
#include <stddef.h>
#include <isc/mem.h>

typedef struct {
    size_t      gl_pathc;
    char      **gl_pathv;
    isc_mem_t  *mctx;
    void       *reserved;
} glob_t;

#endif

ISC_LANG_BEGINDECLS

isc_result_t
isc_glob(const char *pattern, glob_t *pglob);

void
isc_globfree(glob_t *pglob);

ISC_LANG_ENDDECLS

#endif /* ISC_GLOB_H */
