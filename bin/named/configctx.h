/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#if !defined(CONFIGCTX_H)
#define CONFIGCTX_H 1

#include <isc/mem.h>

#include "zone.h"

typedef struct isc_cfgoptions 
{
	size_t dirlen;			/* XXX no counted strings? */
	char *directory;
} isc_cfgoptions_t;


typedef struct isc_cfgctx
{
	int warnings;
	int errors;
	
	isc_mem_t *mem;
	isc_cfgoptions_t *options;
	isc_zonectx_t *zonecontext;
	
	/* XXX other config stuff like trusted keys, acls, logging etc. */
} isc_cfgctx_t;


isc_result_t isc_cfg_newctx(isc_mem_t *mem, isc_cfgctx_t **ctx);
isc_result_t isc_cfg_freectx(isc_cfgctx_t **ctx);
isc_result_t isc_cfg_setdirectory(isc_cfgctx_t *ctx, char *directory);


#endif
