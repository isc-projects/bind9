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


#include <config.h>

#include <isc/assertions.h>

#include "configctx.h"


static void freeoptions(isc_cfgoptions_t *opts, isc_mem_t *mem);
static isc_result_t setdirectory(isc_cfgoptions_t *opts, char *directory,
				 isc_mem_t *mem);



/***
 *** PUBLIC
 ***/
isc_result_t
isc_cfg_newctx(isc_mem_t *mem, isc_cfgctx_t **ctx)
{
	isc_cfgctx_t *cfg = NULL;
	isc_cfgoptions_t *opts = NULL;
	isc_zonectx_t *zonectx = NULL;
	isc_result_t res;
	
	INSIST(mem != NULL);

	cfg = isc_mem_get(mem, sizeof *cfg);
	if (cfg == NULL) {
		return (ISC_R_NOMEMORY);
	}

	memset(cfg, 0x0, sizeof *cfg);

	cfg->mem = mem;
	
	opts = isc_mem_get(mem, sizeof *opts);
	if (opts == NULL) {
		isc_mem_put(mem, cfg, sizeof *cfg);
		return (ISC_R_NOMEMORY);
	}
	memset (opts, 0x0, sizeof *opts);
	cfg->options = opts;

	if ((res = isc_zone_newcontext(mem, &zonectx)) != ISC_R_SUCCESS) {
		isc_mem_put(mem, opts, sizeof *opts);
		isc_mem_put(mem, cfg, sizeof *cfg);

		return (res);
	}
	cfg->zonecontext = zonectx;
	
	*ctx = cfg ;

	return (ISC_R_SUCCESS);
}

	


isc_result_t
isc_cfg_freectx(isc_cfgctx_t **ctx)
{
	isc_cfgctx_t *c ;

	INSIST(ctx != NULL);

	c = *ctx;

	INSIST(c->mem != NULL);

	
	if (c->options != NULL) {
		freeoptions(c->options, c->mem);
	}

	isc_mem_put(c->mem, c, sizeof *c);
	*ctx = NULL;
	
	return (ISC_R_SUCCESS);
}


isc_result_t
isc_cfg_setdirectory(isc_cfgctx_t *ctx, char *directory)
{
	INSIST(ctx != NULL);
	INSIST(ctx->mem != NULL);
	INSIST(directory != NULL);
	INSIST(strlen(directory) > 0);
	INSIST(ctx->options != NULL);

	return (setdirectory(ctx->options, directory, ctx->mem));
}

		
	


/***
 *** PRIVATE
 ***/

static isc_result_t
setdirectory(isc_cfgoptions_t *opts, char *directory, isc_mem_t *mem)
{
	if (opts->directory != NULL && opts->dirlen <= strlen(directory)) {
		isc_mem_put(mem, opts->directory, opts->dirlen);
		opts->directory = NULL;
		opts->dirlen = 0;
	}

	if (opts->dirlen == 0) {
		int need = strlen(directory) + 1;

		opts->directory = isc_mem_get(mem, need);
		if (opts->directory == NULL) {
			return (ISC_R_NOMEMORY);
		}
		opts->dirlen = need;
	}

	strcpy(opts->directory, directory);

	return (ISC_R_SUCCESS);
}

	
	

static void
freeoptions(isc_cfgoptions_t *opts, isc_mem_t *mem)
{	
	INSIST(opts != NULL);

	if (opts->directory != NULL) {
		INSIST(opts->dirlen > 0);
	} else {
		INSIST(opts->dirlen == 0);
	}
	
	isc_mem_put(mem, opts->directory, opts->dirlen);
	isc_mem_put(mem, opts, sizeof *opts);
}

	
