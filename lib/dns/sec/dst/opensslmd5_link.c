#if defined(OPENSSL)

/*
 * Portions Copyright (c) 1995-1998 by Network Associates, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND NETWORK ASSOCIATES
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * NETWORK ASSOCIATES BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */

/*
 * Principal Author: Brian Wellington
 * $Id: opensslmd5_link.c,v 1.3 2000/03/06 20:06:01 bwelling Exp $
 */

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <isc/assertions.h>
#include <isc/buffer.h>
#include <isc/int.h>
#include <isc/region.h>

#include "dst_internal.h"
#include "dst_parse.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/md5.h>

#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final

/*
 * dst_s_md5
 *	Call MD5 functions to digest a block of data.
 *	There are three steps to signing, INIT (initialize structures), 
 *	UPDATE (hash (more) data), FINAL (generate a digest).  This
 *	routine performs one or more of these steps.
 * Parameters
 *	mode		DST_SIGMODE_{INIT_UPDATE_FINAL|ALL}
 *	context		the context to use for this computation
 *	data		data to be signed
 *	digest		buffer to store digest
 *	mctx		memory context for temporary allocations
 * Returns 
 *	ISC_R_SUCCESS	Success
 *	!ISC_R_SUCCESS	Failure
 */
isc_result_t
dst_s_md5(const unsigned int mode, void **context, isc_region_t *data,
	  isc_buffer_t *digest, isc_mem_t *mctx)
{
	isc_region_t r;
	MD5_CTX *ctx = NULL;
	
	if (mode & DST_SIGMODE_INIT) { 
		ctx = (MD5_CTX *) isc_mem_get(mctx, sizeof(MD5_CTX));
		if (ctx == NULL)
			return (ISC_R_NOMEMORY);
	}
	else if (context != NULL) 
		ctx = (MD5_CTX *) *context;
	REQUIRE (ctx != NULL);

	if (mode & DST_SIGMODE_INIT)
		MD5Init(ctx);

	if (mode & DST_SIGMODE_UPDATE)
		MD5Update(ctx, data->base, data->length);

	if (mode & DST_SIGMODE_FINAL) {
		isc_buffer_available(digest, &r);
		if (r.length < MD5_DIGEST_LENGTH)
			return (ISC_R_NOSPACE);

		MD5Final(r.base, ctx);
		isc_buffer_add(digest, MD5_DIGEST_LENGTH);
		isc_mem_put(mctx, ctx, sizeof(MD5_CTX));
	}
	else
		*context = ctx;

	return (ISC_R_SUCCESS);
}

#endif
