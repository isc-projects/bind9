/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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

#include <isc/error.h>

#include "zone.h"

int
main (int argc, char **argv) {
	isc_mem_t *memctx = NULL;
	zonectx_t *zonectx = NULL;
        zoneinfo_t *zone = NULL;

	RUNTIME_CHECK(isc_mem_create(0, 0, &memctx) == ISC_R_SUCCESS);

	RUNTIME_CHECK(new_zonecontext(memctx, &zonectx) == ISC_R_SUCCESS);

        RUNTIME_CHECK(new_zone(zonectx, &zone) == ISC_R_SUCCESS);
}

