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

/* $Id: mutexblock.c,v 1.8 2000/06/22 21:57:02 tale Exp $ */

#include <config.h>

#include <isc/mutexblock.h>

isc_result_t
isc_mutexblock_init(isc_mutex_t *block, unsigned int count) {
	isc_result_t result;
	unsigned int i;

	for (i = 0 ; i < count ; i++) {
		result = isc_mutex_init(&block[i]);
		if (result != ISC_R_SUCCESS) {
			i--;
			while (i > 0) {
				isc_mutex_destroy(&block[i]);
				i--;
			}
			return (result);
		}
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_mutexblock_destroy(isc_mutex_t *block, unsigned int count) {
	isc_result_t result;
	unsigned int i;

	for (i = 0 ; i < count ; i++) {
		result = isc_mutex_destroy(&block[i]);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	return (ISC_R_SUCCESS);
}
