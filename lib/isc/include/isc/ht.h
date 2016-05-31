/*
 * Copyright (C) 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* ! \file */

#ifndef ISC_HT_H
#define ISC_HT_H 1

#include <string.h>
#include <isc/types.h>
#include <isc/result.h>

typedef struct isc_ht isc_ht_t;
typedef struct isc_ht_iter isc_ht_iter_t;

/*%
 * Initialize hashtable at *htp, using memory context and size of (1<<bits)
 *
 * Requires:
 *\li	htp is not NULL
 *\li	*htp is NULL
 *\li	mctx is a valid memory context
 *\li	bits >=1 && bits <=32
 *
 * Returns:
 *\li	#ISC_R_NOMEMORY		-- not enough memory to create pool
 *\li	#ISC_R_SUCCESS		-- all is well.
 */
isc_result_t
isc_ht_init(isc_ht_t **htp, isc_mem_t *mctx, isc_uint8_t bits);

/*%
 * Destroy hashtable, freeing everything
 *
 * Requires:
 * \li	*htp is valid hashtable
 */
void
isc_ht_destroy(isc_ht_t **htp);

/*%
 * Add a node to hashtable, pointed by binary key 'key' of size 'keysize';
 * set its value to 'value'
 *
 * Requires:
 *\li	ht is a valid hashtable
 *
 * Returns:
 *\li	#ISC_R_NOMEMORY		-- not enough memory to create pool
 *\li	#ISC_R_EXISTS		-- node of the same key already exists
 *\li	#ISC_R_SUCCESS		-- all is well.
 */
isc_result_t
isc_ht_add(isc_ht_t *ht, const unsigned char *key, isc_uint32_t keysize,
		   void *value);

/*%
 * Find a node matching 'key'/'keysize' in hashtable 'ht';
 * if found, set 'value' to its value
 *
 * Requires:
 * \li	'ht' is a valid hashtable
 *
 * Returns:
 * \li	#ISC_R_SUCCESS		-- success
 * \li	#ISC_R_NOTFOUND		-- key not found
 */
isc_result_t
isc_ht_find(const isc_ht_t *ht, const unsigned char *key,
	    isc_uint32_t keysize, void **valuep);

/*%
 * Delete node from hashtable
 * Requires:
 *\li	ht is a valid hashtable
 *
 * Returns:
 *\li	#ISC_R_NOTFOUND		-- key not found
 *\li	#ISC_R_SUCCESS		-- all is well
 */
isc_result_t
isc_ht_delete(isc_ht_t *ht, const unsigned char *key, isc_uint32_t keysize);

/*%
 * Create an iterator for the hashtable; point '*itp' to it.
 */
isc_result_t
isc_ht_iter_create(isc_ht_t *ht, isc_ht_iter_t **itp);

/*%
 * Destroy the iterator '*itp', set it to NULL
 */
void
isc_ht_iter_destroy(isc_ht_iter_t **itp);

/*%
 * Set an iterator to the first entry.
 *
 * Returns:
 * \li 	#ISC_R_SUCCESS	-- success
 * \li	#ISC_R_NOMORE	-- no data in the hashtable
 */
isc_result_t
isc_ht_iter_first(isc_ht_iter_t *it);

/*%
 * Set an iterator to the next entry.
 *
 * Returns:
 * \li 	#ISC_R_SUCCESS	-- success
 * \li	#ISC_R_NOMORE	-- end of hashtable reached
 */
isc_result_t
isc_ht_iter_next(isc_ht_iter_t *it);

/*%
 * Delete current entry and set an iterator to the next entry.
 *
 * Returns:
 * \li 	#ISC_R_SUCCESS	-- success
 * \li	#ISC_R_NOMORE	-- end of hashtable reached
 */
isc_result_t
isc_ht_iter_delcurrent_next(isc_ht_iter_t *it);


/*%
 * Set 'value' to the current value under the iterator
 */
void
isc_ht_iter_current(isc_ht_iter_t *it, void **valuep);

/*%
 * Set 'key' and 'keysize to the current key and keysize for the value
 * under the iterator
 */
void
isc_ht_iter_currentkey(isc_ht_iter_t *it, unsigned char **key, size_t *keysize);

/*%
 * Returns the number of items in the hashtable.
 *
 * Requires:
 *\li	'ht' is a valid hashtable
 */
unsigned int
isc_ht_count(isc_ht_t *ht);
#endif
