/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#ifndef ISC_MUTEX_H
#define ISC_MUTEX_H 1

#include <pthread.h>

#include <isc/result.h>		/* for ISC_R_ codes */

typedef pthread_mutex_t	isc_mutex_t;

/* XXX We could do fancier error handling... */

#define isc_mutex_init(mp) \
	((pthread_mutex_init((mp), NULL) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_lock(mp) \
	((pthread_mutex_lock((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_unlock(mp) \
	((pthread_mutex_unlock((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_trylock(mp) \
	((pthread_mutex_trylock((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_LOCKBUSY)
#define isc_mutex_destroy(mp) \
	((pthread_mutex_destroy((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#endif /* ISC_MUTEX_H */
