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

#ifndef ISC_RWLOCK_H
#define ISC_RWLOCK_H 1

#include <isc/lang.h>
#include <isc/types.h>
#include <isc/condition.h>

ISC_LANG_BEGINDECLS

typedef enum {
	isc_rwlocktype_read = 0,
	isc_rwlocktype_write
} isc_rwlocktype_t;

struct isc_rwlock {
	/* Unlocked. */
	unsigned int		magic;
	isc_mutex_t		lock;
	/* Locked by lock. */
	isc_condition_t		readable;
	isc_condition_t		writeable;
	isc_rwlocktype_t	type;
	unsigned int		active;
	unsigned int		granted;
	unsigned int		readers_waiting;
	unsigned int		writers_waiting;
	unsigned int		read_quota;
	unsigned int		write_quota;
};

isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl, unsigned int read_quota,
		unsigned int write_quota);

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

void
isc_rwlock_destroy(isc_rwlock_t *rwl);

ISC_LANG_ENDDECLS

#endif /* ISC_RWLOCK_H */
