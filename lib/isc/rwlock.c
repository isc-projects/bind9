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

#include <config.h>

#include <stdio.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/boolean.h>
#include <isc/rwlock.h>
#include <isc/util.h>

#define RWLOCK_MAGIC			0x52574C6BU	/* RWLk. */
#define VALID_RWLOCK(rwl)		((rwl) != NULL && \
					 (rwl)->magic == RWLOCK_MAGIC)

#ifdef ISC_RWLOCK_TRACE
static void
print_lock(char *operation, isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	fprintf(stderr,
		"%s(%s): %s, %u active, %u granted, %u rwaiting, %u wwaiting\n",
		operation, (type == isc_rwlocktype_read ? "read" : "write"),
	        (rwl->type == isc_rwlocktype_read ? "reading" : "writing"),
	        rwl->active, rwl->granted, rwl->readers_waiting,
		rwl->writers_waiting);
}
#endif

isc_result_t
isc_rwlock_init(isc_rwlock_t *rwl,
		unsigned int read_quota,
		unsigned int write_quota)
{
	isc_result_t result;

	REQUIRE(rwl != NULL);

	/*
	 * In case there's trouble initializing, we zero magic now.  If all
	 * goes well, we'll set it to RWLOCK_MAGIC.
	 */
	rwl->magic = 0;

	rwl->type = isc_rwlocktype_read;
	rwl->active = 0;
	rwl->granted = 0;
	rwl->readers_waiting = 0;
	rwl->writers_waiting = 0;
	if (read_quota == 0)
		read_quota = 4;
	rwl->read_quota = read_quota;
	if (write_quota == 0)
		write_quota = 4;
	rwl->write_quota = write_quota;
	result = isc_mutex_init(&rwl->lock);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_mutex_init() failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	result = isc_condition_init(&rwl->readable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init(readable) failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}
	result = isc_condition_init(&rwl->writeable);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "isc_condition_init(writeable) failed: %s",
				 isc_result_totext(result));
		return (ISC_R_UNEXPECTED);
	}

	rwl->magic = RWLOCK_MAGIC;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	isc_boolean_t skip = ISC_FALSE;
	isc_boolean_t done = ISC_FALSE;

	REQUIRE(VALID_RWLOCK(rwl));

	LOCK(&rwl->lock);

#ifdef ISC_RWLOCK_TRACE
	print_lock("prelock", rwl, type);
#endif

	if (type == isc_rwlocktype_read) {
		if (rwl->readers_waiting != 0)
			skip = ISC_TRUE;
		while (!done) {
			if (!skip &&
			    ((rwl->active == 0 ||
			      (rwl->type == isc_rwlocktype_read &&
			       rwl->granted < rwl->read_quota)))) {
				rwl->type = isc_rwlocktype_read;
				rwl->active++;
				rwl->granted++;
				done = ISC_TRUE;
			} else {
				skip = ISC_FALSE;
				rwl->readers_waiting++;
				WAIT(&rwl->readable, &rwl->lock);
				rwl->readers_waiting--;
			}
		}
	} else {
		if (rwl->writers_waiting != 0)
			skip = ISC_TRUE;
		while (!done) {
			if (!skip && rwl->active == 0) {
				rwl->type = isc_rwlocktype_write;
				rwl->active = 1;
				rwl->granted++;
				done = ISC_TRUE;
			} else {
				skip = ISC_FALSE;
				rwl->writers_waiting++;
				WAIT(&rwl->writeable, &rwl->lock);
				rwl->writers_waiting--;
			}
		}
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock("postlock", rwl, type);
#endif

	UNLOCK(&rwl->lock);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {

	REQUIRE(VALID_RWLOCK(rwl));
	LOCK(&rwl->lock);
	REQUIRE(rwl->type == type);

#ifdef ISC_RWLOCK_TRACE
	print_lock("preunlock", rwl, type);
#endif

	rwl->active--;
	if (rwl->active == 0) {
		if (rwl->type == isc_rwlocktype_read) {
			rwl->granted = 0;
			if (rwl->writers_waiting > 0) {
				rwl->type = isc_rwlocktype_write;
				SIGNAL(&rwl->writeable);
			} else if (rwl->readers_waiting > 0) {
				/* Does this case ever happen? */
				BROADCAST(&rwl->readable);
			}
		} else {
			if (rwl->readers_waiting > 0) {
				if (rwl->writers_waiting > 0 &&
				    rwl->granted < rwl->write_quota) {
					SIGNAL(&rwl->writeable);
				} else {
					rwl->granted = 0;
					rwl->type = isc_rwlocktype_read;
					BROADCAST(&rwl->readable);
				}
			} else if (rwl->writers_waiting > 0) {
				rwl->granted = 0;
				SIGNAL(&rwl->writeable);
			} else {
				rwl->granted = 0;
			}
		}
	} else {
		if (rwl->type == isc_rwlocktype_read &&
		    rwl->writers_waiting == 0) {
			INSIST(rwl->granted > 0);
			rwl->granted--;
			if (rwl->readers_waiting > 0)
				SIGNAL(&rwl->readable);
		}
	}

#ifdef ISC_RWLOCK_TRACE
	print_lock("postunlock", rwl, type);
#endif

	UNLOCK(&rwl->lock);

	return (ISC_R_SUCCESS);
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {

	REQUIRE(VALID_RWLOCK(rwl));
	LOCK(&rwl->lock);
	REQUIRE(rwl->active == 0 &&
		rwl->readers_waiting == 0 &&
		rwl->writers_waiting == 0);
	UNLOCK(&rwl->lock);

	rwl->magic = 0;
	(void)isc_condition_destroy(&rwl->readable);
	(void)isc_condition_destroy(&rwl->writeable);
	(void)isc_mutex_destroy(&rwl->lock);
}
