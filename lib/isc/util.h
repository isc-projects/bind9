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

#ifndef ISC_UTIL_H
#define ISC_UTIL_H 1

#include <isc/error.h>

/***
 *** General Macros.
 ***/

/*
 * We use macros instead of calling the routines directly because
 * the capital letters make the locking stand out.
 *
 * We RUNTIME_CHECK for success since in general there's no way
 * for us to continue if they fail.
 */

#define LOCK(lp) \
	RUNTIME_CHECK(isc_mutex_lock((lp)) == ISC_R_SUCCESS)
#define UNLOCK(lp) \
	RUNTIME_CHECK(isc_mutex_unlock((lp)) == ISC_R_SUCCESS)
#define BROADCAST(cvp) \
	RUNTIME_CHECK(isc_condition_broadcast((cvp)) == ISC_R_SUCCESS)
#define SIGNAL(cvp) \
	RUNTIME_CHECK(isc_condition_signal((cvp)) == ISC_R_SUCCESS)
#define WAIT(cvp, lp) \
	RUNTIME_CHECK(isc_condition_wait((cvp), (lp)) == ISC_R_SUCCESS)

/*
 * isc_condition_waituntil can return ISC_R_TIMEDOUT, so we
 * don't RUNTIME_CHECK the result.
 */

#define WAITUNTIL(cvp, lp, tp) \
	isc_condition_waituntil((cvp), (lp), (tp))

#define RWLOCK(lp, t) \
	RUNTIME_CHECK(isc_rwlock_lock((lp), (t)) == ISC_R_SUCCESS)
#define RWUNLOCK(lp, t) \
	RUNTIME_CHECK(isc_rwlock_unlock((lp), (t)) == ISC_R_SUCCESS)

#endif /* ISC_UTIL_H */
