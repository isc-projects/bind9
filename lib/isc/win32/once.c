/*
 * Copyright (C) 1999  Internet Software Consortium.
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

/* $Id: once.c,v 1.1 1999/09/23 18:14:16 tale Exp $ */

/* Principal Authors: DCL */

#ifdef ISC_ONCE_USE_MUTEX
#include <stdio.h>
#include <process.h>
#endif

#include <windows.h>

#include <isc/once.h>
#include <isc/assertions.h>

#ifdef ISC_ONCE_USE_MUTEX

/*
 * XXXDCL someone (me? bob?) should decide which method to use,
 * the mutex method or the InterlockedDecrement method.
 */

isc_result_t
isc_once_do(isc_once_t *controller, void(*function)(void))

{
	char mutex_name[64];
	HANDLE mutex;

	REQUIRE(controller != NULL && function != NULL);

	if (controller->status == ISC_ONCE_INIT_NEEDED) {	
	
		/*
		 * Create a name that is associated only with this process
		 * and controller.
		 */
		sprintf(mutex_name, "__isc_once_do_%ld:%p",
			getpid(), controller);

		/*
		 * Create the mutex (or attach to the existing mutex)
		 * and lock it. 
		 */
		mutex = CreateMutex(NULL, FALSE, mutex_name);
		if (mutex == NULL)
			return (ISC_R_UNEXPECTED);
		if (WaitForSingleObject(mutex, INFINITE) == WAIT_FAILED)
			return (ISC_R_UNEXPECTED);

		/*
		 * Recheck need for initialization now that
		 * the controller is locked.
		 */
		if (controller->status == ISC_ONCE_INIT_NEEDED) {
			function();
			controller->status = ISC_ONCE_INIT_DONE;
		}

		ReleaseMutex(mutex);
		CloseHandle(mutex);
	}

	return (ISC_R_SUCCESS);
}

#else /* not ISC_ONCE_USE_MUTEX, use InterlockedDecrement instead */

isc_result_t
isc_once_do(isc_once_t *controller, void(*function)(void))

{
	REQUIRE(controller != NULL && function != NULL);

	if (controller->status == ISC_ONCE_INIT_NEEDED) {	
	
		if (InterlockedDecrement(&controller->counter) == 0) {
			if (controller->status == ISC_ONCE_INIT_NEEDED) {
				function();
				controller->status = ISC_ONCE_INIT_DONE;
			}
		} else {
			while (controller->status == ISC_ONCE_INIT_NEEDED) {
				/*
				 * Spin wait.
				 */
			}
		}
	}

	return (ISC_R_SUCCESS);
}

#endif /* ISC_ONCE_USE_MUTEX */
