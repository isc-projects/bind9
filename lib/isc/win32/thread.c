
#include <isc/thread.h>

isc_result_t
isc_thread_create(isc_threadfunc_t start, isc_threadarg_t arg, 
		  isc_thread_t *threadp)
{
	HANDLE h;
	DWORD id;

	h = CreateThread(NULL, 0, start, arg, 0, &id);
	if (h == NULL) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	*threadp = h;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_thread_join(isc_thread_t thread, isc_threadresult_t *rp) {
	DWORD result;

	result = WaitForSingleObject(thread, INFINITE);
	if (result != WAIT_OBJECT_0) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	if (rp != NULL && !GetExitCodeThread(thread, rp)) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t isc_thread_detach(isc_thread_t thread) {

	/* XXX */

	return (ISC_R_SUCCESS);
}
