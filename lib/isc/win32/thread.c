
#include <isc/thread.h>

isc_result_t
isc_thread_create(isc_threadfunc_t start, isc_threadarg_t arg, 
		  isc_thread_t *threadp)
{
	isc_thread_t thread;
	unsigned int id;

	thread = (isc_thread_t)_beginthreadex(NULL, 0, start, arg, 0, &id);
	if (thread == NULL) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	*threadp = thread;

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
	(void)CloseHandle(thread);

	return (ISC_R_SUCCESS);
}
