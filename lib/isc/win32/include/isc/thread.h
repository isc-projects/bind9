
#ifndef ISC_THREAD_H
#define ISC_THREAD_H 1

#include <windows.h>

#include <isc/result.h>

typedef HANDLE isc_thread_t;
typedef DWORD isc_threadresult_t;
typedef LPVOID isc_threadarg_t;
typedef isc_threadresult_t (WINAPI *isc_threadfunc_t)(isc_threadarg_t);

isc_result_t isc_thread_create(isc_threadfunc_t, isc_threadarg_t, 
			       isc_thread_t *);
isc_result_t isc_thread_join(isc_thread_t, isc_threadresult_t *);
isc_result_t isc_thread_detach(isc_thread_t);
#define isc_thread_self \
	(unsigned long)GetCurrentThreadId

#endif /* ISC_THREAD_H */
