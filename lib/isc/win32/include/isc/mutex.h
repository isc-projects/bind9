
#ifndef ISC_MUTEX_H
#define ISC_MUTEX_H 1

#include <windows.h>

#include <isc/result.h>

typedef CRITICAL_SECTION isc_mutex_t;

#define isc_mutex_init(mp) \
	(InitializeCriticalSection((mp)), ISC_R_SUCCESS)
#define isc_mutex_lock(mp) \
	(EnterCriticalSection((mp)), ISC_R_SUCCESS)
#define isc_mutex_unlock(mp) \
	(LeaveCriticalSection((mp)), ISC_R_SUCCESS)
#define isc_mutex_destroy(mp) \
	(DeleteCriticalSection((mp)), ISC_R_SUCCESS)

#endif /* ISC_MUTEX_H */
