
#ifndef ISC_THREAD_H
#define ISC_THREAD_H 1

#include <pthread.h>

#include <isc/result.h>

typedef pthread_t isc_thread_t;
typedef void * isc_threadresult_t;
typedef void * isc_threadarg_t;
typedef isc_threadresult_t (*isc_threadfunc_t)(isc_threadarg_t);

/* XXX We could do fancier error handling... */

#define isc_thread_create(s, a, tp) \
	((pthread_create((tp), NULL, (s), (a)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_thread_join(t, rp) \
	((pthread_join((t), (rp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_thread_self \
	(unsigned long)pthread_self

#endif /* ISC_THREAD_H */
