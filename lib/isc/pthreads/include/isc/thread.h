
#ifndef ISC_THREAD_H
#define ISC_THREAD_H 1

#include <pthread.h>

#include <isc/result.h>

typedef pthread_t isc_thread_t;

/* XXX We could do fancier error handling... */

#define isc_thread_create(s, a, tp) \
	((pthread_create((tp), NULL, (s), (a)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_thread_detach(t) \
	((pthread_detach((t)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_thread_join(t) \
	((pthread_join((t), NULL) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_thread_self \
	pthread_self

#endif /* ISC_THREAD_H */
