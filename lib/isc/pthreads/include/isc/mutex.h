
#ifndef ISC_MUTEX_H
#define ISC_MUTEX_H 1

#include <pthread.h>

#include <isc/result.h>

typedef pthread_mutex_t	isc_mutex_t;

/* XXX We could do fancier error handling... */

#define isc_mutex_init(mp) \
	((pthread_mutex_init((mp), NULL) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_lock(mp) \
	((pthread_mutex_lock((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_unlock(mp) \
	((pthread_mutex_unlock((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_destroy(mp) \
	((pthread_mutex_destroy((mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#endif /* ISC_MUTEX_H */
