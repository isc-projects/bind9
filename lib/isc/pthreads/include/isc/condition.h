
#ifndef ISC_CONDITION_H
#define ISC_CONDITION_H 1

#include <pthread.h>

#include <isc/boolean.h>
#include <isc/result.h>
#include <isc/mutex.h>
#include <isc/time.h>

typedef pthread_cond_t isc_condition_t;

#define isc_condition_init(cp) \
	((pthread_cond_init((cp), NULL) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_condition_wait(cp, mp) \
	((pthread_cond_wait((cp), (mp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_condition_signal(cp) \
	((pthread_cond_signal((cp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_condition_broadcast(cp) \
	((pthread_cond_broadcast((cp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_condition_destroy(cp) \
	((pthread_cond_destroy((cp)) == 0) ? \
	 ISC_R_SUCCESS : ISC_R_UNEXPECTED)

isc_result_t isc_condition_waituntil(isc_condition_t *, isc_mutex_t *,
				     isc_time_t);

#endif /* ISC_CONDITION_H */
