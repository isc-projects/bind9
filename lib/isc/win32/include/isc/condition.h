
#ifndef ISC_CONDITION_H
#define ISC_CONDITION_H 1

#include <windows.h>

#include <isc/boolean.h>
#include <isc/result.h>
#include <isc/mutex.h>
#include <isc/time.h>

typedef struct isc_condition {
	HANDLE			events[2];	
	unsigned int	waiters;
} isc_condition_t;

isc_result_t isc_condition_init(isc_condition_t *);
isc_result_t isc_condition_wait(isc_condition_t *, isc_mutex_t *);
isc_result_t isc_condition_signal(isc_condition_t *);
isc_result_t isc_condition_broadcast(isc_condition_t *);
isc_result_t isc_condition_destroy(isc_condition_t *);
isc_result_t isc_condition_waituntil(isc_condition_t *, isc_mutex_t *,
				     isc_time_t);

#endif /* ISC_CONDITION_H */
