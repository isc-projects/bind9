
#include <errno.h>
#include <string.h>

#include <isc/condition.h>
#include <isc/unexpect.h>

isc_result_t
isc_condition_waituntil(isc_condition_t *c, isc_mutex_t *m, isc_time_t t)
{
	int presult;
	struct timespec ts;

	ts.tv_sec = t->seconds;
	ts.tv_nsec = t->nanoseconds;
	presult = pthread_cond_timedwait(c, m, &ts);
	if (presult == 0)
		return (ISC_R_SUCCESS);
	if (presult == ETIMEDOUT)
		return (ISC_R_TIMEDOUT);

	UNEXPECTED_ERROR(__FILE__, __LINE__,
			 "pthread_cond_timedwait() returned %s",
			 strerror(presult));
	return (ISC_R_UNEXPECTED);
}
