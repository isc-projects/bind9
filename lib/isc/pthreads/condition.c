
#include <isc/condition.h>
#include <errno.h>

isc_boolean_t
os_condition_waituntil(os_condition_t *c, os_mutex_t *m, os_time_t *t,
		       isc_boolean_t *timeout)
{
	int result;
	struct timespec ts;

	ts.tv_sec = t->seconds;
	ts.tv_nsec = t->nanoseconds;
	result = pthread_cond_timedwait(c, m, &ts);
	if (result == 0) {
		*timeout = ISC_FALSE;
		return (ISC_TRUE);
	} else if (result == ETIMEDOUT) {
		*timeout = ISC_TRUE;
		return (ISC_TRUE);
	}
	return (ISC_FALSE);
}
