
#include <isc/condition.h>
#include <errno.h>

boolean_t
os_condition_waituntil(os_condition_t *c, os_mutex_t *m, os_time_t *t,
		       boolean_t *timeout)
{
	struct timespec ts;

	ts.tv_sec = t->seconds;
	ts.tv_nsec = t->nanoseconds;
	if (pthread_cond_timedwait(c, m, &ts) == 0) {
		*timeout = FALSE;
		return (TRUE);
	} else if (errno == ETIMEDOUT) {
		*timeout = TRUE;
		return (TRUE);
	}
	return (FALSE);
}
