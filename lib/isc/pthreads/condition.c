
#include <isc/condition.h>
#include <errno.h>

boolean_t
os_condition_waituntil(os_condition_t *c, os_mutex_t *m, struct timespec *ts,
		       boolean_t *timeout)
{
	int result;

	result = pthread_cond_timedwait(c, m, ts);
	if (result == 0) {
		*timeout = FALSE;
		return (TRUE);
	} else if (result == ETIMEDOUT) {
		*timeout = TRUE;
		return (TRUE);
	}
	return (FALSE);
}
