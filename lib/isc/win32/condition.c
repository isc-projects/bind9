
#include <isc/condition.h>
#include <isc/assertions.h>

#define SIGNAL		0
#define BROADCAST	1

isc_result_t
isc_condition_init(isc_condition_t *cond) {
	HANDLE h;
	
	REQUIRE(cond != NULL);

	cond->waiters = 0;
	h = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (h == NULL) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	cond->events[SIGNAL] = h;
	h = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (h == NULL) {
		(void)CloseHandle(cond->events[SIGNAL]);
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	cond->events[BROADCAST] = h;

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_signal(isc_condition_t *cond) {
	
	REQUIRE(cond != NULL);

	if (cond->waiters > 0 &&
		!SetEvent(cond->events[SIGNAL])) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_broadcast(isc_condition_t *cond) {
		
	REQUIRE(cond != NULL);

	if (cond->waiters > 0 &&
		!SetEvent(cond->events[BROADCAST])) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_destroy(isc_condition_t *cond) {
		
	REQUIRE(cond != NULL);

	(void)CloseHandle(cond->events[SIGNAL]);
	(void)CloseHandle(cond->events[BROADCAST]);

	return (ISC_R_SUCCESS);
}

static
isc_result_t
wait(isc_condition_t *cond, isc_mutex_t *mutex, DWORD milliseconds) {
	DWORD result;

	cond->waiters++;
	LeaveCriticalSection(mutex);
	result = WaitForMultipleObjects(2, cond->events, FALSE, milliseconds);
	if (result == WAIT_FAILED) {
		/* XXX */
		return (ISC_R_UNEXPECTED);
	}
	EnterCriticalSection(mutex);
	cond->waiters--;
	if (cond->waiters == 0 &&
		!ResetEvent(cond->events[BROADCAST])) {
		/* XXX */
		LeaveCriticalSection(mutex);
		return (ISC_R_UNEXPECTED);
	}

	if (result == WAIT_TIMEOUT)
		return (ISC_R_TIMEDOUT);

	return (ISC_R_SUCCESS);
}

isc_result_t
isc_condition_wait(isc_condition_t *cond, isc_mutex_t *mutex) {
	return (wait(cond, mutex, INFINITE));
}

isc_result_t
isc_condition_waituntil(isc_condition_t *cond, isc_mutex_t *mutex,
			isc_time_t t)
{
	DWORD milliseconds;

	milliseconds = 100; /* XXX */
	return (wait(cond, mutex, milliseconds));
}
