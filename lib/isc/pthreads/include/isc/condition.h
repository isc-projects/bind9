
#ifndef CONDITION_H
#define CONDITION_H 1

#include <pthread.h>

#include <isc/boolean.h>
#include <isc/mutex.h>
#include <isc/assertions.h>

typedef pthread_cond_t			os_condition_t;
#define OS_CONDITION_INITIALIZER	PTHREAD_COND_INITIALIZER

#define os_condition_init(cp)		(pthread_cond_init((cp), NULL) == 0)
#define os_condition_wait(cp, mp)	(pthread_cond_wait((cp), (mp)) == 0)
#define os_condition_signal(cp)		(pthread_cond_signal((cp)) == 0)
#define os_condition_broadcast(cp)	(pthread_cond_broadcast((cp)) == 0)
#define os_condition_destroy(cp)	(pthread_cond_destroy((cp)) == 0)

boolean_t			os_condition_waituntil(os_condition_t *,
						       os_mutex_t *,
						       struct timespec *,
						       boolean_t *);

#endif /* CONDITION_H */
