
#ifndef CONDITION_H
#define CONDITION_H 1

#ifdef MULTITHREADED

#include <pthread.h>
#include <isc/assertions.h>

typedef pthread_cond_t			os_condition_t;
#define OS_CONDITION_INITIALIZER	PTHREAD_COND_INITIALIZER

#define os_condition_init(cp)		INSIST(pthread_cond_init((cp), NULL) \
					       == 0)
#define os_condition_wait(cp, mp)	INSIST(pthread_cond_wait((cp), (mp)) \
					       == 0)
#define os_condition_signal(cp)		INSIST(pthread_cond_signal((cp)) == 0)
#define os_condition_broadcast(cp)	INSIST(pthread_cond_broadcast((cp)) \
					       == 0)
#define os_condition_destroy(cp)	INSIST(pthread_cond_destroy((cp)) \
					       == 0)

#else

#error Condition variables are not meaningful for a non-threaded program.

#endif

#endif /* CONDITION_H */
