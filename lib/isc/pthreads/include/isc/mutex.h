
#ifndef MUTEX_H
#define MUTEX_H 1

#include <pthread.h>

typedef pthread_mutex_t			os_mutex_t;
#define OS_MUTEX_INITIALIZER		PTHREAD_MUTEX_INITIALIZER

#define os_mutex_init(mp)		(pthread_mutex_init((mp), NULL) == 0)
#define os_mutex_lock(mp)		(pthread_mutex_lock((mp)) == 0)
#define os_mutex_unlock(mp)		(pthread_mutex_unlock((mp)) == 0)
#define os_mutex_destroy(mp)		(pthread_mutex_destroy((mp)) == 0)

#endif /* MUTEX_H */
