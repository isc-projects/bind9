
#ifndef MUTEX_H
#define MUTEX_H 1

#ifdef MULTITHREADED

#include <pthread.h>
#include <isc/assertions.h>

typedef pthread_mutex_t		os_mutex_t;
#define OS_MUTEX_INITIALIZER	PTHREAD_MUTEX_INITIALIZER

#define os_mutex_init(mp)	INSIST(pthread_mutex_init((mp), NULL) == 0)
#define os_mutex_lock(mp)	INSIST(pthread_mutex_lock((mp)) == 0)
#define os_mutex_unlock(mp)	INSIST(pthread_mutex_unlock((mp)) == 0)
#define os_mutex_destroy(mp)	INSIST(pthread_mutex_destroy((mp)) == 0)

#else

typedef int				os_mutex_t;
#define OS_MUTEX_INITIALIZER		0

#define os_mutex_init(mp)		
#define os_mutex_lock(mp)		
#define os_mutex_unlock(mp)		

#endif

#endif /* MUTEX_H */
