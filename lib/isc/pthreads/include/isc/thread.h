
#ifndef THREAD_H
#define THREAD_H 1

#include <pthread.h>

#include <isc/assertions.h>

typedef pthread_t			os_thread_t;

#define os_thread_create(s, a, tp)	(pthread_create((tp), NULL, (s), (a)) \
					 == 0)
#define os_thread_detach(t)		(pthread_detach((t)) == 0)

#endif /* THREAD_H */
