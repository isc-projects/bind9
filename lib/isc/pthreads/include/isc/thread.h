
#ifndef THREAD_H
#define THREAD_H 1

#ifdef MULTITHREADED

#include <pthread.h>

#include <isc/assertions.h>

typedef pthread_t			os_thread_t;

#define os_thread_create(s, a, tp)	(pthread_create((tp), NULL, (s), (a)) \
					 == 0)
#define os_thread_detach(t)		INSIST(pthread_detach((t)) == 0)

#else

#error Threads are not meaningful for a non-threaded program.

#endif

#endif /* THREAD_H */
