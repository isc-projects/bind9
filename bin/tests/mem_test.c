
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#ifdef SOLARIS
#include <thread.h>
#endif

#include <isc/assertions.h>
#include <isc/mem.h>

char *ptr1[50000];
char *ptr2[50000];

#define ALLOCSZ		100

#undef	THREADS
#undef	LOCKMUTEX
#undef	FINELOCK
#undef	GLOBALMUTEX
#undef	GLOBALMEMCTX
#undef	USE_MALLOC
#undef	FILL
#define	STATS

pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
mem_context_t	global_ctx = NULL;

static void
work(int n, char **p, mem_context_t m, pthread_mutex_t *mutex) {
     int i;

#if !defined(LOCKMUTEX)
     /* Always "use" mutex, so compilers don't complain. */
     mutex = NULL;
#endif
#if defined(THREADS) && defined(LOCKMUTEX) && !defined(FINELOCK)
	     INSIST(pthread_mutex_lock(mutex) == 0);
#endif
     for (i = 0; i < n; i++) {
#if defined(THREADS) && defined(LOCKMUTEX) && defined(FINELOCK)
	     INSIST(pthread_mutex_lock(mutex) == 0);
#endif
#ifdef USE_MALLOC
	     p[i] = malloc(ALLOCSZ);
#else
	     p[i] = mem_allocate(m, ALLOCSZ);
#endif
#if defined(THREADS) && defined(LOCKMUTEX) && defined(FINELOCK)
	     INSIST(pthread_mutex_unlock(mutex) == 0);
#endif
	     INSIST(p[i] != NULL);
#if defined(FILL)
	     {
		     int j;

		     for (j = 0; j < ALLOCSZ; j++)
			     p[i][j] = j;
	     }
#endif
     }
#if defined(THREADS) && defined(LOCKMUTEX) && !defined(FINELOCK)
	     INSIST(pthread_mutex_unlock(mutex) == 0);
#endif
#if defined(THREADS) && defined(LOCKMUTEX) && !defined(FINELOCK)
	     INSIST(pthread_mutex_lock(mutex) == 0);
#endif
     for (i = 0; i < n; i++) {
#if defined(THREADS) && defined(LOCKMUTEX) && defined(FINELOCK)
	     INSIST(pthread_mutex_lock(mutex) == 0);
#endif
#ifdef USE_MALLOC
	     free(p[i]);
#else
	     mem_free(m, p[i]);
#endif
#if defined(THREADS) && defined(LOCKMUTEX) && defined(FINELOCK)
	     INSIST(pthread_mutex_unlock(mutex) == 0);
#endif
	     p[i] = NULL;
     }
#if defined(THREADS) && defined(LOCKMUTEX) && !defined(FINELOCK)
	     INSIST(pthread_mutex_unlock(mutex) == 0);
#endif
}

static void *
run(void *arg) {
	char **p = arg;
	mem_context_t m;
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t *mutexp;

#ifdef GLOBALMUTEX
	mutexp = &global_mutex;
#else
	mutexp = &mutex;
#endif

#ifdef GLOBALMEMCTX
	m = global_ctx;
#else
	INSIST(mem_context_create(0, 0, &m) == 0);
#endif

	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
	work(50000, p, m, mutexp);
#ifdef STATS
	mem_stats(m, stdout);
#endif
	return (NULL);
}
	
int
main(void) {
#ifdef THREADS
	pthread_t t1, t2;
#endif

#ifdef GLOBALMEMCTX
	INSIST(mem_context_create(0, 0, &global_ctx) == 0);
#endif
#ifdef SOLARIS
	thr_setconcurrency(2);		/* Ick. */
#endif
#ifdef THREADS
	INSIST(pthread_create(&t1, NULL, run, ptr1) == 0);
	INSIST(pthread_create(&t2, NULL, run, ptr2) == 0);
	(void)pthread_join(t1, NULL);
	(void)pthread_join(t2, NULL);
#else
	run(ptr1);
	run(ptr2);
#endif
	return (0);
}
