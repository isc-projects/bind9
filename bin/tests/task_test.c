
#include "attribute.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <isc/memcluster.h>
#include <isc/task.h>
#include <isc/thread.h>

mem_context_t mctx = NULL;
os_mutex_t timer_lock;
os_condition_t timer_wakeup;

/*ARGSUSED*/
static boolean_t
my_callback(task_t __attribute__((unused)) task,
	    void *arg,
	    task_event_t __attribute__((unused)) event)
{
	int i, j;
	char *name = arg;

	j = 0;
	for (i = 0; i < 100000000; i++)
		j += 100;
	printf("task %s: %d\n", name, j);
	
	return (FALSE);
}

/*ARGSUSED*/
static boolean_t
my_shutdown(task_t __attribute__((unused)) task,
	    void *arg,
	    task_event_t __attribute__((unused)) event)
{
	char *name = arg;

	printf("shutdown %s\n", name);
	return (TRUE);
}

/*ARGSUSED*/
static boolean_t
my_tick(task_t __attribute__((unused)) task,
	void *arg,
	task_event_t __attribute__((unused)) event)
{
	char *name = arg;

	printf("tick %s\n", name);
	return (FALSE);
}

/*ARGSUSED*/
static boolean_t
wakeup_timer(task_t __attribute__((unused)) task,
	     void *arg,
	     task_event_t __attribute__((unused)) event)
{
	printf("wakeup timer\n");
	(void)os_condition_broadcast(&timer_wakeup);
	return (FALSE);
}

void *
simple_timer_run(void *arg) {
	task_t task = arg;
	task_event_t event;
	int i;
	struct timespec ts;
	struct timeval tv;
	struct timeval tv1;
	boolean_t timeout;
	
	for (i = 0; i < 5; i++) {
		(void)gettimeofday(&tv, NULL);
		ts.tv_sec = tv.tv_sec + 5;
		ts.tv_nsec = 0;
		(void)os_mutex_lock(&timer_lock);
		(void)os_condition_waituntil(&timer_wakeup, &timer_lock, &ts,
					     &timeout);
		(void)os_mutex_unlock(&timer_lock);
		(void)gettimeofday(&tv1, NULL);
		printf("slept %d secs\n", tv1.tv_sec - tv.tv_sec);
		if (timeout)
			printf("timer timeout\n");
		printf("sending timer to %p\n", task);
		event = task_event_allocate(mctx, 2, my_tick, NULL, sizeof *event);
		INSIST(event != NULL);
		(void)task_send_event(task, &event);
	}

	task_detach(&task);
	return (NULL);
}

void
simple_timer_init(task_t task) {
	os_thread_t t;
	task_t task_clone;

	task_clone = NULL;
	task_attach(task, &task_clone);
	(void)os_mutex_init(&timer_lock);
	(void)os_condition_init(&timer_wakeup);
	INSIST(os_thread_create(simple_timer_run, task_clone, &t));
	(void)os_thread_detach(t);
}

void
main(int argc, char *argv[]) {
	task_manager_t manager = NULL;
	task_t t1 = NULL, t2 = NULL;
	task_t t3 = NULL, t4 = NULL;
	task_event_t event;
	unsigned int workers;

	if (argc > 1)
		workers = atoi(argv[1]);
	else
		workers = 2;
	printf("%d workers\n", workers);

	INSIST(mem_context_create(0, 0, &mctx) == 0);

	INSIST(task_manager_create(mctx, workers, 0, &manager) == workers);

	INSIST(task_create(manager, "1", my_shutdown, 0, &t1));
	INSIST(task_create(manager, "2", my_shutdown, 0, &t2));
	INSIST(task_create(manager, "3", my_shutdown, 0, &t3));
	INSIST(task_create(manager, "4", my_shutdown, 0, &t4));

	simple_timer_init(t1);
	simple_timer_init(t2);
	printf("task 1 = %p\n", t1);
	printf("task 2 = %p\n", t2);
	sleep(2);

	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, wakeup_timer, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t1, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t2, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t3, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t4, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t2, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t3, &event);
	event = task_event_allocate(mctx, 1, my_callback, NULL, sizeof *event);
	task_send_event(t4, &event);

	task_detach(&t1);
	task_detach(&t2);
	task_detach(&t3);
	task_detach(&t4);

	printf("destroy\n");
	task_manager_destroy(&manager);
	printf("destroyed\n");
	
	mem_stats(mctx, stdout);
}
