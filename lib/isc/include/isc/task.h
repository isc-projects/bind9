
#ifndef TASK_H
#define TASK_H 1

#include <stddef.h>

#include <isc/list.h>
#include <isc/memcluster.h>

#include <isc/boolean.h>


/***
 *** Core Types.
 ***/

typedef struct task_event *		task_event_t;
typedef struct task *			task_t;
typedef struct task_manager *		task_manager_t;


/***
 *** Events.
 ***/

/*
 * Negative event types are reserved for use by the task manager.
 *
 * Type 0 means "any type".
 */
typedef int				task_eventtype_t;

typedef boolean_t			(*task_action_t)(task_t, task_event_t);

/*
 * This structure is public because "subclassing" it may be useful when
 * defining new event types.
 */ 
struct task_event {
	mem_context_t			mctx;
	size_t				size;
	void *				sender;
	task_eventtype_t		type;
	task_action_t			action;
	void *				arg;
	LINK(struct task_event)		link;
};

#define TASK_EVENT_ANYEVENT		0
#define TASK_EVENT_SHUTDOWN		(-1)

typedef LIST(struct task_event)		task_eventlist_t;

task_event_t				task_event_allocate(mem_context_t,
							    void *,
							    task_eventtype_t,
							    task_action_t,
							    void *arg,
							    size_t);
void					task_event_free(task_event_t *);


/***
 *** Tasks.
 ***/

boolean_t				task_create(task_manager_t,
						    task_action_t,
						    void *,
						    unsigned int,
						    task_t *);
void					task_attach(task_t, task_t *);
void					task_detach(task_t *);
boolean_t				task_send_event(task_t,
							task_event_t *);
void					task_purge_events(task_t, void *,
							  task_eventtype_t);
void					task_shutdown(task_t);
void					task_destroy(task_t *);

/***
 *** Task Manager.
 ***/

unsigned int				task_manager_create(mem_context_t,
							    unsigned int,
							    unsigned int,
							    task_manager_t *);
void					task_manager_destroy(task_manager_t *);

#endif /* TASK_H */
