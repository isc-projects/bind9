
#ifndef TASK_H
#define TASK_H 1

#include <stddef.h>

#include <isc/list.h>
#include "memcluster.h"

#include "mutex.h"
#include "condition.h"
#include "boolean.h"


/***
 *** Core Types.
 ***/

typedef struct generic_event *		generic_event_t;
typedef struct task *			task_t;
typedef struct task_manager *		task_manager_t;


/***
 *** Events.
 ***/

/*
 * Negative event types are reserved for use by the task manager.
 */
typedef int				event_type_t;

typedef boolean_t			(*event_action_t)(task_t, void *,
							  generic_event_t);

/*
 * Unlike other type names, which are prefixed with the module's name,
 * event types have a suffix of "_event_t".  All event types must start
 * with the same fields as the generic event.
 */
struct generic_event {
	mem_context_t			mctx;
	size_t				size;
	event_type_t			type;
	event_action_t			action;
	LINK(struct generic_event)	link;
};

#define	TASK_NOP_EVENT			(-1)
typedef generic_event_t			nop_event_t;

typedef LIST(struct generic_event)	event_list_t;

void *					event_get(mem_context_t,
						  event_type_t,
						  event_action_t,
						  size_t);
void					event_put(void *);

/***
 *** Tasks.
 ***/

typedef enum {
	task_state_idle, task_state_ready, task_state_running,
	task_state_shutdown
} task_state_t;

#define TASK_MAGIC			0x5441534BU	/* TASK. */

struct task {
	/* Not locked. */
	unsigned int			magic;
	struct task_manager *		manager;
	os_mutex_t			lock;
	/* Locked by task lock. */
	task_state_t			state;
	unsigned int			references;
	event_list_t			events;
	unsigned int			quantum;
	boolean_t			shutdown_pending;
	event_action_t			shutdown_action;
	void *				arg;
	/* Locked by task manager lock. */
	LINK(struct task)		link;
	LINK(struct task)		ready_link;
};

boolean_t				task_create(task_manager_t,
						    void *,
						    event_action_t,
						    unsigned int,
						    task_t *);
boolean_t				task_attach(task_t, task_t *);
void					task_detach(task_t *);
boolean_t				task_send_event(task_t,
							generic_event_t);
void					task_shutdown(task_t);
void					task_destroy(task_t *);


/***
 *** Task Manager.
 ***/

#define TASK_MANAGER_MAGIC		0x54534B4DU	/* TSKM. */

struct task_manager {
	/* Not locked. */
	unsigned int			magic;
	mem_context_t			mctx;
	os_mutex_t			lock;
	/* Locked by task manager lock. */
	unsigned int			default_quantum;
	LIST(struct task)		tasks;
	LIST(struct task)		ready_tasks;
	os_condition_t			work_available;
	boolean_t			exiting;
	unsigned int			workers;
	os_condition_t			no_workers;
};

unsigned int				task_manager_create(mem_context_t,
							    unsigned int,
							    unsigned int,
							    task_manager_t *);
boolean_t				task_manager_destroy(task_manager_t *);

#endif /* TASK_H */
