
#ifndef ISC_TASK_H
#define ISC_TASK_H 1

#include <stddef.h>

#include <isc/list.h>
#include <isc/memcluster.h>

#include <isc/boolean.h>


/***
 *** Core Types.
 ***/

typedef struct isc_event *		isc_event_t;
typedef struct isc_task *		isc_task_t;
typedef struct isc_taskmgr *		isc_taskmgr_t;


/***
 *** Events.
 ***/

/*
 * Negative event types are reserved for use by the task manager.
 *
 * Type 0 means "any type".
 */
typedef int				isc_eventtype_t;

typedef isc_boolean_t (*isc_taskaction_t)(isc_task_t, isc_event_t);

/*
 * This structure is public because "subclassing" it may be useful when
 * defining new event types.
 */ 
struct isc_event {
	isc_memctx_t			mctx;
	size_t				size;
	void *				sender;
	isc_eventtype_t			type;
	isc_taskaction_t		action;
	void *				arg;
	LINK(struct isc_event)		link;
};

#define ISC_TASKEVENT_ANYEVENT		0
#define ISC_TASKEVENT_SHUTDOWN		(-1)

typedef LIST(struct isc_event)		isc_eventlist_t;

isc_event_t				isc_event_allocate(isc_memctx_t,
							   void *,
							   isc_eventtype_t,
							   isc_taskaction_t,
							   void *arg,
							   size_t);
void					isc_event_free(isc_event_t *);


/***
 *** Tasks.
 ***/

isc_boolean_t				isc_task_create(isc_taskmgr_t,
						    isc_taskaction_t,
						    void *,
						    unsigned int,
						    isc_task_t *);
void					isc_task_attach(isc_task_t,
							isc_task_t *);
void					isc_task_detach(isc_task_t *);
isc_boolean_t				isc_task_send(isc_task_t,
							isc_event_t *);
void					isc_task_purge(isc_task_t, void *,
						   isc_eventtype_t);
void					isc_task_shutdown(isc_task_t);
void					isc_task_destroy(isc_task_t *);

/***
 *** Task Manager.
 ***/

unsigned int				isc_taskmgr_create(isc_memctx_t,
							   unsigned int,
							   unsigned int,
							   isc_taskmgr_t *);
void					isc_taskmgr_destroy(isc_taskmgr_t *);

#endif /* ISC_TASK_H */
