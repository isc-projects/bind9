/*
 * Copyright (C) 1996, 1997, 1998, 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* $Id: dispatch.c,v 1.2 1999/11/02 04:01:32 tale Exp $ */

/* Principal Author: Ted Lemon */

/*
 * I/O dispatcher.
 */
#include <stddef.h>		/* NULL */
#include <stdlib.h>		/* malloc, free */
#include <string.h>		/* memset */

#include <isc/assertions.h>
#include <isc/int.h>

#include <omapi/omapip_p.h>

typedef struct omapi_io_object {
	OMAPI_OBJECT_PREAMBLE;
	struct omapi_io_object *	next;
	int 				(*readfd) (omapi_object_t *);
	int 				(*writefd)(omapi_object_t *);
	isc_result_t			(*reader) (omapi_object_t *);
	isc_result_t			(*writer) (omapi_object_t *);
	isc_result_t			(*reaper) (omapi_object_t *);
} omapi_io_object_t;

typedef struct omapi_waiter_object {
	OMAPI_OBJECT_PREAMBLE;
	struct omapi_waiter_object *	next;
	int				ready;
} omapi_waiter_object_t;

static omapi_io_object_t omapi_io_states;
isc_uint32_t cur_time;

/*
 * Register an I/O handle so that we can do asynchronous I/O on it.
 */

isc_result_t
omapi_register_io_object(omapi_object_t *h,
			 int (*readfd)(omapi_object_t *),
			 int (*writefd)(omapi_object_t *),
			 isc_result_t (*reader)(omapi_object_t *),
			 isc_result_t (*writer)(omapi_object_t *),
			 isc_result_t (*reaper)(omapi_object_t *))
{
	omapi_io_object_t *obj, *p;

	/*
	 * omapi_io_states is a static object.   If its reference count
	 * is zero, this is the first I/O handle to be registered, so
	 * we need to initialize it.   Because there is no inner or outer
	 * pointer on this object, and we're setting its refcnt to 1, it
	 * will never be freed.
	 */
	if (omapi_io_states.refcnt == 0) {
		omapi_io_states.refcnt = 1;
		omapi_io_states.type = omapi_type_io_object;
	}
		
	obj = (omapi_io_object_t *)malloc(sizeof(*obj));
	if (obj == NULL)
		return (ISC_R_NOMEMORY);
	memset(obj, 0, sizeof(*obj));

	obj->refcnt = 1;
	obj->type = omapi_type_io_object;

	omapi_object_reference(&obj->inner, h, "omapi_register_io_object");
	omapi_object_reference(&h->outer, (omapi_object_t *)obj,
			       "omapi_register_io_object");

	/*
	 * Find the last I/O state, if there are any.
	 */
	for (p = omapi_io_states.next; p != NULL && p->next; p = p->next)
		;
	if (p != NULL)
		p->next = obj;
	else
		omapi_io_states.next = obj;

	obj->readfd = readfd;
	obj->writefd = writefd;
	obj->reader = reader;
	obj->writer = writer;
	obj->reaper = reaper;

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_dispatch(struct timeval *t) {
	return (omapi_wait_for_completion((omapi_object_t *)&omapi_io_states,
					  t));
}

isc_result_t
omapi_wait_for_completion (omapi_object_t *object, struct timeval *t) {
	isc_result_t result;
	omapi_waiter_object_t *waiter;
	omapi_object_t *inner;

	if (object != NULL) {
		waiter = malloc(sizeof(*waiter));
		if (waiter == NULL)
			return (ISC_R_NOMEMORY);
		memset (waiter, 0, sizeof(*waiter));
		waiter->refcnt = 1;
		waiter->type = omapi_type_waiter;

		/*
		 * Paste the waiter object onto the inner object we're
		 * waiting on.
		 */
		for (inner = object; inner->inner != NULL;
		     inner = inner->inner)
			;

		omapi_object_reference(&waiter->outer, inner,
				       "omapi_wait_for_completion");
		omapi_object_reference(&inner->inner, (omapi_object_t *)waiter,
				       "omapi_wait_for_completion");
	} else
		waiter = NULL;

	do {
		result = omapi_one_dispatch((omapi_object_t *)waiter, t);
		if (result != ISC_R_SUCCESS)
			return (result);
	} while (waiter == NULL || waiter->ready == 0);

	if (waiter->outer != NULL) {
		if (waiter->outer->inner != NULL) {
			omapi_object_dereference(&waiter->outer->inner,
						 "omapi_wait_for_completion");
			if (waiter->inner != NULL)
				omapi_object_reference(&waiter->outer->inner,
						  waiter->inner,
						  "omapi_wait_for_completion");
		}
		omapi_object_dereference(&waiter->outer,
					 "omapi_wait_for_completion");
	}
	if (waiter->inner != NULL)
		omapi_object_dereference(&waiter->inner,
					 "omapi_wait_for_completion");
	
	omapi_object_dereference((omapi_object_t **)&waiter,
				 "omapi_wait_for_completion");

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_one_dispatch(omapi_object_t *wo, struct timeval *t) {
	fd_set r, w, x;
	int max = 0;
	int count;
	int desc;
	struct timeval now, to;
	omapi_io_object_t *io, *prev;
	isc_result_t result;
	omapi_waiter_object_t *waiter;

	if (wo == NULL || wo->type != omapi_type_waiter)
		waiter = NULL;
	else
		waiter = (omapi_waiter_object_t *)wo;

	FD_ZERO(&r);
	FD_ZERO(&w);
	FD_ZERO(&x);

	/*
	 * First, see if the timeout has expired, and if so return.
	 */
	if (t != NULL) {
		gettimeofday(&now, NULL);
		cur_time = now.tv_sec;
		if (now.tv_sec > t->tv_sec ||
		    (now.tv_sec == t->tv_sec && now.tv_usec >= t->tv_usec))
			return (ISC_R_TIMEDOUT);
			
		/*
		 * We didn't time out, so figure out how long until we do.
		 */
		to.tv_sec = t->tv_sec - now.tv_sec;
		to.tv_usec = t->tv_usec - now.tv_usec;
		if (to.tv_usec < 0) {
			to.tv_usec += 1000000;
			to.tv_sec--;
		}
	}

	/*
	 * If the object we're waiting on has reached completion,
	 * return now.
	 */
	if (waiter != NULL && waiter->ready != 0)
		return (ISC_R_SUCCESS);

	/*
	 * If we have no I/O state, we can't proceed.
	 */
	io = omapi_io_states.next;
	if (io == NULL)
		return (ISC_R_NOMORE);

	/*
	 * Set up the read and write masks.
	 */
	for (; io != NULL; io = io->next) {
		/*
		 * Check for a read socket.   If we shouldn't be
		 * trying to read for this I/O object, either there
		 * won't be a readfd function, or it'll return -1.
		 */
		if (io->readfd != NULL &&
		    (desc = (*(io->readfd))(io->inner)) >= 0) {
			FD_SET(desc, &r);
			if (desc > max)
				max = desc;
		}
		
		/*
		 * Same deal for write fdsets.
		 */
		if (io->writefd != NULL &&
		    (desc = (*(io->writefd))(io->inner)) >= 0) {
			FD_SET(desc, &w);
			if (desc > max)
				max = desc;
		}
	}

	/*
	 * Wait for a packet or a timeout. XXXTL
	 */
	count = select(max + 1, &r, &w, &x, t ? &to : NULL);

	/*
	 * Get the current time.
	 */
	gettimeofday(&now, NULL);
	cur_time = now.tv_sec;

	/*
	 * Not likely to be transitory.
	 */
	if (count < 0)
		return (ISC_R_UNEXPECTED);

	for (io = omapi_io_states.next; io != NULL; io = io->next) {
		/*
		 * Check for a read descriptor, and if there is one,
		 * see if we got input on that socket.
		 */
		if (io->readfd != NULL &&
		    (desc = (*(io->readfd))(io->inner)) >= 0) {
			if (FD_ISSET(desc, &r))
				result = (*(io->reader))(io->inner);
				/* XXXTL what to do with result? */
		}
		
		/*
		 * Same deal for write descriptors.
		 */
		if (io->writefd != NULL &&
		    (desc = (*(io->writefd))(io->inner)) >= 0) {
			if (FD_ISSET(desc, &w))
				result = (*(io->writer))(io->inner);
				/* XXX what to do with result? */
		}
	}

	/*
	 * Now check for I/O handles that are no longer valid,
	 * and remove them from the list.
	 */
	prev = NULL;
	for (io = omapi_io_states.next; io != NULL; io = io->next) {
		if (io->reaper != NULL) {
			result = (*(io->reaper))(io->inner);
			if (result != ISC_R_SUCCESS) {
				omapi_io_object_t *tmp = NULL;
				/*
				 * Save a reference to the next
				 * pointer, if there is one.
				 */
				if (io->next != NULL)
					omapi_object_reference
						((omapi_object_t **)&tmp,
						 (omapi_object_t *)io->next,
						 "omapi_wfc");
				if (prev != NULL) {
					omapi_object_dereference
					       ((omapi_object_t **)&prev->next,
						"omapi_wfc");
					if (tmp != NULL)
						omapi_object_reference
						    (((omapi_object_t **)
						      &prev->next),
						     (omapi_object_t *)tmp,
						     "omapi_wfc");
				} else {
					omapi_object_dereference
						(((omapi_object_t **)
						  &omapi_io_states.next),
						 "omapi_wfc");
					if (tmp != NULL)
						omapi_object_reference
						    (((omapi_object_t **)
						      &omapi_io_states.next),
						     (omapi_object_t *)tmp,
						     "omapi_wfc");
					else
						omapi_signal_in
							((omapi_object_t *)
							 &omapi_io_states,
							 "ready");
				}
				if (tmp != NULL)
					omapi_object_dereference
						((omapi_object_t **)&tmp,
						 "omapi_wfc");
			}
		}
		prev = io;
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_io_set_value(omapi_object_t *h, omapi_object_t *id,
		   omapi_data_string_t *name, omapi_typed_data_t *value)
{
	REQUIRE(h != NULL && h->type == omapi_type_io_object);
	
	if (h->inner != NULL && h->inner->type->set_value != NULL)
		return (*(h->inner->type->set_value))(h->inner, id,
						      name, value);

	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_io_get_value(omapi_object_t *h, omapi_object_t *id,
		   omapi_data_string_t *name, omapi_value_t **value)
{
	REQUIRE(h != NULL && h->type == omapi_type_io_object);
	
	if (h->inner != NULL && h->inner->type->get_value != NULL)
		return (*(h->inner->type->get_value))(h->inner, id,
						      name, value);

	return (ISC_R_NOTFOUND);
}

void
omapi_io_destroy(omapi_object_t *h, const char *name) {
	REQUIRE(h != NULL && h->type == omapi_type_io_object);

	(void)name;		/* Unused. */
}

isc_result_t
omapi_io_signal_handler(omapi_object_t *h, const char *name, va_list ap) {
	REQUIRE(h != NULL && h->type == omapi_type_io_object);

	if (h->inner != NULL && h->inner->type->signal_handler != NULL)
		return (*(h->inner->type->signal_handler))(h->inner, name, ap);

	return (ISC_R_NOTFOUND);
}

isc_result_t
omapi_io_stuff_values(omapi_object_t *c, omapi_object_t *id, omapi_object_t *h)
{
	REQUIRE(h != NULL && h->type == omapi_type_io_object);

	if (h->inner != NULL && h->inner->type->stuff_values != NULL)
		return (*(h->inner->type->stuff_values))(c, id, h->inner);

	return (ISC_R_SUCCESS);
}

isc_result_t
omapi_waiter_signal_handler(omapi_object_t *h, const char *name, va_list ap) {
	omapi_waiter_object_t *waiter;

	REQUIRE(h != NULL && h->type == omapi_type_waiter);
	
	if (strcmp(name, "ready") == 0) {
		waiter = (omapi_waiter_object_t *)h;
		waiter->ready = 1;
		return (ISC_R_SUCCESS);
	}

	if (h->inner != NULL && h->inner->type->signal_handler != NULL)
		return ((*(h->inner->type->signal_handler))(h->inner, name,
							    ap));
	return (ISC_R_NOTFOUND);
}

