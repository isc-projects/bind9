/* dispatch.c

   I/O dispatcher. */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#include <omapip/omapip_p.h>

static omapi_io_object_t omapi_io_states;
u_int32_t cur_time;

/* Register an I/O handle so that we can do asynchronous I/O on it. */

isc_result_t omapi_register_io_object (omapi_object_t *h,
				       int (*readfd) (omapi_object_t *),
				       int (*writefd) (omapi_object_t *),
				       isc_result_t (*reader)
						(omapi_object_t *),
				       isc_result_t (*writer)
						(omapi_object_t *),
				       isc_result_t (*reaper)
						(omapi_object_t *))
{
	isc_result_t status;
	omapi_io_object_t *obj, *p;

	/* omapi_io_states is a static object.   If its reference count
	   is zero, this is the first I/O handle to be registered, so
	   we need to initialize it.   Because there is no inner or outer
	   pointer on this object, and we're setting its refcnt to 1, it
	   will never be freed. */
	if (!omapi_io_states.refcnt) {
		omapi_io_states.refcnt = 1;
		omapi_io_states.type = omapi_type_io_object;
	}
		
	obj = malloc (sizeof *obj);
	if (!obj)
		return ISC_R_NOMEMORY;
	memset (obj, 0, sizeof *obj);

	obj -> refcnt = 1;
	obj -> type = omapi_type_io_object;

	status = omapi_object_reference (&obj -> inner, h,
					 "omapi_register_io_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_register_io_object");
		return status;
	}

	status = omapi_object_reference (&h -> outer, (omapi_object_t *)obj,
					 "omapi_register_io_object");
	if (status != ISC_R_SUCCESS) {
		omapi_object_dereference ((omapi_object_t **)&obj,
					  "omapi_register_io_object");
		return status;
	}

	/* Find the last I/O state, if there are any. */
	for (p = omapi_io_states.next;
	     p && p -> next; p = p -> next)
		;
	if (p)
		p -> next = obj;
	else
		omapi_io_states.next = obj;

	obj -> readfd = readfd;
	obj -> writefd = writefd;
	obj -> reader = reader;
	obj -> writer = writer;
	obj -> reaper = reaper;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_dispatch (struct timeval *t)
{
	return omapi_wait_for_completion ((omapi_object_t *)&omapi_io_states,
					  t);
}

isc_result_t omapi_wait_for_completion (omapi_object_t *object,
					struct timeval *t)
{
	isc_result_t status;
	omapi_waiter_object_t *waiter;
	omapi_object_t *inner;

	if (object) {
		waiter = malloc (sizeof *waiter);
		if (!waiter)
			return ISC_R_NOMEMORY;
		memset (waiter, 0, sizeof *waiter);
		waiter -> refcnt = 1;
		waiter -> type = omapi_type_waiter;

		/* Paste the waiter object onto the inner object we're
		   waiting on. */
		for (inner = object; inner -> inner; inner = inner -> inner)
			;

		status = omapi_object_reference (&waiter -> outer, inner,
						 "omapi_wait_for_completion");
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference ((omapi_object_t **)&waiter,
						  "omapi_wait_for_completion");
			return status;
		}
		
		status = omapi_object_reference (&inner -> inner,
						 (omapi_object_t *)waiter,
						 "omapi_wait_for_completion");
		if (status != ISC_R_SUCCESS) {
			omapi_object_dereference ((omapi_object_t **)&waiter,
						  "omapi_wait_for_completion");
			return status;
		}
	} else
		waiter = (omapi_waiter_object_t *)0;

	do {
		status = omapi_one_dispatch ((omapi_object_t *)waiter, t);
		if (status != ISC_R_SUCCESS)
			return status;
	} while (!waiter || !waiter -> ready);

	if (waiter -> outer) {
		if (waiter -> outer -> inner) {
			omapi_object_dereference (&waiter -> outer -> inner,
						  "omapi_wait_for_completion");
			if (waiter -> inner)
				omapi_object_reference
					(&waiter -> outer -> inner,
					 waiter -> inner,
					 "omapi_wait_for_completion");
		}
		omapi_object_dereference (&waiter -> outer,
					  "omapi_wait_for_completion");
	}
	if (waiter -> inner)
		omapi_object_dereference (&waiter -> inner,
					  "omapi_wait_for_completion");
	
	omapi_object_dereference ((omapi_object_t **)&waiter,
				  "omapi_wait_for_completion");
	return ISC_R_SUCCESS;
}

isc_result_t omapi_one_dispatch (omapi_object_t *wo,
				 struct timeval *t)
{
	fd_set r, w, x;
	int max = 0;
	int count;
	int desc;
	struct timeval now, to;
	omapi_io_object_t *io, *prev;
	isc_result_t status;
	omapi_waiter_object_t *waiter;

	if (!wo || wo -> type != omapi_type_waiter)
		waiter = (omapi_waiter_object_t *)0;
	else
		waiter = (omapi_waiter_object_t *)wo;

	FD_ZERO (&x);

	/* First, see if the timeout has expired, and if so return. */
	if (t) {
		gettimeofday (&now, (struct timezone *)0);
		cur_time = now.tv_sec;
		if (now.tv_sec > t -> tv_sec ||
		    (now.tv_sec == t -> tv_sec && now.tv_usec >= t -> tv_usec))
			return ISC_R_TIMEDOUT;
			
		/* We didn't time out, so figure out how long until
		   we do. */
		to.tv_sec = t -> tv_sec - now.tv_sec;
		to.tv_usec = t -> tv_usec - now.tv_usec;
		if (to.tv_usec < 0) {
			to.tv_usec += 1000000;
			to.tv_sec--;
		}
	}
	
	/* If the object we're waiting on has reached completion,
	   return now. */
	if (waiter && waiter -> ready)
		return ISC_R_SUCCESS;
	
	/* If we have no I/O state, we can't proceed. */
	if (!(io = omapi_io_states.next))
		return ISC_R_NOMORE;

	/* Set up the read and write masks. */
	FD_ZERO (&r);
	FD_ZERO (&w);

	for (; io; io = io -> next) {
		/* Check for a read socket.   If we shouldn't be
		   trying to read for this I/O object, either there
		   won't be a readfd function, or it'll return -1. */
		if (io -> readfd &&
		    (desc = (*(io -> readfd)) (io -> inner)) >= 0) {
			FD_SET (desc, &r);
			if (desc > max)
				max = desc;
		}
		
		/* Same deal for write fdets. */
		if (io -> writefd &&
		    (desc = (*(io -> writefd)) (io -> inner)) >= 0) {
			FD_SET (desc, &w);
			if (desc > max)
				max = desc;
		}
	}

	/* Wait for a packet or a timeout... XXX */
	count = select (max + 1, &r, &w, &x, t ? &to : (struct timeval *)0);

	/* Get the current time... */
	gettimeofday (&now, (struct timezone *)0);
	cur_time = now.tv_sec;

	/* Not likely to be transitory... */
	if (count < 0)
		return ISC_R_UNEXPECTED;

	for (io = omapi_io_states.next; io; io = io -> next) {
		/* Check for a read descriptor, and if there is one,
		   see if we got input on that socket. */
		if (io -> readfd &&
		    (desc = (*(io -> readfd)) (io -> inner)) >= 0) {
			if (FD_ISSET (desc, &r))
				status = ((*(io -> reader)) (io -> inner));
				/* XXX what to do with status? */
		}
		
		/* Same deal for write descriptors. */
		if (io -> writefd &&
		    (desc = (*(io -> writefd)) (io -> inner)) >= 0)
		{
			if (FD_ISSET (desc, &w))
				status = ((*(io -> writer)) (io -> inner));
				/* XXX what to do with status? */
		}
	}

	/* Now check for I/O handles that are no longer valid,
	   and remove them from the list. */
	prev = (omapi_io_object_t *)0;
	for (io = omapi_io_states.next; io; io = io -> next) {
		if (io -> reaper) {
			status = (*(io -> reaper)) (io -> inner);
			if (status != ISC_R_SUCCESS) {
				omapi_io_object_t *tmp =
					(omapi_io_object_t *)0;
				/* Save a reference to the next
				   pointer, if there is one. */
				if (io -> next)
					omapi_object_reference
						((omapi_object_t **)&tmp,
						 (omapi_object_t *)io -> next,
						 "omapi_wfc");
				if (prev) {
					omapi_object_dereference
						(((omapi_object_t **)
						  &prev -> next), "omapi_wfc");
					if (tmp)
						omapi_object_reference
						    (((omapi_object_t **)
						      &prev -> next),
						     (omapi_object_t *)tmp,
						     "omapi_wfc");
				} else {
					omapi_object_dereference
						(((omapi_object_t **)
						  &omapi_io_states.next),
						 "omapi_wfc");
					if (tmp)
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
				if (tmp)
					omapi_object_dereference
						((omapi_object_t **)&tmp,
						 "omapi_wfc");
			}
		}
		prev = io;
	}

	return ISC_R_SUCCESS;
}

isc_result_t omapi_io_set_value (omapi_object_t *h,
				 omapi_object_t *id,
				 omapi_data_string_t *name,
				 omapi_typed_data_t *value)
{
	if (h -> type != omapi_type_io_object)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> set_value)
		return (*(h -> inner -> type -> set_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_io_get_value (omapi_object_t *h,
				 omapi_object_t *id,
				 omapi_data_string_t *name,
				 omapi_value_t **value)
{
	if (h -> type != omapi_type_io_object)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> get_value)
		return (*(h -> inner -> type -> get_value))
			(h -> inner, id, name, value);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_io_destroy (omapi_object_t *h, const char *name)
{
	if (h -> type != omapi_type_io_object)
		return ISC_R_INVALIDARG;
	return ISC_R_SUCCESS;
}

isc_result_t omapi_io_signal_handler (omapi_object_t *h,
				      const char *name, va_list ap)
{
	if (h -> type != omapi_type_io_object)
		return ISC_R_INVALIDARG;
	
	if (h -> inner && h -> inner -> type -> signal_handler)
		return (*(h -> inner -> type -> signal_handler)) (h -> inner,
								  name, ap);
	return ISC_R_NOTFOUND;
}

isc_result_t omapi_io_stuff_values (omapi_object_t *c,
				    omapi_object_t *id,
				    omapi_object_t *i)
{
	if (i -> type != omapi_type_io_object)
		return ISC_R_INVALIDARG;

	if (i -> inner && i -> inner -> type -> stuff_values)
		return (*(i -> inner -> type -> stuff_values)) (c, id,
								i -> inner);
	return ISC_R_SUCCESS;
}

isc_result_t omapi_waiter_signal_handler (omapi_object_t *h,
					  const char *name, va_list ap)
{
	omapi_waiter_object_t *waiter;

	if (h -> type != omapi_type_waiter)
		return ISC_R_INVALIDARG;
	
	if (!strcmp (name, "ready")) {
		waiter = (omapi_waiter_object_t *)h;
		waiter -> ready = 1;
		return ISC_R_SUCCESS;
	}

	if (h -> inner && h -> inner -> type -> signal_handler)
		return (*(h -> inner -> type -> signal_handler)) (h -> inner,
								  name, ap);
	return ISC_R_NOTFOUND;
}

