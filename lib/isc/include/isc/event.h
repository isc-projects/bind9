/*
 * Copyright (C) 1998, 1999, 2000  Internet Software Consortium.
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

#ifndef ISC_EVENT_H
#define ISC_EVENT_H 1

#include <stddef.h>

#include <isc/lang.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

/*****
 ***** Events.
 *****/

typedef void (*isc_eventdestructor_t)(isc_event_t *);

/*
 * XXXRTH  These fields may soon be prefixed with something like "ev_"
 *         so that there's no way someone using ISC_EVENT_COMMON could
 *         have a namespace conflict with us.
 *
 *	   On the other hand, if we ever changed the contents of this
 *	   structure, we'd break binary compatibility, so maybe this isn't
 *         really an issue.
 */
#define ISC_EVENT_COMMON(ltype)		\
	size_t				size; \
	unsigned int			attributes; \
	void *				tag; \
	isc_eventtype_t			type; \
	isc_taskaction_t		action; \
	void *				arg; \
	void *				sender; \
	isc_eventdestructor_t		destroy; \
	void *				destroy_arg; \
	ISC_LINK(ltype)			link

/*
 * Attributes matching a mask of 0x000000ff are reserved for the task library's
 * definition.  Attributes of 0xffffff00 may be used by the application
 * or non-ISC libraries.
 */
#define ISC_EVENTATTR_NOPURGE		0x00000001

#define ISC_EVENT_INIT(event, sz, at, ta, ty, ac, ar, sn, df, da) \
do { \
	(event)->size = (sz); \
	(event)->attributes = (at); \
	(event)->tag = (ta); \
	(event)->type = (ty); \
	(event)->action = (ac); \
	(event)->arg = (ar); \
	(event)->sender = (sn); \
	(event)->destroy = (df); \
	(event)->destroy_arg = (da); \
	ISC_LINK_INIT((event), link); \
} while (0)
	
/*
 * This structure is public because "subclassing" it may be useful when
 * defining new event types.
 */ 
struct isc_event {
	ISC_EVENT_COMMON(struct isc_event);
};

#define ISC_EVENTTYPE_FIRSTEVENT	0x00000000
#define ISC_EVENTTYPE_LASTEVENT		0xffffffff

isc_event_t *				isc_event_allocate(isc_mem_t *,
							   void *,
							   isc_eventtype_t,
							   isc_taskaction_t,
							   void *arg,
							   size_t);
void					isc_event_free(isc_event_t **);

ISC_LANG_ENDDECLS

#endif /* ISC_EVENT_H */
