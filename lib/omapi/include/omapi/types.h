/*
 * Copyright (C) 1996-2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: types.h,v 1.7.4.1 2001/01/09 22:53:17 bwelling Exp $ */

#ifndef OMAPI_TYPES_H
#define OMAPI_TYPES_H 1

/*****
 ***** Type definitions.
 *****/

/*
 * These structures are all opaque; they are fully defined in private.h
 * for use only by the internal library.  If there is a need to get
 * at their internal data for some purpose, new APIs can be added for that.
 */
typedef unsigned int			omapi_handle_t;
typedef struct omapi_object		omapi_object_t;
typedef struct omapi_objecttype 	omapi_objecttype_t;
typedef struct omapi_data		omapi_data_t;
typedef struct omapi_string		omapi_string_t;
typedef struct omapi_value		omapi_value_t;

typedef enum {
	omapi_datatype_int,
	omapi_datatype_string,
	omapi_datatype_data,
	omapi_datatype_object
} omapi_datatype_t;

#endif /* OMAPI_TYPES_H */
