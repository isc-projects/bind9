/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: condition.h,v 1.1 2000/08/28 23:16:50 bwelling Exp $ */

#ifndef ISC_CONDITION_H
#define ISC_CONDITION_H 1

/*
 * This file is a placeholder.
 */

typedef int isc_condition_t;

#define isc_condition_init(cp) \
	((void)(cp), ISC_R_NOTIMPLEMENTED)

#define isc_condition_wait(cp, mp) \
	((void)(cp), (void)(mp), ISC_R_NOTIMPLEMENTED)

#define isc_condition_waituntil(cp, mp, tp) \
	((void)(cp), (void)(mp), (void)(tp), ISC_R_NOTIMPLEMENTED)

#define isc_condition_signal(cp) \
	((void)(cp), ISC_R_NOTIMPLEMENTED)

#define isc_condition_broadcast(cp) \
	((void)(cp), ISC_R_NOTIMPLEMENTED)

#define isc_condition_destroy(cp) \
	((void)(cp), ISC_R_NOTIMPLEMENTED)

#endif /* ISC_CONDITION_H */
