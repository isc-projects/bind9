/*
 * Copyright (C) 2000  Internet Software Consortium.
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

/* $Id: keyboard.h,v 1.2 2000/06/22 00:25:33 explorer Exp $ */

#ifndef ISC_KEYBOARD_H
#define ISC_KEYBOARD_H 1

#include <termios.h>

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

typedef struct {
	int fd;
	struct termios saved_mode;
} isc_keyboard_t;

isc_result_t
isc_keyboard_open(isc_keyboard_t *keyboard);

isc_result_t
isc_keyboard_close(isc_keyboard_t *keyboard, unsigned int sleepseconds);

isc_result_t
isc_keyboard_getchar(isc_keyboard_t *keyboard, unsigned char *cp);

ISC_LANG_ENDDECLS

#endif /* ISC_KEYBOARD_H */
