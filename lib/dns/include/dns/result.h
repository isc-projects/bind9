/*
 * Copyright (C) 1998, 1999  Internet Software Consortium.
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

#ifndef DNS_RESULT_H
#define DNS_RESULT_H 1

typedef unsigned int dns_result_t;

#define DNS_R_SUCCESS			0
#define DNS_R_NOMEMORY			1
#define DNS_R_NOSPACE			2
#define DNS_R_LABELTOOLONG		3
#define DNS_R_BADESCAPE			4
#define DNS_R_BADBITSTRING		5
#define DNS_R_BITSTRINGTOOLONG		6
#define DNS_R_EMPTYLABEL		7
#define DNS_R_BADDOTTEDQUAD		8
#define DNS_R_UNEXPECTEDEND		9
#define DNS_R_NOTIMPLEMENTED		10
#define DNS_R_UNKNOWN			11
#define DNS_R_BADLABELTYPE		12
#define DNS_R_BADPOINTER		13
#define DNS_R_TOOMANYHOPS		14

#define DNS_R_LASTENTRY			14	/* Last entry on list. */

#define DNS_R_UNEXPECTED		0xFFFFFFFFL

char *					dns_result_totext(dns_result_t);

#endif /* DNS_RESULT_H */
