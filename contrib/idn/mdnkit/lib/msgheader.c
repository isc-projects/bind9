#ifndef lint
static char *rcsid = "$Id: msgheader.c,v 1.1 2002/01/02 02:46:44 marka Exp $";
#endif

/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Kokusai-Kougyou-Kanda Bldg 6F, 2-3-4 Uchi-Kanda,
 * Chiyoda-ku, Tokyo 101-0047, Japan.
 * 
 * 1. Use, Modification and Redistribution (including distribution of any
 *    modified or derived work) in source and/or binary forms is permitted
 *    under this License Terms and Conditions.
 * 
 * 2. Redistribution of source code must retain the copyright notices as they
 *    appear in each source code file, this License Terms and Conditions.
 * 
 * 3. Redistribution in binary form must reproduce the Copyright Notice,
 *    this License Terms and Conditions, in the documentation and/or other
 *    materials provided with the distribution.  For the purposes of binary
 *    distribution the "Copyright Notice" refers to the following language:
 *    "Copyright (c) Japan Network Information Center.  All rights reserved."
 * 
 * 4. Neither the name of JPNIC may be used to endorse or promote products
 *    derived from this Software without specific prior written approval of
 *    JPNIC.
 * 
 * 5. Disclaimer/Limitation of Liability: THIS SOFTWARE IS PROVIDED BY JPNIC
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *    PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL JPNIC BE LIABLE
 *    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *    ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * 6. Indemnification by Licensee
 *    Any person or entities using and/or redistributing this Software under
 *    this License Terms and Conditions shall defend indemnify and hold
 *    harmless JPNIC from and against any and all judgements damages,
 *    expenses, settlement liabilities, cost and other liabilities of any
 *    kind as a result of use and redistribution of this Software or any
 *    claim, suite, action, litigation or proceeding by any third party
 *    arising out of or relates to this License Terms and Conditions.
 * 
 * 7. Governing Law, Jurisdiction and Venue
 *    This License Terms and Conditions shall be governed by and and
 *    construed in accordance with the law of Japan. Any person or entities
 *    using and/or redistributing this Software under this License Terms and
 *    Conditions hereby agrees and consent to the personal and exclusive
 *    jurisdiction and venue of Tokyo District Court of Japan.
 */

#include <config.h>

#include <stddef.h>
#include <stdarg.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/logmacro.h>
#include <mdn/debug.h>
#include <mdn/msgheader.h>

#define DNS_HEADER_SIZE		12

mdn_result_t
mdn_msgheader_parse(const char *msg, size_t msglen, mdn_msgheader_t *parsed) {
	const unsigned char *p = (const unsigned char *)msg;
	unsigned int v;

	assert(msg != NULL && parsed != NULL);

	TRACE(("mdn_msgheader_parse(msg=<%s>, msglen=%d)\n",
	      mdn_debug_hexdata(msg, msglen, 12), msglen));

	if (msglen < DNS_HEADER_SIZE)
		return (mdn_invalid_message);

#define GET16(off)	((p[off]<<8)+p[(off)+1])
	parsed->id = GET16(0);
	v = GET16(2);
	parsed->qr = (v & 0x8000) != 0;
	parsed->opcode = (v >> 11) & 0xf;
	parsed->flags = (v >> 4) & 0x7f;
	parsed->rcode = v & 0xf;
	parsed->qdcount = GET16(4);
	parsed->ancount = GET16(6);
	parsed->nscount = GET16(8);
	parsed->arcount = GET16(10);
#undef GET16

	return (mdn_success);
}

mdn_result_t
mdn_msgheader_unparse(mdn_msgheader_t *parsed, char *msg, size_t msglen) {
	unsigned char *p = (unsigned char *)msg;
	unsigned int v;

	assert(parsed != NULL && msg != NULL);

	TRACE(("mdn_msgheader_unparse()\n"));

	if (msglen < DNS_HEADER_SIZE)
		return (mdn_buffer_overflow);

	v = ((parsed->qr & 1) << 15) +
		((parsed->opcode & 0xf) << 11) +
		((parsed->flags & 0x7f) << 4) +
		(parsed->rcode & 0xf);

#define PUT16(off, v)	p[off] = ((v)>>8) & 0xff; p[(off)+1] = (v) & 0xff
	PUT16(0, parsed->id);
	PUT16(2, v);
	PUT16(4, parsed->qdcount);
	PUT16(6, parsed->ancount);
	PUT16(8, parsed->nscount);
	PUT16(10, parsed->arcount);
#undef PUT16

	return (mdn_success);
}

unsigned int
mdn_msgheader_getid(const char *msg) {
	const unsigned char *p = (const unsigned char *)msg;

	return ((p[0] << 8) + p[1]);
}

void
mdn_msgheader_setid(char *msg, unsigned int id) {
	unsigned char *p = (unsigned char *)msg;

	p[0] = (id >> 8) & 0xff;
	p[1] = id & 0xff;
}
