#ifndef lint
static char *rcsid = "$Id: api.c,v 1.1.2.1 2002/02/08 12:13:46 marka Exp $";
#endif

/*
 * Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
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

#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/log.h>
#include <mdn/logmacro.h>
#include <mdn/resconf.h>
#include <mdn/api.h>
#include <mdn/debug.h>
#include <mdn/res.h>

static struct actiondesc {
	int bit;
	char *desc;
} actiondesc[] = {
	{ MDN_LOCALCONV, "local-conv" },
	{ MDN_IDNCONV, "idn-conv" },
	{ MDN_NAMEPREP, "nameprep" },
	{ MDN_UNASCHECK, "unassigned-check" },
	{ MDN_LOCALMAP, "local-map" },
	{ MDN_DELIMMAP, "delimiter-map" },
	{ 0, "" },
};

#define ENCODE_MASK \
	(MDN_LOCALCONV|MDN_IDNCONV|MDN_NAMEPREP|MDN_UNASCHECK|\
	 MDN_DELIMMAP|MDN_LOCALMAP)
#define DECODE_MASK (MDN_LOCALCONV|MDN_NAMEPREP|MDN_UNASCHECK|MDN_IDNCONV)

static int initialized;
static mdn_resconf_t default_conf;

static char	*actions_to_string(int actions);

mdn_result_t
mdn_nameinit(void) {
	mdn_result_t r;
	static int firsttime = 1;

	TRACE(("mdn_nameinit()\n"));

	initialized = 1;
	if (firsttime) {
		mdn_resconf_initialize();
		firsttime = 0;
	}
	if (default_conf != NULL) {
		mdn_resconf_destroy(default_conf);
		default_conf = NULL;
	}
	if ((r = mdn_resconf_create(&default_conf)) == mdn_success) {
		r = mdn_resconf_loadfile(default_conf, NULL);
	}
	return (r);
}

mdn_result_t
mdn_encodename(int actions, const char *from, char *to, size_t tolen) {
	char buf[20];
	char *p = buf;
	mdn_result_t r;

	assert(from != NULL && to != NULL);

	TRACE(("mdn_encodename(actions=%s, from=\"%s\")\n",
	       actions_to_string(actions),
	       mdn_debug_xstring(from, 256)));

	if (actions & ~ENCODE_MASK) {
		WARNING(("mdn_encodename: invalid actions 0x%x\n", actions));
		return mdn_invalid_action;
	}

	if (!initialized && ((r = mdn_nameinit()) != mdn_success))
		return (r);

	if (actions & MDN_LOCALCONV)
		*p++ = 'l';
	if (actions & MDN_LOCALMAP)
		*p++ = 'd';
	if (actions & MDN_LOCALMAP)
		*p++ = 'M';
	if (actions & MDN_NAMEPREP) {
		p[0] = 'm';
		p[1] = 'n';
		p[2] = 'p';
		p += 3;
	}
	if (actions & MDN_UNASCHECK)
		*p++ = 'u';
	if (actions & MDN_IDNCONV)
		*p++ = 'I';
	*p = '\0';

	return (mdn_res_nameconv(default_conf, buf, from, to, tolen));
}

mdn_result_t
mdn_decodename(int actions, const char *from, char *to, size_t tolen) {
	char buf[20];
	char *p = buf;
	mdn_result_t r;

	assert(from != NULL && to != NULL);

	TRACE(("mdn_decodename(actions=%s, from=\"%s\")\n",
	       actions_to_string(actions),
	       mdn_debug_xstring(from, 256)));

	if (actions & ~DECODE_MASK) {
		WARNING(("mdn_decodename: invalid actions 0x%x\n", actions));
		return mdn_invalid_action;
	}

	if (!initialized && ((r = mdn_nameinit()) != mdn_success))
		return (r);

	if (actions & MDN_IDNCONV)
		*p++ = 'i';
	if (actions & MDN_NAMEPREP) {
		*p++ = '!';
		*p++ = 'N';
	}
	if (actions & MDN_UNASCHECK) {
		*p++ = '!';
		*p++ = 'u';
	}
	if (actions & MDN_LOCALCONV)
		*p++ = 'L';
	*p = '\0';

	return (mdn_res_nameconv(default_conf, buf, from, to, tolen));
}

static char *
actions_to_string(int actions) {
	static char buf[100];
	int i;
	int first = 1;

	buf[0] = '\0';
	for (i = 0; actiondesc[i].bit != 0; i++) {
		if (actions & actiondesc[i].bit) {
			if (!first)
				strcat(buf, "|");
			strcat(buf, actiondesc[i].desc);
			first = 0;
		}
	}
	return (buf);
}
