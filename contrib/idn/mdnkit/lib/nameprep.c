#ifndef lint
static char *rcsid = "$Id: nameprep.c,v 1.1.2.1 2002/02/08 12:14:10 marka Exp $";
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

#include <stdlib.h>
#include <string.h>

#include <mdn/result.h>
#include <mdn/assert.h>
#include <mdn/log.h>
#include <mdn/logmacro.h>
#include <mdn/utf8.h>
#include <mdn/debug.h>
#include <mdn/nameprep.h>

#define UCS_MAX		0x7fffffff
#define UNICODE_MAX	0x10ffff

/*
 * The latest version.
 */
#define NAMEPREP_CURRENT	"nameprep-05"

/*
 * Load NAMEPREP compiled tables.
 */
#include "nameprepdata.c"

/*
 * Define mapping/checking functions for each version of the draft.
 */

#define VERSION id03
#include "nameprep_template.c"
#undef VERSION

#define VERSION id05
#include "nameprep_template.c"
#undef VERSION

#define VERSION id06
#include "nameprep_template.c"
#undef VERSION

typedef const char	*(*nameprep_mapproc)(unsigned long v);
typedef int		(*nameprep_checkproc)(unsigned long v);

static struct mdn_nameprep {
	char *version;
	nameprep_mapproc map_proc;
	nameprep_checkproc prohibited_proc;
	nameprep_checkproc unassigned_proc;
} nameprep_versions[] = {
#define MAKE_NAMEPREP_HANDLE(version, id) \
	{ version, \
	  compose_sym2(nameprep_map_, id), \
	  compose_sym2(nameprep_prohibited_, id), \
	  compose_sym2(nameprep_unassigned_, id) }
	MAKE_NAMEPREP_HANDLE("nameprep-03", id03),
	MAKE_NAMEPREP_HANDLE("nameprep-05", id05),
	MAKE_NAMEPREP_HANDLE("nameprep-06", id06),
	{ NULL, NULL, NULL },
};

static mdn_result_t	mdn_nameprep_check(nameprep_checkproc proc,
					   const char *str,
					   const char **found);

mdn_result_t
mdn_nameprep_create(const char *version, mdn_nameprep_t *handlep) {
	mdn_nameprep_t handle;

	assert(handlep != NULL);

	TRACE(("mdn_nameprep_create(version=%-.50s)\n",
	       version == NULL ? "<NULL>" : version));

	if (version == NULL)
		version = NAMEPREP_CURRENT;

	/*
	 * Lookup table for the specified version.  Since the number of
	 * versions won't be large (I don't want see draft-23 or such :-),
	 * simple linear search is OK.
	 */
	for (handle = nameprep_versions; handle->version != NULL; handle++) {
		if (strcmp(handle->version, version) == 0) {
			*handlep = handle;
			return (mdn_success);
		}
	}
	return (mdn_notfound);
}

void
mdn_nameprep_destroy(mdn_nameprep_t handle) {
	assert(handle != NULL);

	TRACE(("mdn_nameprep_destroy()\n"));

	/* Nothing to do. */
}

mdn_result_t
mdn_nameprep_map(mdn_nameprep_t handle, const char *from,
		 char *to, size_t tolen) {
	size_t fromlen;

	assert(handle != NULL && from != NULL && to != NULL);

	TRACE(("mdn_nameprep_map(from=\"%s\")\n",
	       mdn_debug_xstring(from, 50)));

	fromlen = strlen(from);
	while (fromlen > 0) {
		unsigned long v;
		int w;
		const char *mapped;

		if ((w = mdn_utf8_getwc(from, fromlen, &v)) == 0)
			return (mdn_invalid_encoding);

		if (v > UCS_MAX) {
			/* This cannot happen, but just in case.. */
			return (mdn_invalid_codepoint);
		} else if (v > UNICODE_MAX) {
			/* No mapping is possible. */
			mapped = NULL;
		} else {
			/* Try mapping. */
			mapped = (*handle->map_proc)(v);
		}

		if (mapped == NULL) {
			/* No mapping. Just copy verbatim. */
			if (tolen < w)
				return (mdn_buffer_overflow);
			(void)memcpy(to, from, w);
			to += w;
			tolen -= w;
		} else {
			size_t mappedlen = strlen(mapped);

			if (tolen < mappedlen)
				return (mdn_buffer_overflow);
			(void)memcpy(to, mapped, mappedlen);
			to += mappedlen;
			tolen -= mappedlen;
		}
		from += w;
		fromlen -= w;
	}
	if (tolen == 0)
		return (mdn_buffer_overflow);
	*to = '\0';
	return (mdn_success);
}

mdn_result_t
mdn_nameprep_isprohibited(mdn_nameprep_t handle, const char *str,
			  const char **found)
{
	assert(handle != NULL && str != NULL && found != NULL);

	TRACE(("mdn_nameprep_isprohibited(str=\"%s\")\n",
	       mdn_debug_xstring(str, 50)));

	return (mdn_nameprep_check(handle->prohibited_proc, str, found));
}
		
mdn_result_t
mdn_nameprep_isunassigned(mdn_nameprep_t handle, const char *str,
			  const char **found)
{
	assert(handle != NULL && str != NULL && found != NULL);

	TRACE(("mdn_nameprep_isunassigned(str=\"%s\")\n",
	       mdn_debug_xstring(str, 50)));

	return (mdn_nameprep_check(handle->unassigned_proc, str, found));
}
		
static mdn_result_t
mdn_nameprep_check(nameprep_checkproc proc, const char *str,
		   const char **found)
{
	size_t len;

	len = strlen(str);
	while (len > 0) {
		unsigned long v;
		int w;

		if ((w = mdn_utf8_getwc(str, len, &v)) == 0)
			return (mdn_invalid_encoding);

		if (v > UCS_MAX) {
			/* This cannot happen, but just in case.. */
			return (mdn_invalid_codepoint);
		} else if (v > UNICODE_MAX) {
			/* It is invalid.. */
			*found = str;
			return (mdn_success);
		} else if ((*proc)(v)) {
			*found = str;
			return (mdn_success);
		}

		str += w;
		len -= w;
	}
	*found = NULL;
	return (mdn_success);
}

mdn_result_t
mdn__nameprep_createproc(const char *parameter, void **handlep) {
	return mdn_nameprep_create(parameter, (mdn_nameprep_t *)handlep);
}

void
mdn__nameprep_destroyproc(void *handle) {
	mdn_nameprep_destroy((mdn_nameprep_t)handle);
}

mdn_result_t
mdn__nameprep_mapproc(void *handle, const char *from, char *to, size_t tolen) {
	return mdn_nameprep_map((mdn_nameprep_t)handle, from, to, tolen);
}

mdn_result_t
mdn__nameprep_prohibitproc(void *handle, const char *str, const char **found) {
	return mdn_nameprep_isprohibited((mdn_nameprep_t)handle, str, found);
}

mdn_result_t
mdn__nameprep_unassignedproc(void *handle, const char *str,
			     const char **found) {
	return mdn_nameprep_isunassigned((mdn_nameprep_t)handle, str, found);
}

