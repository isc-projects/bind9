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

#ifndef lint
static char *rcsid = "$Id: translate.c,v 1.1.2.1 2002/02/08 12:15:01 marka Exp $";
#endif

#include <config.h>

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <mdn/result.h>
#include <mdn/log.h>
#include <mdn/converter.h>
#include <mdn/normalizer.h>
#include <mdn/msgtrans.h>

#include "mdnsproxy.h"

/*
 * DNS message rcode.
 */
enum {
    RCODE_NO_ERROR = 0,
    RCODE_FORMAT_ERROR = 1,
    RCODE_SERVER_FAILURE = 2,
    RCODE_NAME_ERROR = 3,
    RCODE_NOT_IMPLEMENTED = 4,
    RCODE_REFUSED = 5
};

mdn_converter_t client_converter;
mdn_resconf_t resconf;

static int	result_to_rcode(mdn_result_t r);
static char	*address_to_string(struct sockaddr *sa);
static void	mdnerror(int code, char *fmt, ...);


BOOL
translate_initialize(void)
{
    mdn_result_t r;
    char *mdn_conf_file;
    int ac;
    char **av;
    int lineNo;

    TRACE("translate_initialize()\n");

    /*
     * Initialize the resconf module.
     */
    mdn_resconf_initialize();
    mdn_converter_initialize();

    /*
     * Create a resconf module.
     */
    if (!config_query_value(KW_MDN_CONF_FILE, &ac, &av, &lineNo)) {
	mdn_conf_file = mdn_resconf_defaultfile();
    } else {
	if (ac != 2) {
	    WARN("wrong # of args for \"%s\", line %d\n", KW_MDN_CONF_FILE,
		lineNo);
	    return FALSE;
	}
	mdn_conf_file = av[1];
    }

    if ((r = mdn_resconf_create(&resconf)) != mdn_success) {
	mdnerror(r, "mdn conf file");
	return FALSE;
    }
    if ((r = mdn_resconf_loadfile(resconf, mdn_conf_file)) != mdn_success) {
	mdnerror(r, "mdn conf file %s", mdn_conf_file);
	return FALSE;
    }

    /*
     * Create a converter for local encoding.
     */
    if (!config_query_value(KW_CLIENT_ENCODING, &ac, &av, &lineNo)) {
	WARN("\"%s\" not found in the configuration file\n",
	    KW_CLIENT_ENCODING);
	return FALSE;
    }
    if (ac != 2) {
	WARN("wrong # of args for \"%s\", line %d\n", KW_CLIENT_ENCODING,
	    lineNo);
	return FALSE;
    }
    if ((r = mdn_converter_create(av[1], &client_converter, 0))
	!= mdn_success) {
	mdnerror(r, "client encoding %s", av[1]);
	return FALSE;
    }

    mdn_resconf_setlocalconverter(resconf, client_converter);

    return TRUE;
}

void
translate_finish(void)
{
    mdn_converter_destroy(client_converter);
    mdn_resconf_destroy(resconf);
}

int
translate_request(translation_context_t *ctx,
		  const char *msg, size_t msglen,
		  char *translated, size_t bufsize, size_t *translatedlenp)
{
    mdn_result_t r;

    TRACE("translate_request()\n");

    r = mdn_msgtrans_translate(resconf, msg, msglen,
			       translated, bufsize, translatedlenp);

    if (r != mdn_success) {
	mdnerror(r, "translating request message from %s(%s)",
		 address_to_string(ctx->client),
		 ctx->protocol == SOCK_STREAM ? "tcp" : "udp");
    }

    return result_to_rcode(r);
}

int
translate_reply(translation_context_t *ctx,
		const char *msg, size_t msglen,
		char *translated, size_t bufsize, size_t *translatedlenp)
{
    mdn_result_t r;

    TRACE("translate_reply()\n");

    r = mdn_msgtrans_translate(resconf, msg, msglen,
			       translated, bufsize, translatedlenp);

    if (r != mdn_success) {
	mdnerror(r, "translating reply message from %s",
		 address_to_string(ctx->client));
    }

    return result_to_rcode(r);
}

static int
result_to_rcode(mdn_result_t r)
{
    int rcode;

    switch (r) {
    case mdn_success:
	rcode = RCODE_NO_ERROR;
	break;
    case mdn_buffer_overflow:
    case mdn_nomemory:
	rcode = RCODE_SERVER_FAILURE;
	break;
    case mdn_invalid_message:
    case mdn_invalid_encoding:
	rcode = RCODE_FORMAT_ERROR;
	break;
    default:
	rcode = RCODE_SERVER_FAILURE;
	break;
    }
    return rcode;
}

static char *
address_to_string(struct sockaddr *sa)
{
    static char tmp[200];

    switch (sa->sa_family) {
    case AF_INET:
    {
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	sprintf(tmp, "%s/%d", inet_ntoa(sin->sin_addr),
		ntohs(sin->sin_port));
	break;
    }
#if 0
#ifdef AF_INET6
    case AF_INET6:
    {
	char buf[INET6_ADDRSTRLEN];

	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	sprintf(tmp, "%s/%d",
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)),
		ntohs(sin6->sin6_port));
	break;
    }
#endif
#endif
    default:
	sprintf(tmp, "unknown address family %d", sa->sa_family);
	break;
    }
    return tmp;
}

static void
mdnerror(int code, char *fmt, ...)
{
    char buf[1024];
    va_list args;

    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);

    sprintf(buf + strlen(buf), ": %s", mdn_result_tostring(code));
    WARN("%s\n", buf);
}
