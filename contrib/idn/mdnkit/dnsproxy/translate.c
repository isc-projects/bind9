/*
 * Copyright (c) 2000 Japan Network Information Center.  All rights reserved.
 *  
 * By using this file, you agree to the terms and conditions set forth bellow.
 * 
 * 			LICENSE TERMS AND CONDITIONS 
 * 
 * The following License Terms and Conditions apply, unless a different
 * license is obtained from Japan Network Information Center ("JPNIC"),
 * a Japanese association, Fuundo Bldg., 1-2 Kanda Ogawamachi, Chiyoda-ku,
 * Tokyo, Japan.
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
static char *rcsid = "$Id: translate.c,v 1.22 2000/11/21 02:09:02 ishisone Exp $";
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
#include <mdn/translator.h>
#include <mdn/zldrule.h>
#include <mdn/msgtrans.h>

#include "dnsproxy.h"

/*
 * Configuration file keywords.
 */
#define KW_LOG_LEVEL		"mdn-log-level"		/* tentative */
#define KW_ALIAS_FILE		"encoding-alias-file"
#define KW_CLIENT_TRANSLATION	"client-translation"
#define KW_ALTERNATE_ENCODING	"alternate-encoding"
#define KW_NORMALIZATION	"normalize"
#define KW_SERVER_TRANSLATION	"server-translation"

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

typedef struct translation {
    mdn_zldrule_t rule;
    char *server_zld;
    mdn_converter_t server_converter;
    mdn_normalizer_t normalizer;
    mdn_converter_t alternate_converter;
} translation_t;

static translation_t	trans;

static int	result_to_rcode(mdn_result_t r);
static char	*address_to_string(struct sockaddr *sa);
static int	string_to_loglevel(char *s);
static void	config_required(char *keyword);
static void	mdnerror(int code, char *fmt, ...);
static void	translate_log_handler(int level, const char *msg);


BOOL
translate_initialize(void)
{
    mdn_result_t r;
    config_ctx_t cctx;
    int ac;
    char **av;
    int i;

    TRACE("translate_initialize()\n");

    /*
     * Set MDN library log handler.
     */
    mdn_log_setproc(translate_log_handler);

    /*
     * Set log level before calling any other functions in
     * MDN library.
     */
    if (config_query_value(KW_LOG_LEVEL, &ac, &av)) {
	int level;

	if (ac != 2) {
	    WARN("syntax error at %s line\n", KW_LOG_LEVEL);
	    return FALSE;
	}
	if ((level = string_to_loglevel(av[1])) >= 0) {
	    mdn_log_setlevel(level);
	} else {
	    WARN("unknown log level %.100s -- ignored\n", av[1]);
	}
    }

    /*
     * Initialize modules.
     */
    mdn_converter_initialize();
    mdn_normalizer_initialize();

    /*
     * Create context.
     */
    if ((r = mdn_zldrule_create(&trans.rule)) != mdn_success) {
	mdnerror(r, "initializing ZLD rules");
	return FALSE;
    }
    if ((r = mdn_normalizer_create(&trans.normalizer)) != mdn_success) {
	mdnerror(r, "initializing normalization");
	return FALSE;
    }

    /*
     * Load configuration data other than log level.
     */

    /*
     * Encoding alias file.
     */
    if (config_query_value(KW_ALIAS_FILE, &ac, &av)) {
	if (ac != 2) {
	    WARN("syntax error at %s line\n", KW_ALIAS_FILE);
	    return FALSE;
	}
	if ((r = mdn_converter_aliasfile(av[1])) != mdn_success) {
	    mdnerror(r, "reading codeset alias file %.200s", av[1]);
	    return FALSE;
	}
    }

    /*
     * Client-side translation rule.
     */
    if ((cctx = config_query_open(KW_CLIENT_TRANSLATION, &ac, &av)) == NULL) {
	config_required(KW_CLIENT_TRANSLATION);
	return FALSE;
    }
    do {
	if (ac < 3) {
	    WARN("syntax error at %s line\n", KW_ALIAS_FILE);
	    return FALSE;
	}
#ifndef MDN_SUPPORT_ZLD
	if (strcmp(av[1], "") != 0 && strcmp(av[1], ".") != 0) {
	    WARN("ignore ZLD %s\n", av[1]);
	}
#endif
	r = mdn_zldrule_add(trans.rule, av[1], (const char **)&av[2], ac - 2);
	if (r != mdn_success) {
	    mdnerror(r, "adding ZLD rules for %s", av[1]);
	    return FALSE;
	}
    } while ((cctx = config_query_more(cctx, &ac, &av)) != NULL);
    config_query_close(cctx);

    /*
     * Client-side alternate encoding.
     */
    if (config_query_value(KW_ALTERNATE_ENCODING, &ac, &av)) {
	if (ac != 2) {
	    WARN("syntax error at %s line\n", KW_ALTERNATE_ENCODING);
	    return FALSE;
	}
	if ((r = mdn_converter_create(av[1], &trans.alternate_converter, 0))
	    != mdn_success) {
	    mdnerror(r, "alternate encoding %s", av[2]);
	    return FALSE;
	}
	if (!mdn_converter_isasciicompatible(trans.alternate_converter)) {
	    WARN("alternate encoding must be ASCII-compatible\n");
	    return FALSE;
	}
    } else {
	trans.alternate_converter = NULL;
    }

    /*
     * Normalization.
     */
    if (!config_query_value(KW_NORMALIZATION, &ac, &av)) {
	config_required(KW_NORMALIZATION);
	return FALSE;
    }
    for (i = 1; i < ac; i++) {
	if ((r = mdn_normalizer_add(trans.normalizer, av[i])) != mdn_success) {
	    mdnerror(r, "adding normalization scheme %s", av[i]);
	    return FALSE;
	}
    }

    /*
     * Server-side translation.
     */
    if (!config_query_value(KW_SERVER_TRANSLATION, &ac, &av)) {
	config_required(KW_SERVER_TRANSLATION);
	return FALSE;
    }
    if (ac != 3) {
	WARN("syntax error at %s line\n", KW_SERVER_TRANSLATION);
	return FALSE;
    }
    if ((r = mdn_translator_canonicalzld(av[1], &trans.server_zld))
	!= mdn_success) {
	mdnerror(r, "server-side ZLD %s", av[2]);
	return FALSE;
    }
#ifndef MDN_SUPPORT_ZLD
    if (trans.server_zld != NULL) {
	WARN("ignore ZLD %s\n", av[1]);
	free(trans.server_zld);
	trans.server_zld = NULL;
    }
#endif
    if ((r = mdn_converter_create(av[2], &trans.server_converter, 0))
	!= mdn_success) {
	mdnerror(r, "server-side encoding %s", av[2]);
	return FALSE;
    }

    return TRUE;
}

void
translate_finish(void)
{
    if (trans.rule != NULL) {
	mdn_zldrule_destroy(trans.rule);
	trans.rule = NULL;
    }
    if (trans.server_zld != NULL) {
	free(trans.server_zld);
	trans.server_zld = NULL;
    }
    if (trans.server_converter != NULL) {
	mdn_converter_destroy(trans.server_converter);
	trans.server_converter = NULL;
    }
    if (trans.normalizer != NULL) {
	mdn_normalizer_destroy(trans.normalizer);
	trans.normalizer = NULL;
    }
    if (trans.alternate_converter != NULL) {
	mdn_converter_destroy(trans.alternate_converter);
	trans.alternate_converter = NULL;
    }
}

int
translate_request(translation_context_t *ctx,
		  const char *msg, size_t msglen,
		  char *translated, size_t bufsize, size_t *translatedlenp)
{
    mdn_msgtrans_param_t param;
    mdn_result_t r;

    TRACE("translate_request()\n");

    ctx->zld = NULL;
    ctx->converter = NULL;

    /*
     * Initialize translation parameters.
     */
    param.use_local_rule = 1;
    param.local_rule = trans.rule;
    param.local_converter = NULL;
    param.local_zld = NULL;
    param.local_alt_converter = trans.alternate_converter;
    param.target_converter = trans.server_converter;
    param.target_alt_converter = NULL;
    param.target_zld = trans.server_zld;
    param.normalizer = trans.normalizer;

    r = mdn_msgtrans_translate(&param, msg, msglen,
			       translated, bufsize, translatedlenp);

    if (r != mdn_success) {
	mdnerror(r, "translating request message from %s(%s)",
		 address_to_string(ctx->client),
		 ctx->protocol == SOCK_STREAM ? "tcp" : "udp");
    } else {
	ctx->zld = param.local_zld;
	ctx->converter = param.local_converter;
    }

    return result_to_rcode(r);
}

int
translate_reply(translation_context_t *ctx,
		const char *msg, size_t msglen,
		char *translated, size_t bufsize, size_t *translatedlenp)
{
    mdn_msgtrans_param_t param;
    mdn_result_t r;

    TRACE("translate_reply()\n");

    if (ctx->converter == NULL) {
	/*
	 * No translation required.
	 */
	TRACE("translate_reply: pass through message (old_id=%d,new_id=%d)\n",
	      ctx->old_id, ctx->new_id);
	if (bufsize < msglen)
	    return (RCODE_SERVER_FAILURE);
	(void)memcpy(translated, msg, msglen);
	*translatedlenp = msglen;
	return RCODE_NO_ERROR;
    }

    /*
     * Initialize translation parameters.
     */
    param.use_local_rule = 0;
    param.local_rule = NULL;
    param.local_converter = trans.server_converter;
    param.local_zld = trans.server_zld;
    param.local_alt_converter = NULL;
    param.target_converter = ctx->converter; 
    param.target_alt_converter = trans.alternate_converter;
    param.target_zld = ctx->zld;
    param.normalizer = NULL;

    r = mdn_msgtrans_translate(&param, msg, msglen,
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

static int
string_to_loglevel(char *s)
{
    if ('0' <= s[0] && s[0] <= '9')
	return atoi(s);
    else if (!strcmp(s, "fatal"))
	return mdn_log_level_fatal;
    else if (!strcmp(s, "error"))
	return mdn_log_level_error;
    else if (!strcmp(s, "warning"))
	return mdn_log_level_warning;
    else if (!strcmp(s, "info"))
	return mdn_log_level_info;
    else if (!strcmp(s, "trace"))
	return mdn_log_level_trace;
    else if (!strcmp(s, "dump"))
	return mdn_log_level_dump;
    else
	return -1;
}

static void
config_required(char *keyword)
{
    WARN("%s line required in the configuration file\n", keyword);
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

static void
translate_log_handler(int level, const char *msg)
{
    switch (level) {
    case mdn_log_level_fatal:
	FATAL((char *)msg);
	break;
    case mdn_log_level_warning:
    case mdn_log_level_info:
	WARN((char *)msg);
	break;
    case mdn_log_level_trace:
    case mdn_log_level_dump:
	TRACE((char *)msg);
	break;
    }
}
