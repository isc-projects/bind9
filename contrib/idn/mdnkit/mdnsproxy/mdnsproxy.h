/*
 * dnsproxy.h - mDNS Proxy, Common Definitions
 */

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

/* $Id: mdnsproxy.h,v 1.1.2.1 2002/02/08 12:14:54 marka Exp $ */

#ifndef DNSPROXY_H
#define DNSPROXY_H 1

#include <stdio.h>

#ifdef  WIN32
#include <windows.h>
#include <winsock.h>
#else   /* for normal systems */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "proxycnf.h"

/*
 * Redefine TRUE and FALSE.
 */
#undef TRUE
#undef FALSE
#define TRUE    1
#define FALSE   0

/*
 * Macro for Error Logging
 */

enum {
    LOGMODE_FILE = 0,
    LOGMODE_SYSLOG = 1,
    LOGMODE_STDERR = 2
};

enum {
    LOGLEVEL_NONE = 0,
    LOGLEVEL_FATAL = 1,
    LOGLEVEL_WARN = 2,
    LOGLEVEL_TRACE = 3
};

BOOL    log_configure(int ac, char *av[]) ;
void    log_terminate(void) ;
void	log_turnover_request(void) ;
void	log_turnover(void) ;
void	log_setlevel(int level) ;
int	log_strtolevel(char *s) ;
void    log_fatal_printf(char *fmt, ...) ;
void    log_warn_printf(char *fmt, ...) ;
void    log_trace_printf(char *fmt, ...) ;

#define TRACE   log_trace_printf
#define WARN    log_warn_printf
#define FATAL   log_fatal_printf

/*
 * Server's Control Entries
 */

BOOL    server_init(int ac,  char *av[]) ;
void    server_stop(void) ;
void    server_loop(void) ;
void    server_done(void) ;

/*
 * Server calls following callback when received message
 */

void    notify_message(struct sockaddr *from, int proto,
                       u_char *msg, int len) ;

void    notify_timer(void) ;

/*
 * To send messages, call following entires in server module
 */

void    server_forward(struct sockaddr *to, int proto,
                      u_char *msg, int len) ;
void    server_response(struct sockaddr *to, int proto,
                      u_char *msg, int len) ;

/*
 * load/dump/dispose configuration data
 */
 
BOOL    config_load(int ac, char *av[]) ;
void    config_free(void) ;
void    config_dump(FILE *ofp) ;

/*
 * query configuration data
 */

BOOL    config_query_value(char *key, int *count, char ***array, int *lineNo) ;
BOOL    config_query_listen(struct sockaddr *addr)  ;
BOOL    config_query_forward(struct sockaddr *addr) ;
BOOL    config_query_restrict(BOOL *src_restrict) ;
BOOL    config_query_log_on_denied(BOOL *flag) ;

/*
 * Message (domain name) translation
 */

typedef struct translation_context {
    struct sockaddr *client;	/* address family/IP address/port */
    int protocol;		/* IPPROTO_TCP or IPPROTO_UDP */
    unsigned int old_id;	/* original message ID */
    unsigned int new_id;	/* new message ID */
} translation_context_t;

BOOL    translate_initialize(void) ;
void    translate_finish(void) ;
int     translate_request(translation_context_t *ctx,
		  const char *msg, size_t msglen,
		  char *translated, size_t bufsize, size_t *translatedlenp) ;
int     translate_reply(translation_context_t *ctx,
		const char *msg, size_t msglen,
		char *translated, size_t bufsize, size_t *translatedlenp) ;

/*
 * query configuration having multiple entries (with same key)
 *
 *      ctx = config_query_open(key, ...) ;
 *      while (ctx != NULL) {
 *          ctx = config_query_more(ctx, ...) ;
 *      }
 *      config_query_close(ctx) ;
 */

typedef void    *config_ctx_t ;     /* opaque pointer to lookup context */

config_ctx_t    config_query_open(char *key, int *count, char ***array,
    			int *lineNo) ;
config_ctx_t    config_query_more(config_ctx_t ctx, int *count, char ***array,
			int *lineNo) ;
void            config_query_close(config_ctx_t ctx) ;

/*
 * managing access control list.
 */
int		acl_initialize(void);
BOOL		acl_test(struct sockaddr *address);
void		acl_finalize(void);

#endif  /* DNSPROXY_H */
