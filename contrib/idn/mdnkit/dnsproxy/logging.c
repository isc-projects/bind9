/*
 * logging.c - logging support
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
static char *rcsid = "$Id: logging.c,v 1.13 2000/11/17 05:46:23 ishisone Exp $";
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "dnsproxy.h"

#define DEFAULT_LOGFILE	"dnsproxy.log"

#ifdef DEBUG
#define DEFAULT_LOG_LEVEL LOGLEVEL_TRACE
#else
#define DEFAULT_LOG_LEVEL LOGLEVEL_WARN
#endif

/*
 * Logging Control Variables
 */

static  char    logFname[256] = { 0 } ;
static  FILE    *logFptr = NULL       ;
static	int	logLevel = DEFAULT_LOG_LEVEL ;
static  int	timeToTurnOver = 0 ;

/*
 * log_default_path -- get default log file pathname
 */

static void	log_default_path(void)
{
#ifdef UNIX
    (void)strcpy(logFname, "/tmp/") ;
    (void)strcat(logFname, DEFAULT_LOGFILE) ;
#endif
#if defined(WIN32) || defined(OS2)
    {
	char *env;
	if ((env = getenv("TEMP")) == NULL)
	    env = getenv("TMP");
	if (env != NULL &&
	    strlen(env) + strlen(DEFAULT_LOGFILE) + 1 < sizeof(logFname)) {
	    (void)strcpy(logFname, env);
	    (void)strcat(logFname, "\\");
	    (void)strcat(logFname, DEFAULT_LOGFILE);
	}
    }
#endif
}

/*
 * log_configure - configure logging (must be called after 'config_load')
 */

void    log_configure(int ac, char *av[])
{
    int     i, nArgs   ;
    char    **aArgs    ;
    char    *fn = NULL ;

    if (config_query_value("log-file", &nArgs, &aArgs) == TRUE) {
        if (nArgs >= 2) {
	    fn = aArgs[1] ;
	}
    }
    for (i = 1 ; i < ac ; i++) {
        if (strcmp(av[i], "-logfile") == 0) {
	    fn = av[i+=1] ;
	}
    }
    if (fn != NULL && strlen(fn) < sizeof(logFname)) {
        strcpy(logFname, fn) ;
    } else {
	log_default_path();
    }

    if (config_query_value("log-level", &nArgs, &aArgs) == TRUE) {
	int level ;

	if (nArgs != 2) {
	    WARN("syntax error at log-level line\n");
	} else if ((level = log_strtolevel(aArgs[1])) < 0) {
	    WARN("invalid log level %s\n", aArgs[1]);
	} else {
	    log_setlevel(level);
	}
    }
}

/*
 * log_terminate - terminate logging
 */

void    log_terminate(void)
{
    if (logFptr != NULL) {
        fclose(logFptr) ;
        logFptr = NULL  ;
    }
}

/*
 * log_turnover_request - request turning over log
 *	this function is intended for calling from singnal handler.
 */

void	log_turnover_request(void)
{
    timeToTurnOver = 1;
}

/*
 * log_turnover - turn over log if requested
 */

void	log_turnover(void)
{
    if (timeToTurnOver) {
	timeToTurnOver = 0;
	log_trace_printf("--- log file turned over\n");
	log_terminate() ;
    }
}

/*
 * log_setlevel - set log level
 */
void	log_setlevel(int level)
{
    logLevel = level;
}

/*
 * log_strtolevel - string to log level
 */
int	log_strtolevel(char *s)
{
    if ('0' <= s[0] && s[0] <= '9') {
	return atoi(s) ;
    } else if (!strcmp(s, "none")) {
	return LOGLEVEL_NONE;
    } else if (!strcmp(s, "fatal")) {
	return LOGLEVEL_FATAL;
    } else if (!strcmp(s, "warn") || !strcmp(s, "warning")) {
	return LOGLEVEL_WARN;
    } else if (!strcmp(s, "trace")) {
	return LOGLEVEL_TRACE;
    } else {
	return -1;
    }
}

/*
 * log_vprintf - as name describes
 */

static void	log_vprintf(int level, char *fmt, va_list arg_ptr)
{
    char    buff[512] ;
    
    if (logLevel < level) {
	return;
    }

    /*
     * format message
     */
     
    vsprintf(buff, fmt, arg_ptr) ;

#ifdef  DEBUG
    printf("%s", buff) ;
    fflush(stdout)    ;
#endif

    /*
     * log to file
     */
     
    if (*logFname == '\0') {
        return ;                /* no logging file specified */
    }
    if (logFptr == NULL) {
        logFptr = fopen(logFname, "a") ;
    }
    if (logFptr != NULL) {
        fputs(buff, logFptr) ;
	fflush(logFptr) ;
    }
#ifdef  WIN32               /* For NT, having trouble with      */
    fclose(logFptr) ;       /* reading open'd logging file      */
    logFptr = NULL  ;       /* so, close and re-open it         */
#endif
}

/*
 * log_fatal_printf, log_warn_printf, log_trace_printf - write out
 *	fatal/warning/trace log to the log file
 */

void    log_fatal_printf(char *fmt, ...)
{
    va_list arg_ptr   ;
    
    va_start(arg_ptr, fmt) ;
    log_vprintf(LOGLEVEL_FATAL, fmt, arg_ptr) ;
    va_end(arg_ptr) ;
}

void    log_warn_printf(char *fmt, ...)
{
    va_list arg_ptr   ;
    
    va_start(arg_ptr, fmt) ;
    log_vprintf(LOGLEVEL_WARN, fmt, arg_ptr) ;
    va_end(arg_ptr) ;
}

void    log_trace_printf(char *fmt, ...)
{
    va_list arg_ptr   ;
    
    va_start(arg_ptr, fmt) ;
    log_vprintf(LOGLEVEL_TRACE, fmt, arg_ptr) ;
    va_end(arg_ptr) ;
}
