/*
 * os2main.c - mDNS Proxy, entry for OS2
 *
 *      For OS/2, there are no daemon, nor service.  Simply
 *      start server program with
 *
 *          RUN in config.sys
 *          START in startup.cmd
 *          put server program (object) into startup folder
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

#ifndef lint
static char *rcsid = "$Id: os2main.c,v 1.1.2.1 2002/02/08 12:14:56 marka Exp $";
#endif

#ifdef  OS2

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "mdnsproxy.h"       /* Common definitions for mDNS proxy    */

/*
 * signal handler to catch signal to terminate server
 */

static  void    handler(int signo)
{
    server_stop() ;
    signal(signo, SIG_DFL) ;
}

/*
 * main - entry of os2 version
 */

int     main(int ac, char *av[])
{
    int     i, pid ;

    for (i = 1 ; i < ac ; i++) {
        if (strcmp(av[i], "-daemon") == 0) {
	    as_daemon = TRUE ;
	} else if (strcmp(av[i], "-conf") == 0) {
	    if (i + 1 == ac) {
		fprintf(stderr, "missing argument to \"%s\"\n", av[i]) ;
		return 1 ;
	    }
        } else if (strcmp(av[i], "-logfile") == 0) {
	    if (i + 1 == ac) {
		fprintf(stderr, "missing argument to \"%s\"\n", av[i]) ;
		return 1 ;
	    }
	} else if (av[i][0] == '-' && av[i][1] != '\0') {
		fprintf(stderr, "unknown option \"%s\"\n", av[i]) ;
		return 1 ;
	} else {
		fprintf(stderr, "too many arguments\n");
		return 1 ;
	}
    }

    if (config_load(ac, av) != TRUE) {
        printf("cannot load configurations\n") ;
	return 1 ;
    }

    if (log_configure(ac, av) != TRUE) {
        printf("cannot logging\n") ;
	return 1 ;
    }
    
    if (server_init(ac, av) != TRUE) {
        printf("cannot initialize server\n") ;
	log_terminate() ;
	return 1 ;
    }
    
    signal(SIGINT, handler)   ;
    signal(SIGKILL, handler)  ;
    signal(SIGTERM, handler)  ;
    signal(SIGBREAK, handler) ;
    
#ifdef  DEBUG
    printf("Service Started\n") ;
#endif
    
    server_loop() ;
    
#ifdef  DEBUG
    printf("Service Termiating...\n") ;
#endif

    server_done() ;
    
    log_terminate() ;
    
#ifdef  DEBUG
    printf("Service Terminated\n") ;
#endif
    
    return 0 ;
}

#endif  /* OS2 */

