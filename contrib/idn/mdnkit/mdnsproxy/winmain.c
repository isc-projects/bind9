/*
 * winmain.c - mDNS Proxy, entry for WIN32
 *
 *      Windows version works as
 *
 *          Service Program, as mDNS Proxy Server
 *          Service Configuration Program, Install/Remove mDNS Proxy
 *
 *      or simply as
 *
 *          Application Program, for debugging
 *
 *      with single executable, switched with first option
 *
 *          -service        as Service Program
 *          -install        as Configuration, install serivce
 *          -remove         as Configuration, remove  service
 *
 *      Otherwise, it runs as simple console apllication.
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
static char *rcsid = "$Id: winmain.c,v 1.1.2.1 2002/02/08 12:15:04 marka Exp $";
#endif

#ifdef  WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "mdnsproxy.h"       /* Common definitions for mDNS proxy    */
#include "winserv.h"        /* WIN32 Service Related Functions      */

/*
 * signal handler to catch signal to terminate server
 */

static  void    handler(int signo)
{
    server_stop() ;
    signal(signo, SIG_DFL) ;
}

/*
 * main - entry of windows version
 */

int     main(int ac, char *av[])
{
    WORD    version = MAKEWORD(2, 0) ;
    WSADATA wsaData ;

    /*
     * check 1st option
     */

    if (ac >= 2) {
        if (strcmp(av[1], "-service") == 0) {
	    serviceRun(ac, av) ;
	    return 0 ;
	}
	if (strcmp(av[1], "-install") == 0) {
	    serviceInstall(ac, av) ;
	    return 0 ;
	}
	if (strcmp(av[1], "-remove") == 0) {
	    serviceRemove(ac, av) ;
	    return 0 ;
	}
    }
    
    /*
     * otherwise run as normal application
     */
     
    if (config_load(ac, av) != TRUE) {
        printf("cannot load configration\n") ;
	return 1 ;
    }

    if (log_configure(ac, av) != TRUE) {
        printf("cannot logging\n") ;
	return 1 ;
    }
    
    if (WSAStartup(version, &wsaData) != 0) {
        printf("cannot startup WinSock\n") ;
	return FALSE ;
    }
    if (server_init(ac, av) != TRUE) {
        printf("cannot initialize server\n") ;
	WSACleanup() ;
	return 1 ;
    }
    
    signal(SIGINT, handler)   ;
    signal(SIGTERM, handler)  ;
    signal(SIGBREAK, handler) ;
    
    printf("Service  Started\n") ;
    
    server_loop() ;
    
    printf("Service Termiating...\n") ;

    server_done() ;

    printf("Service Terminated\n") ;
    
    WSACleanup() ;

    log_terminate() ;
    
    return 0 ;
}

#endif  /* WIN32 */
