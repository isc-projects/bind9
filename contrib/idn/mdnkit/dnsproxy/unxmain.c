/*
 * unxmain.c - mDNS Proxy, entry for UNIX
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
static char *rcsid = "$Id: unxmain.c,v 1.16 2000/11/17 05:46:23 ishisone Exp $";
#endif

#ifdef	UNIX

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#ifdef  HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "dnsproxy.h"       /* Common definitions for mDNS proxy    */

#define KW_ROOT_DIR	"root-directory"
#define KW_USER_ID	"user-id"
#define KW_GROUP_ID	"group-id"

static uid_t	uid;
static gid_t	gid;
static char	*root_dir;
static BOOL	uid_specified = FALSE;
static BOOL	gid_specified = FALSE;

/*
 * signal handler to catch signal to terminate server
 */

static  void    handler(int signo)
{
    server_stop() ;
    signal(signo, SIG_DFL) ;
}

/*
 * signal handler to turn over the log file
 */

static  void    hup_handler(int signo)
{
    log_turnover_request();
    signal(signo, hup_handler) ;
}

/*
 * Set root directory.
 */

static	void	change_root(void)
{
    int		err;

    if (root_dir != NULL && chroot(root_dir) < 0) {
	err = errno;
	FATAL("cannot change root directory: %s\n", strerror(err));
	exit(1);
    }
}

/*
 * Set user/group ID.
 */

static	void	set_id(void)
{
    int		err;

    if (uid_specified && setuid(uid) < 0) {
	err = errno;
	FATAL("cannot set user ID: %s\n", strerror(err));
	exit(1);
    }

    if (gid_specified && setgid(gid) < 0) {
	err = errno;
	FATAL("cannot set group ID: %s\n", strerror(err));
	exit(1);
    }
}

/*
 * Load configuration parameter related to security.
 */

static	void	get_security_conf(void)
{
    int		ac;
    char	**av;

    if (config_query_value(KW_ROOT_DIR, &ac, &av)) {
	if (ac != 2) {
	    WARN("syntax error at %s line\n", KW_ROOT_DIR);
	    exit(1);
	}
	root_dir = malloc(strlen(av[1]) + 1);
	if (root_dir == NULL) {
		FATAL("malloc failed\n");
		exit(1);
	}
	(void)strcpy(root_dir, av[1]);
    }

    if (config_query_value(KW_USER_ID, &ac, &av)) {
	struct passwd	*pwd;

	if (ac != 2) {
	    WARN("syntax error at %s line\n", KW_USER_ID);
	    exit(1);
	} else if ((pwd = getpwnam(av[1])) != NULL) {
	    uid = pwd->pw_uid;
	    uid_specified = TRUE;
	} else if (isdigit((unsigned char)(av[1][0]))) {
	    uid = atoi(av[1]);
	    uid_specified = TRUE;
	} else {
	    FATAL("unknown user %s\n", av[1]);
	    exit(1);
	}
    }

    if (config_query_value(KW_GROUP_ID, &ac, &av)) {
	struct group	*gr;

	if (ac != 2) {
	    WARN("syntax error at %s line\n", KW_GROUP_ID);
	    exit(1);
	} else if ((gr = getgrnam(av[1])) != NULL) {
	    gid = gr->gr_gid;
	    gid_specified = TRUE;
	} else if (isdigit((unsigned char)(av[1][0]))) {
	    gid = atoi(av[1]);
	    gid_specified = TRUE;
	} else {
	    FATAL("unknown group %s\n", av[1]);
	    exit(1);
	}
    }
}

/*
 * main - entry of UNIX version
 */

int     main(int ac, char *av[])
{
    int     i, pid ;
    BOOL    as_daemon = FALSE ;
    
    for (i = 1 ; i < ac ; i++) {
        if (strcmp(av[i], "-daemon") == 0) {
	    as_daemon = TRUE ;
	}
    }
    if (config_load(ac, av) != TRUE) {
        printf("cannot load configurations\n") ;
	return 1 ;
    }
    log_configure(ac, av) ;
    
    get_security_conf();

    if (server_init(ac, av) != TRUE) {
        printf("cannot initialize server\n") ;
	log_terminate() ;
	return 1 ;
    }
    
    if (as_daemon) {
        switch (pid = fork()) {
	case -1 :
	    printf("cannot start daemon %d\n", errno) ;
	    server_done()   ;
	    log_terminate() ;
	    return 2 ;
        case 0 :    /* children, as daemon */
	    setsid() ;
	    close(0) ;
	    close(1) ;
	    close(2) ;
	    break ;
        default :
	    printf("start daemon PID %d\n", pid) ;
	    return 0 ;
        }
    }

    /*
     * Change root directory/user ID/group ID if specified.
     */
    change_root();
    set_id();
     
    signal(SIGHUP, hup_handler) ;
    signal(SIGINT, handler)   ;
    signal(SIGKILL, handler)  ;
    signal(SIGTERM, handler)  ;
    
#ifdef  DEBUG
    printf("Service Started\n") ;
#endif
    
    server_loop() ;
    
#ifdef  DEBUG
    printf("Service Terminating...\n") ;
#endif

    server_done() ;
    
    log_terminate() ;
    
#ifdef  DEBUG
    printf("Service Terminated\n") ;
#endif
    
    return 0 ;
}
#endif /* UNIX */
