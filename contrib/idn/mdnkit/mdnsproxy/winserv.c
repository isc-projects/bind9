/*
 * winserv.c - mDNS Proxy, WIN32 Service Specific Functions
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
static char *rcsid = "$Id: winserv.c,v 1.1.2.1 2002/02/08 12:15:06 marka Exp $";
#endif

#ifdef  WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#include "mdnsproxy.h"       /* Common definitions for mDNS proxy    */
#include "winserv.h"        /* Windows's Service Specific           */

/*
 * Parameters for WIN32 Service
 */

#define SERVICENAME     "mdnsproxy"
#define DISPLAYNAME     "mDNS Proxy"

static  UCHAR   pathService[1024] ;

/*
 * getFileName - get fullpath and split it
 */
 
static  UCHAR   p_ful[256] ;
static  UCHAR   p_drv[256] ;
static  UCHAR   p_dir[256] ;
static  UCHAR   p_nam[256] ;
static  UCHAR   p_ext[256] ;

static  void    getFileName(void)
{
    GetModuleFileName(NULL, p_ful, 256) ;
    _splitpath(p_ful, p_drv, p_dir, p_nam, p_ext) ;
}

/*
 * Service management Varibales
 */

SERVICE_STATUS_HANDLE   ServiceStatusHandle = 0     ;
SERVICE_STATUS          ServiceStatusRecord = { 0 } ;
int                     ServiceErrorCode    = 0     ;

void    serviceLogTrace(PUCHAR msg)
{
    char    msgbuff[256] ;
    HANDLE  hEventSrc    ;
    char    *strings[2]  ;

    ServiceErrorCode = GetLastError() ;

    sprintf(msgbuff, "%s trace: %d", SERVICENAME, ServiceErrorCode) ;
    strings[0] = msgbuff ;
    strings[1] = msg     ;

    hEventSrc = RegisterEventSource(NULL, TEXT(SERVICENAME)) ;

    if (hEventSrc != NULL) {
        ReportEvent(
            hEventSrc,
            EVENTLOG_INFORMATION_TYPE,
            0,
            0,
            NULL,
            2,
            0,
            (const char **) strings,
            NULL) ;
        DeregisterEventSource(hEventSrc) ;
    }
    /* TRACE("%s %s\n", msgbuff, msg) ; */
}

void    serviceLogError(PUCHAR msg)
{
    char    msgbuff[256] ;
    HANDLE  hEventSrc    ;
    char    *strings[2]  ;

    ServiceErrorCode = GetLastError() ;

    sprintf(msgbuff, "%s error: %d", SERVICENAME, ServiceErrorCode) ;
    strings[0] = msgbuff ;
    strings[1] = msg     ;

    hEventSrc = RegisterEventSource(NULL, TEXT(SERVICENAME)) ;

    if (hEventSrc != NULL) {
        ReportEvent(
            hEventSrc,
            EVENTLOG_ERROR_TYPE,
            0,
            0,
            NULL,
            2,
            0,
            (const char **) strings,
            NULL) ;
        DeregisterEventSource(hEventSrc) ;
    }
    /* FATAL("%s %s\n", msgbuff, msg) ; */
}

/*
 * serviceReport - report service status
 */

VOID    serviceReport(DWORD state, DWORD exitcode, DWORD waithint)
{
    static  DWORD   checkpoint = 1 ;

    if (state == SERVICE_START_PENDING) {
        ServiceStatusRecord.dwControlsAccepted = 0 ;
    } else {
        ServiceStatusRecord.dwControlsAccepted = SERVICE_ACCEPT_STOP ;
    }
    ServiceStatusRecord.dwCurrentState  = state    ;
    ServiceStatusRecord.dwWin32ExitCode = exitcode ;
    ServiceStatusRecord.dwWaitHint      = waithint ;

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
        ServiceStatusRecord.dwCheckPoint = 0 ;
    } else {
        ServiceStatusRecord.dwCheckPoint = checkpoint++ ;
    }

    SetServiceStatus(ServiceStatusHandle, &ServiceStatusRecord) ;
}

/*
 * ServiceCtrl - service control handler
 */

VOID    ServiceCtrl(DWORD opcode)
{
    switch (opcode) {

    case SERVICE_CONTROL_STOP :
        serviceLogTrace("ServiceCtrl STOP") ;
        ServiceStatusRecord.dwCurrentState = SERVICE_STOP_PENDING ;
        /* nofity later, so set status only */
        server_stop() ;     /* stop server loop */
        break ;

    case SERVICE_CONTROL_INTERROGATE :
        /* query, report later */
        serviceLogTrace("ServiceCtrl INTERROGATE") ;
        break ;

    default :
        break ;
    }
    serviceReport(ServiceStatusRecord.dwCurrentState, NO_ERROR, 0) ;
}

/*
 * ServiceMain - as name describes
 */

static  UCHAR   cmdline[1024] ;

VOID    ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    WORD    version = MAKEWORD(2, 0) ;
    WSADATA wsaData ;

    /*
     * initialize service status
     */

    ServiceStatusRecord.dwServiceType = SERVICE_WIN32 | SERVICE_INTERACTIVE_PROCESS ;
    ServiceStatusRecord.dwServiceSpecificExitCode = 0 ;

    /*
     * register Service Control Handler
     */

    ServiceStatusHandle = RegisterServiceCtrlHandler(
            TEXT(SERVICENAME),
            (LPHANDLER_FUNCTION) ServiceCtrl) ;
    if (ServiceStatusHandle == (SERVICE_STATUS_HANDLE) 0) {
        serviceLogError("RegisterServiceCtrlHandler failed") ;
        return ;
    }

    serviceReport(SERVICE_START_PENDING, NO_ERROR, (30 * 1000)) ;

    /*
     * Initialize & Run service
     */

    serviceLogTrace("start initializing") ;

    if (config_load((int) dwArgc, (char **) lpszArgv) != TRUE) {
        serviceLogError("cannot initialize server") ;
        serviceReport(SERVICE_STOPPED, 0, 0) ;
        return ;
    }

    if (log_configure((int) dwArgc, (char **) lpszArgv) != TRUE) {
        serviceLogError("cannot logging") ;
        serviceReport(SERVICE_STOPPED, 0, 0) ;
        return ;
    }
        
    if (WSAStartup(version, &wsaData) != 0) {
        serviceLogError("cannot initialize WinSock") ;
        serviceReport(SERVICE_STOPPED, 0, 0) ;
        return ;
    }
    if (server_init((int) dwArgc, (char **) lpszArgv) != TRUE) {
        serviceLogError("cannot initialize server") ;
        serviceReport(SERVICE_STOPPED, 0, 0) ;
	WSACleanup() ;
        return ;
    }

    serviceReport(SERVICE_RUNNING, NO_ERROR, 0) ;

    serviceLogTrace("initialization done, running now") ;

    server_loop() ;         /* do service here */

    serviceLogTrace("service loop finished, closing") ;

    serviceReport(SERVICE_STOP_PENDING, NO_ERROR, (10 * 1000)) ;

    server_done() ;         /* cleaup */
    WSACleanup() ;

    serviceLogTrace("service finised") ;

    serviceReport(SERVICE_STOPPED, NO_ERROR, 0) ;

    log_terminate() ;
}

/*
 * serviceRun - run Service
 */

static      SERVICE_TABLE_ENTRY   ServiceTable[] = {
    { TEXT(SERVICENAME), (LPSERVICE_MAIN_FUNCTION) ServiceMain } ,
    { NULL,              NULL                                  }
} ;

void    serviceRun(int ac, char *av[])
{
    serviceLogTrace("serviceRun - start") ;

    if (StartServiceCtrlDispatcher(ServiceTable) == 0) {
        serviceLogError("StartServiceCtrlDispatcher failed") ;
    }
}

/*
 * serviceInstall - install service
 */

void    serviceInstall(int ac, char *av[])
{
    SC_HANDLE   hSCManager = NULL ;
    SC_HANDLE   hService   = NULL ;

    getFileName() ;

#ifdef  DEBUG
    printf("Install Service %s \"%s\"\n", SERVICENAME, p_ful) ;
#endif

    /*
     * open Service Manager
     */

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS) ;

    if (hSCManager == NULL) {
        printf("cannot open SCManager %d\n", GetLastError()) ;
        return ;
    }

#ifdef  DEBUG
    printf("open SCManager\n") ; fflush(stdout) ;
#endif

    /*
     * prepare service path (exe path with arguments)
     */

    sprintf(pathService, "\"%s\" -service", p_ful) ;

#ifdef  DEBUG
    printf("Installing %s\n", pathService) ;
#endif

    /*
     * create service entry
     */

    hService = CreateService(
            hSCManager,                         /* SCManager database   */
            TEXT(SERVICENAME),                  /* name of service      */
            TEXT(DISPLAYNAME),                  /* its display name     */
            SERVICE_ALL_ACCESS,                 /* desired access       */
            SERVICE_WIN32_OWN_PROCESS,          /* service type         */
            SERVICE_DEMAND_START,               /* start type           */
            SERVICE_ERROR_IGNORE,               /* error control type   */
            TEXT(pathService),                  /* service image        */
            NULL,                               /* no load order        */
            NULL,                               /* no tag identifier    */
            NULL,                               /* no dependencies      */
            NULL,                               /* LocalSystem account  */
            NULL) ;                             /* no password          */

    CloseServiceHandle(hSCManager) ;

    if (hService == NULL) {
        printf("cannot create service %d\n", GetLastError()) ;
        return ;
    }

    CloseServiceHandle(hSCManager) ;

    printf("Installed Service %s\n", pathService) ;
}

/*
 * serviceRemove - remove service
 */

void    serviceRemove(int ac, char *av[])
{
    SC_HANDLE   hSCManager = NULL ;
    SC_HANDLE   hService   = NULL ;

    getFileName() ;

#ifdef  DEBUG
    printf("Removing Service %s\n", SERVICENAME) ;
#endif

    /*
     * open Service Manager
     */

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS) ;

    if (hSCManager == NULL) {
        printf("cannot open SCManager %d\n", GetLastError()) ;
        return ;
    }

#ifdef  DEBUG
    printf("open SCManager\n") ; fflush(stdout) ;
#endif

    /*
     * delete service
     */

    hService = OpenService(
            hSCManager,                         /* SCManager database   */
            TEXT(SERVICENAME),                  /* name of service      */
            DELETE) ;                           /* type of access       */

    if (hService == NULL) {
        printf("cannot open service %s %d\n", SERVICENAME, GetLastError()) ;
        CloseServiceHandle(hSCManager) ;
        return ;
    }
    if (DeleteService(hService) == 0) {
        printf("cannot remove service %s %d\n", SERVICENAME, GetLastError()) ;
        CloseServiceHandle(hService)   ;
        CloseServiceHandle(hSCManager) ;
        return ;
    }

    CloseServiceHandle(hService)   ;
    CloseServiceHandle(hSCManager) ;

    printf("Removed Service %s\n", SERVICENAME) ;
}

#endif  /* WIN32 */
