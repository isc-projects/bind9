/*
 * hook.c - Hooking Asynchronous Completion
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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jpnicmdn.h"

/*
 * Hook Managements
 */

static  HHOOK   hookHandle = NULL ;

typedef struct _HOOK    *HOOKPTR ;

typedef struct _HOOK {
    HOOKPTR     prev  ;
    HOOKPTR     next  ;
    CONVPTR     pCnv  ;
    HWND        hWnd  ;
    u_int       wMsg  ;
    char FAR    *pBuf ;
} HOOKREC ;

static  HOOKREC hookList = { 0 } ;

static  void    hookListInit(void)
{
    if (hookList.prev == NULL || hookList.next == NULL) {
        hookList.prev = &hookList ;
        hookList.next = &hookList ;
    }
}

static  HOOKPTR hookListSearch(HWND hWnd, u_int wMsg)
{
    HOOKPTR hp ;
    
    for (hp = hookList.next ; hp != &hookList ; hp = hp->next) {
        if (hp->hWnd == hWnd && hp->wMsg == wMsg) {
	    return hp ;
	}
    }
    return NULL ;
}

static  BOOL    hookListAppend(HWND hWnd, u_int wMsg, char FAR *buf, CONVPTR pConv)
{
    HOOKPTR hp, prev, next ;
    
    if ((hp = (HOOKPTR) malloc(sizeof(HOOKREC))) == NULL) {
        mdnPrintf("cannot create hook record\n") ;
        return FALSE ;
    }
    memset(hp, 0, sizeof(HOOKREC)) ;
    
    hp->pCnv = pConv ;
    hp->hWnd = hWnd  ;
    hp->wMsg = wMsg  ;
    hp->pBuf = buf   ;
    
    prev = hookList.prev ;
    next = prev->next    ;
    prev->next = hp ;
    next->prev = hp ;
    hp->next = next ;
    hp->prev = prev ;    

    return TRUE ;
}

static  void    hookListDelete(HOOKPTR hp)
{
    HOOKPTR prev, next ;
    
    prev = hp->prev ;
    next = hp->next ;
    prev->next = next ;
    next->prev = prev ;
    
    free(hp) ;
}

static  void    hookListDone(void)
{
    HOOKPTR hp ;
    
    while ((hp = hookList.next) != &hookList) {
        hookListDelete(hp) ;
    }
}

/*
 * mdnHookInit - initialize Hook Management
 */

void    mdnHookInit(void)
{
    hookListInit() ;
}

/*
 * mdnHookDone - finalize Hook Management
 */

void    mdnHookDone(void)
{
    if (hookHandle != NULL) {
        UnhookWindowsHookEx(hookHandle) ;
	hookHandle = NULL ;
    }
    hookListDone() ;
}

/*
 * hookProc - hookprocedure, used as WH_GETMESSAGE hook
 */

LRESULT CALLBACK    hookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    MSG             *pMsg  ;
    HOOKPTR         pHook  ;
    struct  hostent *pHost ;
    char            nbuff[256] ;
    char            hbuff[256] ;
    
    if (nCode < 0) {
        return CallNextHookEx(hookHandle, nCode, wParam, lParam) ;
    }
    if (nCode != HC_ACTION) {
        return 0 ;
    }
    if ((pMsg = (MSG *) lParam) == NULL) {
        return 0 ;
    }
    if ((pHook = hookListSearch(pMsg->hwnd, pMsg->message)) == NULL) {
        return 0 ;
    }
    
    /*
     * Convert the Host Name
     */
     
    pHost = (struct hostent *) pHook->pBuf ;

    mdnPrintf("AsyncComplete Resulting <%s>\n", dumpName(pHost->h_name, hbuff)) ;
    mdnConvRsp(pHook->pCnv, pHost->h_name, nbuff, sizeof(nbuff)) ;
    mdnPrintf("AsyncComplete Converted <%s>\n", dumpName(nbuff, hbuff)) ;
    strcpy(pHost->h_name, nbuff) ;

    /*
     * Delete target
     */

    hookListDelete(pHook) ;

    return 0 ;
}

/*
 * mdnHook - hook async. completion message
 */

BOOL    mdnHook(HWND hWnd, u_int wMsg, char FAR *buf, CONVPTR pConv)
{
    if (hookHandle == NULL) {
        hookHandle = SetWindowsHookEx(WH_GETMESSAGE, hookProc, NULL, GetCurrentThreadId()) ;
    }
    if (hookHandle == NULL) {
        mdnPrintf("mdnHook: cannot set hook\n") ;
        return FALSE ;
    }
    if (hookListAppend(hWnd, wMsg, buf, pConv) != TRUE) {
        return FALSE ;
    }
    return TRUE ;
}
