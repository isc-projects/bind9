/*
 * encoding.c - get DNS/Local encodings
 *
 *      Software\\JPNIC\\MDN\\Where
 *                          \\Encoding
 *                          \\ConfFile
 *                          \\LogFile
 *                          \\PerProg\\<name>\\Where
 *                          \\PerProg\\<name>\\Encoding
 */

/*
 * Copyright (c) 2000,2001 Japan Network Information Center.
 * All rights reserved.
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
#include <ctype.h>

#include "jpnicmdn.h"

#define MDN_GLOBAL	1
#define MDN_PERPROG	2

/*
 * Registry of Encodings
 */

static  CHAR   MDNKEY_WRAPPER[] = "Software\\JPNIC\\MDN";
static  CHAR   MDNKEY_PERPROG[] = "Software\\JPNIC\\MDN\\PerProg";
static  CHAR   MDNVAL_WHERE[]   = "Where";
static  CHAR   MDNVAL_ENCODE[]  = "Encoding";
static  CHAR   MDNVAL_CONFFILE[]= "ConfFile";
static  CHAR   MDNVAL_LOGLVL[]  = "LogLevel";
static  CHAR   MDNVAL_LOGFILE[] = "LogFile";

static int	GetRegistry(HKEY top, const char *key, const char *name,
			    DWORD type, void *param, DWORD length);
static char	*GetPerProgKey(char *buf);
static int	GetIntFromRegistry(const char *name, int defvalue, int where);
static BOOL	GetStringFromRegistry(const char *name, PUCHAR result,
				      int where);

static int
GetRegistry(HKEY top, const char *key, const char *name, DWORD type,
	    void *param, DWORD length)
{
    LONG stat;
    HKEY hk;
    DWORD realtype;

    stat = RegOpenKeyEx(top, key, 0, KEY_READ, &hk);
    if (stat != ERROR_SUCCESS) {
	return 0;
    }

    stat = RegQueryValueEx(hk, (LPCTSTR)name, NULL,
			   &realtype, (LPBYTE)param, &length);

    RegCloseKey(hk);

    if (stat != ERROR_SUCCESS || realtype != type)
	return 0;

    return 1;
}

static char *
GetPerProgKey(char *buf)
{
    UCHAR exename[256];
    UCHAR prgname[256];
    PUCHAR p, last;

    GetModuleFileName(NULL, exename, 256);
     
    for (p = exename, last = NULL; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            last = p;
	}
    }
    if (last == NULL) {
        strcpy(prgname, exename);
    } else {
        strcpy(prgname, last + 1);
    }

    if ((p = strrchr(prgname, '.')) != NULL) {
        *p = '\0';
    }

    sprintf(buf, "%s\\%s", MDNKEY_PERPROG, prgname);
    return buf;
}

static int
GetIntFromRegistry(const char *name, int defvalue, int where)
{
    DWORD param;

    if (where & MDN_PERPROG) {
	/*
	 * First, try program specific setting.
	 */
	UCHAR keyname[256];

	(void)GetPerProgKey(keyname);

	/*
	 * Try HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE.
	 */
	if (GetRegistry(HKEY_CURRENT_USER, keyname, name,
			REG_DWORD, &param, sizeof(param))) {
	    return (int)param;
	}

	if (GetRegistry(HKEY_LOCAL_MACHINE, keyname, name,
			REG_DWORD, &param, sizeof(param))) {
	    return (int)param;
	}
    }

    if (where & MDN_GLOBAL) {
	/*
	 * Try global setting.
	 */
	if (GetRegistry(HKEY_CURRENT_USER, MDNKEY_WRAPPER, name,
			REG_DWORD, &param, sizeof(param))) {
	    return (int)param;
	}
	if (GetRegistry(HKEY_LOCAL_MACHINE, MDNKEY_WRAPPER, name,
			REG_DWORD, &param, sizeof(param))) {
	    return (int)param;
	}
    }

    /*
     * Not found.  Return default value.
     */
    return defvalue;
}

static BOOL
GetStringFromRegistry(const char *name, PUCHAR result, int where)
{
    UCHAR param[256];

    if (where & MDN_PERPROG) {
	/*
	 * First, try program specific setting.
	 */
	UCHAR keyname[256];

	(void)GetPerProgKey(keyname);

	/*
	 * Try HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE.
	 */
	if (GetRegistry(HKEY_CURRENT_USER, keyname, name,
			REG_SZ, param, sizeof(param))) {
	    strcpy(result, param);
	    return TRUE;
	}
	if (GetRegistry(HKEY_LOCAL_MACHINE, keyname, name,
			REG_SZ, param, sizeof(param))) {
	    strcpy(result, param);
	    return TRUE;
	}
    }

    if (where & MDN_GLOBAL) {
	/*
	 * Try global setting.
	 */
	if (GetRegistry(HKEY_CURRENT_USER, MDNKEY_WRAPPER, name,
			REG_SZ, param, sizeof(param))) {
	    strcpy(result, param);
	    return TRUE;
	}
	if (GetRegistry(HKEY_LOCAL_MACHINE, MDNKEY_WRAPPER, name,
			REG_SZ, param, sizeof(param))) {
	    strcpy(result, param);
	    return TRUE;
	}
    }

    /*
     * Not found.
     */
    return FALSE;
}

/*
 * mdnEncodeWhere - which module should convert domain name
 */

int     mdnEncodeWhere(void)
{
    int v;
    v = GetIntFromRegistry(MDNVAL_WHERE, MDN_ENCODE_ALWAYS,
			   MDN_GLOBAL|MDN_PERPROG);
    mdnLogPrintf(mdn_log_level_trace, "mdnEncodeWhere: %d\n", v);
    return v;
}

/*
 * mdnGetConfFile - refer to Configuration file
 */

BOOL    mdnGetConfFile(PUCHAR file)
{
    BOOL v;

    v = GetStringFromRegistry(MDNVAL_CONFFILE, file, MDN_GLOBAL);
    if (v == TRUE) {
	mdnLogPrintf(mdn_log_level_trace, "mdnGetConfFile: %s\n", file);
    } else {
	mdnLogPrintf(mdn_log_level_trace, "mdnGetConfFile: <none>\n");
    }
    return v;
}

/*
 * mdnGetLogFile - refer to log file
 */

BOOL    mdnGetLogFile(PUCHAR file)
{
    BOOL v;

    v = GetStringFromRegistry(MDNVAL_LOGFILE, file, MDN_GLOBAL);
    if (v == TRUE) {
	mdnLogPrintf(mdn_log_level_trace, "mdnGetLogFile: %s\n", file);
    } else {
	mdnLogPrintf(mdn_log_level_trace, "mdnGetLogFile: <none>\n");
    }
    return v;
}

/*
 * mdnGetPrgEncoding - refer to Program's Local Encoding
 *
 *      use program name as registry key
 */
 
BOOL    mdnGetPrgEncoding(PUCHAR enc)
{
    if (GetStringFromRegistry(MDNVAL_ENCODE, enc, MDN_PERPROG) != TRUE ||
	enc[0] == '\0') {
	sprintf(enc, "CP%d", GetACP());
    }
    mdnLogPrintf(mdn_log_level_trace, "mdnGetPrgEncoding: %s\n", enc);
    return TRUE;
}

/*
 * mdnGetLogLevel
 */

int     mdnGetLogLevel(void)
{
    int v;

    v = GetIntFromRegistry(MDNVAL_LOGLVL, 0, MDN_GLOBAL|MDN_PERPROG);
    mdnLogPrintf(mdn_log_level_trace, "mdnGetLogLevel: %d\n", v);
    return v;
}

