/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/* $Id: lwconfig.c,v 1.7 2007/12/14 01:40:42 marka Exp $ */

/*
 * We do this so that we may incorporate everything in the main routines
 * so that we can take advantage of the fixes and changes made there
 * without having to add them twice. We can then call the parse routine
 * if there is a resolv.conf file and fetch our own data from the
 * Windows environment otherwise.
 */

/*
 * Note that on Win32 there is normally no resolv.conf since all information
 * is stored in the registry. Therefore there is no ordering like the
 * contents of resolv.conf. Since the "search" or "domain" keyword, on
 * Win32 if a search list is found it is used, otherwise the domain name
 * is used since they are mutually exclusive. The search list can be entered
 * in the DNS tab of the "Advanced TCP/IP settings" window under the same place
 * that you add your nameserver list.
 */

#define lwres_conf_parse generic_lwres_conf_parse
#include "../lwconfig.c"
#undef lwres_conf_parse

#include <iphlpapi.h>

#define TCPIP_SUBKEY	\
	"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"

void
get_win32_searchlist(lwres_context_t *ctx) {
	HKEY hKey;
	BOOL keyFound = TRUE;
	char searchlist[MAX_PATH];
	DWORD searchlen = MAX_PATH;
	char *cp;
	lwres_conf_t *confdata;

	REQUIRE(ctx != NULL);
	confdata = &ctx->confdata;

	memset(searchlist, 0, MAX_PATH);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TCPIP_SUBKEY, 0, KEY_READ, &hKey)
		!= ERROR_SUCCESS)
		keyFound = FALSE;

	if (keyFound == TRUE) {
		/* Get the named directory */
		if (RegQueryValueEx(hKey, "SearchList", NULL, NULL,
			(LPBYTE)searchlist, &searchlen) != ERROR_SUCCESS)
			keyFound = FALSE;
		RegCloseKey(hKey);
	}

	confdata->searchnxt = 0;

	if (!keyFound)
		return;

	cp = strtok((char *)searchlist, ", \0");
	while (cp != NULL) {
		if (confdata->searchnxt == LWRES_CONFMAXSEARCH)
			break;
		if (strlen(cp) <= MAX_PATH && strlen(cp) > 0) {
			confdata->search[confdata->searchnxt] = lwres_strdup(ctx, cp);
			if (confdata->search[confdata->searchnxt] != NULL)
				confdata->searchnxt++;
		}
		cp = strtok(NULL, ", \0");
	}
}

lwres_result_t
lwres_conf_parse(lwres_context_t *ctx, const char *filename) {
	lwres_result_t ret;
	lwres_conf_t *confdata;
	FIXED_INFO * FixedInfo;
	ULONG    BufLen = sizeof(FIXED_INFO);
	DWORD    dwRetVal;
	IP_ADDR_STRING *pIPAddr;

	REQUIRE(ctx != NULL);
	confdata = &ctx->confdata;
	REQUIRE(confdata != NULL);

	/* Use the resolver if there is one */
	ret = generic_lwres_conf_parse(ctx, filename);
	if ((ret != LWRES_R_NOTFOUND && ret != LWRES_R_SUCCESS) ||
		(ret == LWRES_R_SUCCESS && confdata->nsnext > 0))
		return (ret);

	/*
	 * We didn't get any nameservers so we need to do this ourselves
	 */
	FixedInfo = (FIXED_INFO *) GlobalAlloc(GPTR, BufLen);
	dwRetVal = GetNetworkParams(FixedInfo, &BufLen);
	if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
		GlobalFree(FixedInfo);
		FixedInfo = GlobalAlloc(GPTR, BufLen);
		dwRetVal = GetNetworkParams(FixedInfo, &BufLen);
	}
	if (dwRetVal != ERROR_SUCCESS) {
		GlobalFree(FixedInfo);
		return (LWRES_R_FAILURE);
	}

	/* Get the search list from the registry */
	get_win32_searchlist(ctx);

	/* Use only if there is no search list */
	if (confdata->searchnxt == 0 && strlen(FixedInfo->DomainName) > 0) {
		confdata->domainname = lwres_strdup(ctx, FixedInfo->DomainName);
		if (confdata->domainname == NULL) {
			GlobalFree(FixedInfo);
			return (LWRES_R_FAILURE);
		}
	} else
		confdata->domainname = NULL;

	/* Get the list of nameservers */
	pIPAddr = &FixedInfo->DnsServerList;
	while (pIPAddr) {
		if (confdata->nsnext >= LWRES_CONFMAXNAMESERVERS)
			break;

		ret = lwres_create_addr(pIPAddr->IpAddress.String,
				&confdata->nameservers[confdata->nsnext++], 1);
		if (ret != LWRES_R_SUCCESS) {
			GlobalFree(FixedInfo);
			return (ret);
		}
		pIPAddr = pIPAddr ->Next;
	}

	GlobalFree(FixedInfo);
	return (LWRES_R_SUCCESS);
}
