/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: fsaccess.c,v 1.5.4.1 2001/01/09 22:51:48 bwelling Exp $ */

#include <windows.h>
#include <winerror.h>
#include <aclapi.h>

/*
 * This file is entirely theoretical.  It has never been compiled or tested.
 * At the very least, even if this is all perfect (HAH!), isc__winerror2result
 * needs to be written.
 */

/*
 * The OS-independent part of the API is in lib/isc.
 */
#include "../fsaccess.c"

isc_result_t
isc_fsaccess_set(const char *path, isc_fsaccess_t access) {
	isc_result_t result;
	isc_fsaccess_t bits, mask;
	isc_boolean_t is_dir = ISC_FALSE;
	int i;
	DWORD winerror;
	PACL dacl;
	PSID psid[3];
#define owner psid[0]
#define group psid[1]
#define world psid[2]
	PSECURITY_DESCRIPTOR sd;
	EXPLICIT_ACCESS ea[3], *pea;
	TRUSTEETYPE trustee_type[3] = {
		TRUSTEE_IS_USER, TRUSTEE_IS_GROUP, TRUSTEE_IS_WELL_KNOWN_GROUP
	};

	owner = group = world = dacl = sd = NULL;

	/* XXXDCL -- NEED TO SET is_dir! Maybe use stat; what is native way? */
	result = check_bad_bits(access, is_dir);
	if (result != ISC_R_SUCCESS)
		return (result);

	winerror = GetNamedSecurityInfo(path, SE_FILE_OBJECT,
					OWNER_SECURITY_INFORMATION |
					GROUP_SECURITY_INFORMATION,
					&owner, &group, NULL, NULL, &sd);
	/*
	 * "ERROR_SUCCESS".  Heh heh heh.
	 */
	if (winerror != ERROR_SUCCESS)
		return (isc__winerror2result(winerror));

	ZeroMemory(&ea, sizeof(ea));
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;

	/*
	 * Make a mask for the number of bits per owner/group/other.
	 */
	for (i = mask = 0; i < ISC__FSACCESS_PERMISSIONBITS; i++) {
		mask <<= 1;
		mask |= 1;
	}

#define MAP(isc, win32) \
	if ((bits & (isc)) != 0) { \
		ea.grfAccessPermissions |= (win32); \
		 bits &= ~(isc); \
	}

	for (i = 0; i < 2; i++) {
		bits = access & mask;

		pea = &ea[i];

		pea->grfAccessPermissions =
			SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES;
		if (i == 0)
			/*
			 * Owner-only permissions.
			 */
			pea->grfAccessPermissions |= WRITE_DAC | DELETE;

		/*
		 * File access rights.
		 */
		MAP(ISC_FSACCESS_READ, FILE_READ_DATA | FILE_READ_EA);
		MAP(ISC_FSACCESS_WRITE,
		    FILE_WRITE_DATA | FILE_WRITE_EA | FILE_APPEND_DATA);
		MAP(ISC_FSACCESS_EXECUTE, FILE_EXECUTE);

		/*
		 * Directory access rights.
		 */
		MAP(ISC_FSACCESS_LISTDIRECTORY, FILE_LIST_DIRECTORY);
		MAP(ISC_FSACCESS_CREATECHILD, FILE_CREATE_CHILD);
		MAP(ISC_FSACCESS_DELETECHILD, FILE_DELETE_CHILD);
		MAP(ISC_FSACCESS_ACCESSCHILD, FILE_TRAVERSE);

		/*
		 * Ensure no other bits were set.
		 */
		INSIST(bits == 0);

 		if (i == 2) {
			/*
			 * Setting world.
			 */
			SID_IDENTIFIER_AUTHORITY authworld =
				SECURITY_WORLD_SID_AUTHORITY;

			if (AllocateAndInitializeSid(&authworld, 1,
						     SECURITY_WORLD_RID,
						     0, 0, 0, 0, 0, 0, 0,
						     &world)
			    == 0)
				winerror = GetLastError();
			else
				/*
				 * This should already be ERROR_SUCCESS.
				 */
				ENSURE(winerror == ERROR_SUCCESS);

		}

		if (winerror == ERROR_SUCCESS) {
			BuildTrusteeWithSid(&pea->Trustee, psid[i]);
			pea->Trustee.Trusteetype = trustee_type[i];

			winerror = SetEntriesInAcl(3, ea, NULL, &dacl);
		}

		if (winerror == ERROR_SUCCESS)
			winerror =
				SetNamedSecurityInfo(path, SE_FILE_OBJECT,
						     DACL_SECURITY_INFORMATION,
						     NULL, NULL, dacl, NULL);

		if (winerror == ERROR_SUCCESS)
			access >> shift;
		else
			break;
	}

	if (sd != NULL)
		LocalFree(sd);
	if (dacl != NULL)
		LocalFree(dacl);
	if (world != NULL)
		FreeSid(world);

	if (winerror == ERROR_SUCCESS) {
		/*
		 * Ensure no other bits were set.
		 */
		INSIST(access == 0);

		return (ISC_R_SUCCESS);
	} else
		return (isc__winerror2result(winerror));
}
