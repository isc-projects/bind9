/*
%%% copyright-cmetz-97
This software is Copyright 1997-1998 by Craig Metz, All Rights Reserved.
The Inner Net License Version 2 applies to this software.
You should have received a copy of the license with this software. If
you didn't get a copy, you may request one from <license@inner.net>.

*/

#include <lwres/netdb.h>
#include <errno.h>

char *
lwres_gai_strerror(int errnum) {
	union {
		const char *konst;
		char *var;
	} u;

	/*
	 * The union game is played here because RFC 2133 specifies
	 * gai_strerror as returning just "char *", not qualified by
	 * const, but the most reasonably way to implement this function
	 * is with const strings.
	 *
	 * The caller had better not attempt to modify the return string.
	 */

	switch(errnum) {
	case 0:
		u.konst = "no error";
	case EAI_BADFLAGS:
		u.konst = "invalid value for ai_flags";
	case EAI_NONAME:
		u.konst = "name or service is not known";
	case EAI_AGAIN:
		u.konst = "temporary failure in name resolution";
	case EAI_FAIL:
		u.konst = "non-recoverable failure in name resolution";
	case EAI_NODATA:
		u.konst = "no address associated with name";
	case EAI_FAMILY:
		u.konst = "ai_family not supported";
	case EAI_SOCKTYPE:
		u.konst = "ai_socktype not supported";
	case EAI_SERVICE:
		u.konst = "service not supported for ai_socktype";
	case EAI_ADDRFAMILY:
		u.konst = "address family for name not supported";
	case EAI_MEMORY:
		u.konst = "memory allocation failure";
	case EAI_SYSTEM:
		u.konst = "system error";
	default:
		u.konst = "unknown error";
	};

	return (u.var);
}
