#ifndef lint
static char *rcsid = "$Id: stub.c,v 1.1.2.1 2002/02/08 12:15:38 marka Exp $";
#endif

/*
 * Copyright (c) 2001 Japan Network Information Center.  All rights reserved.
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

#include <config.h>

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <mdn/logmacro.h>
#include <mdn/debug.h>

#include "stub.h"

typedef struct {
	const char *name;
	void *handle;
} shared_obj_t;

static shared_obj_t shobj[] = {
#ifdef SOPATH_LIBC
	{ SOPATH_LIBC },
#endif
#ifdef SOPATH_LIBNSL
	{ SOPATH_LIBNSL },
#endif
	{ NULL },
};

static void	*shared_obj_open(const char *path);
static void	*shared_obj_findsym(void *handle, const char *name);
static void	*shared_obj_findsymx(void *handle, const char *name);
static void	*get_func_addr(const char *name);

static void *
shared_obj_open(const char *path) {
#ifdef HAVE_DLOPEN
	return (dlopen(path, RTLD_LAZY));
#endif
	FATAL(("stub: no way to load shared object file\n"));
	return (NULL);
}

static void *
shared_obj_findsym(void *handle, const char *name) {
	char namebuf[100];
	void *addr;
	static int need_leading_underscore = -1;

	/* Prepend underscore. */
	namebuf[0] = '_';
	name = strcpy(namebuf + 1, name);

	if (need_leading_underscore < 0) {
		/* First try without one. */
		if ((addr = shared_obj_findsymx(handle, name + 1)) != NULL) {
			need_leading_underscore = 0;
			return (addr);
		}
		/* Then try with one. */
		if ((addr = shared_obj_findsymx(handle, name)) != NULL) {
			need_leading_underscore = 1;
			return (addr);
		}
	} else if (need_leading_underscore) {
		return (shared_obj_findsymx(handle, name));
	} else {
		return (shared_obj_findsymx(handle, name + 1));
	}
	return (NULL);
}
		
static void *
shared_obj_findsymx(void *handle, const char *name) {
#ifdef HAVE_DLSYM
	return (dlsym(handle, name));
#endif
	/* logging */
	FATAL(("stub: no way to get symbol address\n"));
	return (NULL);
}

static void *
get_func_addr(const char *name) {
	int i;

	for (i = 0; shobj[i].name != NULL; i++) {
		if (shobj[i].handle == NULL) {
			TRACE(("stub: loading %s\n", shobj[i].name));
			shobj[i].handle = shared_obj_open(shobj[i].name);
		}
		if (shobj[i].handle != NULL) {
			void *addr = shared_obj_findsym(shobj[i].handle, name);
			if (addr != NULL) {
				TRACE(("stub: %s found in %s\n",
				       name, shobj[i].name));
				return (addr);
			}
		}
	}
	TRACE(("stub: %s not found\n", name));
	return (NULL);
}

#ifdef HAVE_GETHOSTBYNAME
struct hostent *
mdn_stub_gethostbyname(const char *name) {
	static struct hostent *(*fp)(const char *name);

	if (fp == NULL)
		fp = get_func_addr("gethostbyname");
	if (fp != NULL)
		return ((*fp)(name));
	return (NULL);
}
#endif

#ifdef HAVE_GETHOSTBYNAME2
struct hostent *
mdn_stub_gethostbyname2(const char *name, int af) {
	static struct hostent *(*fp)(const char *name, int af);

	if (fp == NULL)
		fp = get_func_addr("gethostbyname2");
	if (fp != NULL)
		return ((*fp)(name, af));
	return (NULL);
}
#endif

#ifdef HAVE_GETHOSTBYADDR
struct hostent *
mdn_stub_gethostbyaddr(GHBA_ADDR_T addr, GHBA_ADDRLEN_T len, int type) {
	static struct hostent *(*fp)(GHBA_ADDR_T name,
				     GHBA_ADDRLEN_T len, int type);

	if (fp == NULL)
		fp = get_func_addr("gethostbyaddr");
	if (fp != NULL)
		return ((*fp)(addr, len, type));
	return (NULL);
}
#endif

#ifdef GETHOST_R_GLIBC_FLAVOR

#ifdef HAVE_GETHOSTBYNAME_R
int
mdn_stub_gethostbyname_r(const char *name, struct hostent *result,
			 char *buffer, size_t buflen,
			 struct hostent **rp, int *errp)
{
	static int (*fp)(const char *name, struct hostent *result,
			 char *buffer, size_t buflen,
			 struct hostent **rp, int *errp);

	if (fp == NULL)
		fp = get_func_addr("gethostbyname_r");
	if (fp != NULL)
		return ((*fp)(name, result, buffer, buflen, rp, errp));
	return (ENOENT);	/* ??? */
}
#endif

#ifdef HAVE_GETHOSTBYNAME2_R
int
mdn_stub_gethostbyname2_r(const char *name, int af, struct hostent *result,
			  char *buffer, size_t buflen,
			  struct hostent **rp, int *errp)
{
	static int (*fp)(const char *name, int af, struct hostent *result,
			 char *buffer, size_t buflen,
			 struct hostent **rp, int *errp);

	if (fp == NULL)
		fp = get_func_addr("gethostbyname2_r");
	if (fp != NULL)
		return ((*fp)(name, af, result, buffer, buflen, rp, errp));
	return (ENOENT);	/* ??? */
}
#endif

#ifdef HAVE_GETHOSTBYADDR_R
int
mdn_stub_gethostbyaddr_r(GHBA_ADDR_T addr, GHBA_ADDRLEN_T len, int type,
			 struct hostent *result, char *buffer,
			 size_t buflen, struct hostent **rp, int *errp)
{
	static int (*fp)(GHBA_ADDR_T addr, GHBA_ADDRLEN_T len, int type,
			 struct hostent *result, char *buffer,
			 size_t buflen, struct hostent **rp, int *errp);

	if (fp == NULL)
		fp = get_func_addr("gethostbyaddr_r");
	if (fp != NULL)
		return ((*fp)(addr, len, type, result,
			      buffer, buflen, rp, errp));
	return (ENOENT);	/* ??? */
}
#endif

#else /* GETHOST_R_GLIBC_FLAVOR */

#ifdef HAVE_GETHOSTBYNAME_R
struct hostent *
mdn_stub_gethostbyname_r(const char *name, struct hostent *result,
			 char *buffer, int buflen, int *errp)
{
	static struct hostent *(*fp)(const char *name, struct hostent *result,
				     char *buffer, int buflen, int *errp);

	if (fp == NULL)
		fp = get_func_addr("gethostbyname_r");
	if (fp != NULL)
		return ((*fp)(name, result, buffer, buflen, errp));
	return (NULL);
}
#endif

#ifdef HAVE_GETHOSTBYADDR_R
struct hostent *
mdn_stub_gethostbyaddr_r(GHBA_ADDR_T addr, int len, int type,
			 struct hostent *result, char *buffer,
			 int buflen, int *errp)
{
	static struct hostent *(*fp)(GHBA_ADDR_T addr, int len, int type,
				     struct hostent *result, char *buffer,
				     int buflen, int *errp);

	if (fp == NULL)
		fp = get_func_addr("gethostbyaddr_r");
	if (fp != NULL)
		return ((*fp)(addr, len, type, result, buffer, buflen, errp));
	return (NULL);
}
#endif

#endif /* GETHOST_R_GLIBC_FLAVOR */

#ifdef HAVE_GETIPNODEBYNAME
struct hostent *
mdn_stub_getipnodebyname(const char *name, int af, int flags, int *errp) {
	static struct hostent *(*fp)(const char *name, int af, int flags,
				     int *errp);

	if (fp == NULL)
		fp = get_func_addr("getipnodebyname");
	if (fp != NULL)
		return ((*fp)(name, af, flags, errp));
	return (NULL);
}
#endif

#ifdef HAVE_GETIPNODEBYADDR
struct hostent *
mdn_stub_getipnodebyaddr(const void *src, size_t len, int af, int *errp) {
	static struct hostent *(*fp)(const void *src, size_t len, int af,
				     int *errp);

	if (fp == NULL)
		fp = get_func_addr("getipnodebyaddr");
	if (fp != NULL)
		return ((*fp)(src, len, af, errp));
	return (NULL);
}
#endif

#ifdef HAVE_FREEHOSTENT
void
mdn_stub_freehostent(struct hostent *hp) {
	static void (*fp)(struct hostent *hp);

	if (fp == NULL)
		fp = get_func_addr("freehostent");
	if (fp != NULL)
		(*fp)(hp);
}
#endif

#ifdef HAVE_GETADDRINFO
int
mdn_stub_getaddrinfo(const char *nodename, const char *servname,
		     const struct addrinfo *hints, struct addrinfo **res)
{
	static int (*fp)(const char *nodename, const char *servname,
			 const struct addrinfo *hints, struct addrinfo **res);

	if (fp == NULL)
		fp = get_func_addr("getaddrinfo");
	if (fp != NULL)
		return ((*fp)(nodename, servname, hints, res));
	return (EAI_FAIL);
}
#endif

#ifdef HAVE_FREEADDRINFO
void
mdn_stub_freeaddrinfo(struct addrinfo *aip) {
	static void (*fp)(struct addrinfo *aip);

	if (fp == NULL)
		fp = get_func_addr("freeaddrinfo");
	if (fp != NULL)
		(*fp)(aip);
}
#endif

#ifdef HAVE_GETNAMEINFO
int
mdn_stub_getnameinfo(const struct sockaddr *sa, GNI_SALEN_T salen,
		     char *host, GNI_HOSTLEN_T hostlen,
		     char *serv, GNI_SERVLEN_T servlen, GNI_FLAGS_T flags) {
	static int (*fp)(const struct sockaddr *sa, GNI_SALEN_T salen,
			 char *host, GNI_HOSTLEN_T hostlen,
			 char *serv, GNI_SERVLEN_T servlen,
			 GNI_FLAGS_T flags);

	if (fp == NULL)
		fp = get_func_addr("getnameinfo");
	if (fp != NULL)
		return ((*fp)(sa, salen, host, hostlen, serv, servlen, flags));
	return (EAI_FAIL);
}
#endif
