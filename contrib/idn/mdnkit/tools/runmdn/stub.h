/* $Id: stub.h,v 1.1 2001/06/09 00:30:51 tale Exp $ */

#ifndef STUB_H
#define STUB_H

#ifdef HAVE_GETHOSTBYNAME
extern struct hostent *
mdn_stub_gethostbyname(const char *name);
#endif

#ifdef GETHOST_R_GLIBC_FLAVOR
#ifdef HAVE_GETHOSTBYNAME_R
extern int
mdn_stub_gethostbyname_r(const char *name, struct hostent *result,
			 char *buffer, size_t buflen,
			 struct hostent **rp, int *errp);
#endif
#else /* GETHOST_R_GLIBC_FLAVOR */
#ifdef HAVE_GETHOSTBYNAME_R
extern struct hostent *
mdn_stub_gethostbyname_r(const char *name, struct hostent *result,
			 char *buffer, int buflen, int *errp);
#endif
#endif /* GETHOST_R_GLIBC_FLAVOR */

#ifdef HAVE_GETHOSTBYNAME2
extern struct hostent *
mdn_stub_gethostbyname2(const char *name, int af);
#endif

#ifdef GETHOST_R_GLIBC_FLAVOR
#ifdef HAVE_GETHOSTBYNAME2_R
extern int
mdn_stub_gethostbyname2_r(const char *name, int af, struct hostent *result,
			  char *buffer, size_t buflen,
			  struct hostent **rp, int *errp);
#endif
#endif /* GETHOST_R_GLIBC_FLAVOR */

#ifdef HAVE_GETHOSTBYADDR
extern struct hostent *
mdn_stub_gethostbyaddr(const char *addr, GHBA_ADDRLEN_T len, int type);
#endif

#ifdef GETHOST_R_GLIBC_FLAVOR
#ifdef HAVE_GETHOSTBYADDR_R
extern int
mdn_stub_gethostbyaddr_r(const char *addr, GHBA_ADDRLEN_T len, int type,
			 struct hostent *result, char *buffer,
			 size_t buflen, struct hostent **rp, int *errp);
#endif
#else /* GETHOST_R_GLIBC_FLAVOR */
#ifdef HAVE_GETHOSTBYADDR_R
extern struct hostent *
mdn_stub_gethostbyaddr_r(const char *addr, GHBA_ADDRLEN_T len, int type,
			 struct hostent *result, char *buffer,
			 int buflen, int *errp);
#endif
#endif /* GETHOST_R_GLIBC_FLAVOR */

#ifdef HAVE_GETIPNODEBYNAME
extern struct hostent *
mdn_stub_getipnodebyname(const char *name, int af, int flags, int *errp);
#endif

#ifdef HAVE_GETIPNODEBYADDR
extern struct hostent *
mdn_stub_getipnodebyaddr(const void *src, size_t len, int af, int *errp);
#endif

#ifdef HAVE_FREEHOSTENT
extern void
mdn_stub_freehostent(struct hostent *hp);
#endif

#ifdef HAVE_GETADDRINFO
extern int
mdn_stub_getaddrinfo(const char *nodename, const char *servname,
		     const struct addrinfo *hints, struct addrinfo **res);
#endif

#ifdef HAVE_FREEADDRINFO
extern void
mdn_stub_freeaddrinfo(struct addrinfo *aip);
#endif

#ifdef HAVE_GETNAMEINFO
extern int
mdn_stub_getnameinfo(const struct sockaddr *sa, socklen_t salen,
		     char *host, size_t hostlen, char *serv, size_t servlen,
		     int flags);
#endif

#endif /* STUB_H */
