#include <isc/net.h>
#include <lwres/netdb.h>
#include <stdio.h>

static struct hostent *he = NULL;

struct hostent *
gethostbyname(const char *name) {
	int error;

	if (he != NULL)
		freehostent(he);

	he = getipnodebyname(name, AF_INET, 0, &error);
	h_errno = error;
	return (he);
}

#ifdef ISC_LWRES_GETHOSTBYADDRVOID
struct hostent *
gethostbyaddr(const void *addr, int len, int type) {
	int error;

	if (he != NULL) 
		freehostent(he);

	he = getipnodebyaddr(addr, len, type, &error);
	h_errno = error;
	return (he);
}
#else
struct hostent *
gethostbyaddr(const char *addr, int len, int type) {
	int error;

	if (he != NULL) 
		freehostent(he);

	he = getipnodebyaddr(addr, len, type, &error);
	h_errno = error;
	return (he);
}
#endif

struct hostent *
gethostent(void) {

	if (he != NULL)
		freehostent(he);

	return (NULL);
}

#ifdef ISC_LWRES_SETHOSTENTINT
int
sethostent(int stayopen) {
	(void)stayopen;
	return (0);
}
#else
void
sethostent(int stayopen) {
	/* empty */
	(void)stayopen;
}
#endif

#ifdef ISC_LWRES_ENDHOSTENTINT
int
endhostent(void) {
	return(0);
}
#else
void
endhostent(void) {
	/* empty */
}
#endif
