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

struct hostent *
gethostbyaddr(const char *addr, int len, int type) {
	int error;

	if (he != NULL) 
		freehostent(he);

	he = getipnodebyaddr(addr, len, type, &error);
	h_errno = error;
	return (he);
}

struct hostent *
gethostent(void) {

	if (he != NULL)
		freehostent(he);

	return (NULL);
}

void
sethostent(int stayopen) {
	/* empty */
}

void
endhostent(void) {
	/* empty */
}
