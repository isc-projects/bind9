#include <isc/net.h>
#include <netdb.h>
#include <stdio.h>

struct hostent *
getipnodebyname(const char *name, int af, int flags, int *error_num);
struct hostent *
getipnodebyaddr(const void *src, size_t len, int af, int *error_num);

static struct hostent *he;

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
