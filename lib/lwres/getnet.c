#include <isc/net.h>
#include <isc/util.h>

#include <lwres/netdb.h>
#include <stdio.h>

struct netent *
getnetbyname(const char *name) {

	/* XXX */
	UNUSED(name);
	return (NULL);
}

#ifdef ISC_LWRES_GETNETBYADDRINADDR
struct netent *
getnetbyaddr(in_addr_t net, int type) {

	if (type == AF_INET) 
		return (NULL);

	/* XXX */
	UNUSED(net);
	return (NULL);
}
#else
struct netent *
getnetbyaddr(unsigned long net, int type) {

	if (type == AF_INET) 
		return (NULL);

	/* XXX */
	UNUSED(net);
	return (NULL);
}
#endif

struct netent *
getnetent() {

	return (NULL);
}

#ifdef ISC_LWRES_SETNETENTINT
int
setnetent(int stayopen) {
	
	UNUSED(stayopen);
	/* empty */
	return (1);	/* success */
}
#else
void
setnetent(int stayopen) {
	
	UNUSED(stayopen);
	/* empty */
}
#endif

#ifdef ISC_LWRES_ENDNETENTINT
int
endnetent() {
	return (0);
}
#else
void
endnetent() {
	/* empty */
}
#endif

