#include <isc/net.h>
#include <isc/util.h>

#include <netdb.h>
#include <stdio.h>

struct netent *
getnetbyname(const char *name) {

	/* XXX */
	UNUSED(name);
	return (NULL);
}

struct netent *
getnetbyaddr(unsigned long net, int type) {

	if (type == AF_INET) 
		return (NULL);

	/* XXX */
	UNUSED(net);
	return (NULL);
}

struct netent *
getnetent() {

	return (NULL);
}

void
setnetent(int stayopen) {
	
	UNUSED(stayopen);
	/* empty */
}

void
endnetent() {
	/* empty */
}

