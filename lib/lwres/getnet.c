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

struct netent *
getnetbyname_r(const char *name, struct netent *resbuf, char *buf,
	       int buflen)
{
	return (NULL);
}

struct netent *
getnetbyaddr_r(long addr, int type, struct netent *resbuf, char *buf,
	       int buflen)
{
	return (NULL);
}

struct netent *
getnetent_r(struct netent *resbuf, char *buf, int buflen) {
	return (NULL);
}

void
setnetent_r(int stayopen) {
	(void)stayopen;
}

void
endnetent_r(void) {
	/* empty */
}
