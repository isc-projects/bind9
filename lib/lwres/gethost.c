#include <isc/net.h>
#include <lwres/netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define LWRES_ALIGNBYTES (sizeof(char *) - 1)
#define LWRES_ALIGN(p) \
	(((unsigned int)(p) + LWRES_ALIGNBYTES) &~ LWRES_ALIGNBYTES)

static struct hostent *he = NULL;
static int copytobuf(struct hostent *, struct hostent *, char *, int);

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
gethostbyname2(const char *name, int af) {
	int error;

	if (he != NULL)
		freehostent(he);

	he = getipnodebyname(name, af, 0, &error);
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
	(void)stayopen;
}

void
endhostent(void) {
	/* empty */
}

struct hostent *
gethostbyname_r(const char *name, struct hostent *resbuf,
		char *buf, int buflen, int *error) {
	struct hostent *he;
	int res;

	he = getipnodebyname(name, AF_INET, 0, error);
	if (he == NULL)
		return (NULL);
	res = copytobuf(he, resbuf, buf, buflen);
	if (he != NULL)
		freehostent(he);
	if (res != 0) {
		errno = ERANGE;
		return (NULL);
	}
	return (resbuf);
}

struct hostent  *
gethostbyaddr_r(const char *addr, int len, int type, struct hostent *resbuf,
		char *buf, int buflen, int *error) {
	struct hostent *he;
	int res;

	he = getipnodebyaddr(addr, len, type, error);
	if (he == NULL)
		return (NULL);
	res = copytobuf(he, resbuf, buf, buflen);
	if (he != NULL)
		freehostent(he);
	if (res != 0) {
		errno = ERANGE;
		return (NULL);
	}
	return (resbuf);
}

struct hostent  *
gethostent_r(struct hostent *resbuf, char *buf, int buflen, int *error) {
	(void)resbuf;
	(void)buf;
	(void)buflen;
	*error = 0;
	return (NULL);
}

void
sethostent_r(int stayopen) {
	(void)stayopen;
	/* empty */
}

void
endhostent_r(void) {
	/* empty */
}

static int
copytobuf(struct hostent *he, struct hostent *hptr, char *buf, int buflen) {
        char *cp;
        char **ptr;
        int i, n;
        int nptr, len;

        /* Find out the amount of space required to store the answer. */
        nptr = 2; /* NULL ptrs */
        len = (char *)LWRES_ALIGN(buf) - buf;
        for (i = 0; he->h_addr_list[i]; i++, nptr++) {
                len += he->h_length;
        }
        for (i = 0; he->h_aliases[i]; i++, nptr++) {
                len += strlen(he->h_aliases[i]) + 1;
        }
        len += strlen(he->h_name) + 1;
        len += nptr * sizeof(char*);
        
        if (len > buflen) {
                return (-1);
        }

        /* copy address size and type */
        hptr->h_addrtype = he->h_addrtype;
        n = hptr->h_length = he->h_length;

        ptr = (char **)LWRES_ALIGN(buf);
        cp = (char *)LWRES_ALIGN(buf) + nptr * sizeof(char *);

        /* copy address list */
        hptr->h_addr_list = ptr;
        for (i = 0; he->h_addr_list[i]; i++ , ptr++) {
                memcpy(cp, he->h_addr_list[i], n);
                hptr->h_addr_list[i] = cp;
                cp += n;
                i++;
        }
        hptr->h_addr_list[i] = NULL;
        ptr++;

        /* copy official name */
        n = strlen(he->h_name) + 1;
        strcpy(cp, he->h_name);
        hptr->h_name = cp;
        cp += n;

        /* copy aliases */
        hptr->h_aliases = ptr;
        for (i = 0 ; he->h_aliases[i]; i++) {
                n = strlen(he->h_aliases[i]) + 1;
                strcpy(cp, he->h_aliases[i]);
                hptr->h_aliases[i] = cp;
                cp += n;
        }
        hptr->h_aliases[i] = NULL;

        return (0);
}
