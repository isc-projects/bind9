/*
 * Copyright (C) 1999  Internet Software Consortium.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <net/if.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <isc/assertions.h>
#include <isc/error.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/interfaceiter.h>

#define IFITER_MAGIC		0x49464954U	/* IFIT. */	
#define VALID_IFITER(t)		((t) != NULL && (t)->magic == IFITER_MAGIC)

struct isc_interfaceiter {
	unsigned int		magic;		/* Magic number. */
	isc_mem_t		*mctx;
	int			socket;
	struct ifconf 		ifc;
	unsigned int		bufsize;
	unsigned int		pos;		/* Current offset in
						   SIOGCONF data */
	isc_interface_t		current;	/* Current interface data. */
	isc_result_t		result;		/* Last result code. */
};


/*
 * Size of buffer for SIOCGIFCONF, in bytes.  We assume no sane system
 * will have more than a megabyte of interface configuration data.
 */
#define IFCONF_BUFSIZE_INITIAL	4096
#define IFCONF_BUFSIZE_MAX	1048576

isc_result_t
isc_interfaceiter_create(isc_mem_t *mctx, isc_interfaceiter_t **iterp)
{
	isc_interfaceiter_t *iter;
	isc_result_t result;
	char *buf;
	REQUIRE(mctx != NULL);
	REQUIRE(iterp != NULL);
	REQUIRE(*iterp == NULL);
	
	iter = isc_mem_get(mctx, sizeof(*iter));
	if (iter == NULL)
		return (ISC_R_NOMEMORY);

	iter->mctx = mctx;

	/* Create an unbound datagram socket to do the SIOCGIFADDR ioctl on. */
	if ((iter->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "making interface scan socket: %s",
				 strerror(errno));
		result = ISC_R_UNEXPECTED;
		goto socket_failure;
	}
	
	/*
	 * Get the interface configuration, allocating more memory if
	 * necessary.
	 */
	iter->bufsize = IFCONF_BUFSIZE_INITIAL;

	for (;;) {
		buf = isc_mem_get(mctx, iter->bufsize);
		if (buf == NULL) {
			result = ISC_R_NOMEMORY;
			goto alloc_failure;
		}
		
		iter->ifc.ifc_len = iter->bufsize;
		iter->ifc.ifc_buf = buf;
		if (ioctl(iter->socket, SIOCGIFCONF, (char *) &iter->ifc) >= 0)
			break;
		if (errno != EINVAL) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "get interface configuration: %s",
					 strerror(errno));
			result = ISC_R_UNEXPECTED;
			goto ioctl_failure;
		}

		if (iter->bufsize >= IFCONF_BUFSIZE_MAX) {
			UNEXPECTED_ERROR(__FILE__, __LINE__, 
					 "get interface configuration: "
					 "maximum buffer size exceeded");
			result = ISC_R_UNEXPECTED;
			goto ioctl_failure;
		}
		isc_mem_put(mctx, buf, iter->bufsize);
		
		iter->bufsize *= 2;
	}

	/*
	 * A newly created iterator has an undefined position
	 * until isc_interfaceiter_first() is called.
	 */
	iter->pos = (unsigned int) -1;
	iter->result = ISC_R_FAILURE;
	
	iter->magic = IFITER_MAGIC;
	*iterp = iter;
	return (ISC_R_SUCCESS);

 ioctl_failure:
	isc_mem_put(mctx, buf, iter->bufsize);

 alloc_failure:
	(void) close(iter->socket);
	
 socket_failure:
	isc_mem_put(mctx, iter, sizeof *iter);
	return (result);
}

/*
 * Extract the network address part from a "struct sockaddr".
 * 
 * The address family is given explicity
 * instead of using src->sa_family, because the latter does not work
 * for copying a network mask obtained by SIOCGIFNETMASK (it does
 * not have a valid address family).
 */

static void 
get_addr(int family, isc_netaddr_t *dst, struct sockaddr *src) {
	switch (family) {
	case AF_INET:
		memcpy(&dst->type.in,
		       &((struct sockaddr_in *) src)->sin_addr,
		       sizeof(struct in_addr));
		break;
	/* XXX IPv6 */
	default:
		INSIST(0);
		break;
	}
}
	       
/*
 * Get information about the current interface to iter->current.
 * If successful, return ISC_R_SUCCESS.
 * If the interface has an unsupported address family,
 * return ISC_R_FAILURE.  In case of other failure,
 * return ISC_R_UNEXPECTED.
 */

static isc_result_t
internal_current(isc_interfaceiter_t *iter) {
	struct ifreq *ifrp;
	struct ifreq ifreq;
	int family;
	
	REQUIRE(VALID_IFITER(iter));
	REQUIRE (iter->pos < (unsigned int) iter->ifc.ifc_len);
	
	ifrp = (struct ifreq *)((char *) iter->ifc.ifc_req + iter->pos);
	
	memcpy(&ifreq, ifrp, sizeof ifreq);

	family = ifreq.ifr_addr.sa_family;
	if (family != AF_INET) /* XXX IPv6 */	
		return (ISC_R_FAILURE); 
	
	memset(&iter->current, 0, sizeof(iter->current));
	
	INSIST(sizeof(ifreq.ifr_name) <= sizeof(iter->current.name));
	memcpy(iter->current.name, ifreq.ifr_name, sizeof(ifreq.ifr_name));
	
	get_addr(family, &iter->current.address, &ifreq.ifr_addr);

	/* Get interface flags. */

	iter->current.flags = 0;
	
	if (ioctl(iter->socket, SIOCGIFFLAGS, (char *) &ifreq) < 0) {
		UNEXPECTED_ERROR(__FILE__, __LINE__, 
				 "%s: getting interface flags: %s",
				 ifreq.ifr_name,
				 strerror(errno));
		return (ISC_R_UNEXPECTED);
	}
	
	if ((ifreq.ifr_flags & IFF_UP) != 0)
		iter->current.flags |= INTERFACE_F_UP;

	if ((ifreq.ifr_flags & IFF_POINTOPOINT) != 0)
		iter->current.flags |= INTERFACE_F_POINTTOPOINT;

	if ((ifreq.ifr_flags & IFF_LOOPBACK) != 0)
		iter->current.flags |= INTERFACE_F_LOOPBACK;

	/*
	 * If point-to-point, get the destination address;
	 * otherwise, get the network mask.
	 */
	if ((iter->current.flags & INTERFACE_F_POINTTOPOINT) != 0) {
		if (ioctl(iter->socket, SIOCGIFDSTADDR, (char *) &ifreq) < 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__, 
					 "%s: getting destination address: %s",
					 ifreq.ifr_name,
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
		get_addr(family, &iter->current.dstaddress,
			 &ifreq.ifr_dstaddr);
	} else {
		if (ioctl(iter->socket, SIOCGIFNETMASK, (char *) &ifreq) < 0) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "%s: getting netmask: %s",
					 ifreq.ifr_name,
					 strerror(errno));
			return (ISC_R_UNEXPECTED);
		}
		get_addr(family, &iter->current.netmask,
			 &ifreq.ifr_addr);		
	}
	
	return (ISC_R_SUCCESS);
}

/*
 * Step the iterator to the next interface.  Unlike 
 * isc_interfaceiter_next(), this may leave the iterator
 * positioned on an interface that will ultimately
 * be ignored.  Return ISC_R_NOMORE if there are no more
 * interfaces, otherwise ISC_R_SUCCESS.
 */
static isc_result_t
internal_next(isc_interfaceiter_t *iter) {
	struct ifreq *ifrp;

	REQUIRE (iter->pos < (unsigned int) iter->ifc.ifc_len);
	
	ifrp = (struct ifreq *)((char *) iter->ifc.ifc_req + iter->pos);
		
#ifdef ISC_NET_HAVESALEN
	if (ifrp->ifr_addr.sa_len > sizeof(struct sockaddr))
		iter->pos += sizeof(ifrp->ifr_name) + ifrp->ifr_addr.sa_len;
	else
#endif
		iter->pos += sizeof *ifrp;

	if (iter->pos >= (unsigned int) iter->ifc.ifc_len)
		return (ISC_R_NOMORE);
	
	return (ISC_R_SUCCESS);
}


isc_result_t
isc_interfaceiter_current(isc_interfaceiter_t *iter,
			  isc_interface_t *ifdata)
{
	REQUIRE(iter->result == ISC_R_SUCCESS);
	memcpy(ifdata, &iter->current, sizeof(*ifdata));
	return ISC_R_SUCCESS;
}

/*
 * Position the iterator on the first user-visible interface.
 */
isc_result_t
isc_interfaceiter_first(isc_interfaceiter_t *iter) {
	isc_result_t result;

	REQUIRE(VALID_IFITER(iter));	

	iter->pos = 0;
	for (;;) {
		result = internal_current(iter);
		if (result == ISC_R_SUCCESS)
			break;
		result = internal_next(iter);
		if (result == ISC_R_NOMORE)
			break;
		INSIST(result == ISC_R_SUCCESS);
	}
	iter->result = result;
	return (result);
}

/*
 * Position the iterator on the next user-visible interface.
 */
isc_result_t
isc_interfaceiter_next(isc_interfaceiter_t *iter) {
	isc_result_t result;
		
	REQUIRE(VALID_IFITER(iter));
	REQUIRE(iter->result == ISC_R_SUCCESS);

	for (;;) {
		result = internal_next(iter);
		if (result == ISC_R_NOMORE)
			break;
		INSIST(result == ISC_R_SUCCESS);
		result = internal_current(iter);
		if (result == ISC_R_SUCCESS)
			break;
	}
	iter->result = result;
	return (result);
}

void
isc_interfaceiter_destroy(isc_interfaceiter_t **iterp)
{
	isc_interfaceiter_t *iter;
	REQUIRE(iterp != NULL);
	iter = *iterp;
	REQUIRE(VALID_IFITER(iter));

	(void) close(iter->socket);
	isc_mem_put(iter->mctx, iter->ifc.ifc_buf, iter->bufsize);

	iter->magic = 0;
	isc_mem_put(iter->mctx, iter, sizeof *iter);
	*iterp = NULL;
}
