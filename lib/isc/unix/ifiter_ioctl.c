/*
 * Copyright (C) 1999-2001, 2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: ifiter_ioctl.c,v 1.19.2.5.2.5 2003/10/07 03:28:37 marka Exp $ */

/*
 * Obtain the list of network interfaces using the SIOCGLIFCONF ioctl.
 * See netintro(4).
 */

#if defined(SIOCGLIFCONF) && defined(SIOCGLIFADDR)
#ifdef ISC_PLATFORM_HAVEIF_LADDRCONF
#define lifc_len iflc_len
#define lifc_buf iflc_buf
#define lifc_req iflc_req
#define LIFCONF if_laddrconf
#else
#define ISC_HAVE_LIFC_FAMILY 1
#define ISC_HAVE_LIFC_FLAGS 1
#define LIFCONF lifconf
#endif

#ifdef ISC_PLATFORM_HAVEIF_LADDRREQ
#define lifr_addr iflr_addr
#define lifr_name iflr_name
#define lifr_dstaddr iflr_dstaddr
#define lifr_flags iflr_flags
#define ss_family sa_family
#define LIFREQ if_laddrreq
#else
#define LIFREQ lifreq
#endif
#endif

#define IFITER_MAGIC		ISC_MAGIC('I', 'F', 'I', 'T')
#define VALID_IFITER(t)		ISC_MAGIC_VALID(t, IFITER_MAGIC)

#define ISC_IF_INET6_SZ \
	 sizeof("00000000000000000000000000000001 01 80 10 80       lo\n")

struct isc_interfaceiter {
	unsigned int		magic;		/* Magic number. */
	isc_mem_t		*mctx;
	int			socket;
	int			mode;
	struct ifconf 		ifc;
#if defined(SIOCGLIFCONF) && defined(SIOCGLIFADDR)
	struct LIFCONF 		lifc;
#endif
	void			*buf;		/* Buffer for sysctl data. */
	unsigned int		bufsize;	/* Bytes allocated. */
#ifdef HAVE_TRUCLUSTER
	int			clua_context;	/* Cluster alias context */
#endif
#ifdef	__linux
	FILE *			proc;
	char			entry[ISC_IF_INET6_SZ];
	isc_result_t		valid;
	isc_boolean_t		first;
#endif
	unsigned int		pos;		/* Current offset in
						   SIOCGLIFCONF data */
	isc_interface_t		current;	/* Current interface data. */
	isc_result_t		result;		/* Last result code. */
};

#ifdef HAVE_TRUCLUSTER
#include <clua/clua.h>
#include <sys/socket.h>
#endif


/*
 * Size of buffer for SIOCGLIFCONF, in bytes.  We assume no sane system
 * will have more than a megabyte of interface configuration data.
 */
#define IFCONF_BUFSIZE_INITIAL	4096
#define IFCONF_BUFSIZE_MAX	1048576

static isc_result_t
getbuf4(isc_interfaceiter_t *iter) {
	char strbuf[ISC_STRERRORSIZE];

	iter->bufsize = IFCONF_BUFSIZE_INITIAL;

	for (;;) {
		iter->buf = isc_mem_get(iter->mctx, iter->bufsize);
		if (iter->buf == NULL)
			return (ISC_R_NOMEMORY);

		memset(&iter->ifc.ifc_len, 0, sizeof(iter->ifc.ifc_len));
		iter->ifc.ifc_len = iter->bufsize;
		iter->ifc.ifc_buf = iter->buf;
		/*
		 * Ignore the HP/UX warning about "interger overflow during
		 * conversion".  It comes from its own macro definition,
		 * and is really hard to shut up.
		 */
		if (ioctl(iter->socket, SIOCGIFCONF, (char *)&iter->ifc)
		    == -1) {
			if (errno != EINVAL) {
				isc__strerror(errno, strbuf, sizeof(strbuf));
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_IFITERIOCTL,
							ISC_MSG_GETIFCONFIG,
							"get interface "
							"configuration: %s"),
						 strbuf);
				goto unexpected;
			}
			/*
			 * EINVAL.  Retry with a bigger buffer.
			 */
		} else {
			/*
			 * The ioctl succeeded.
			 * Some OS's just return what will fit rather
			 * than set EINVAL if the buffer is too small
			 * to fit all the interfaces in.  If
			 * ifc.lifc_len is too near to the end of the
			 * buffer we will grow it just in case and
			 * retry.
			 */
			if (iter->ifc.ifc_len + 2 * sizeof(struct ifreq)
			    < iter->bufsize)
				break;
		}
		if (iter->bufsize >= IFCONF_BUFSIZE_MAX) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_IFITERIOCTL,
							ISC_MSG_BUFFERMAX,
							"get interface "
							"configuration: "
							"maximum buffer "
							"size exceeded"));
			goto unexpected;
		}
		isc_mem_put(iter->mctx, iter->buf, iter->bufsize);

		iter->bufsize *= 2;
	}
	iter->mode = 4;
	return (ISC_R_SUCCESS);

 unexpected:
	isc_mem_put(iter->mctx, iter->buf, iter->bufsize);
	iter->buf = NULL;
	return (ISC_R_UNEXPECTED);
}

static isc_result_t
getbuf6(isc_interfaceiter_t *iter) {
#if !defined(SIOCGLIFCONF) || !defined(SIOCGLIFADDR)
	UNUSED(iter);
	return (ISC_R_NOTIMPLEMENTED);
#else
	char strbuf[ISC_STRERRORSIZE];
	isc_result_t result;

	iter->bufsize = IFCONF_BUFSIZE_INITIAL;

	for (;;) {
		iter->buf = isc_mem_get(iter->mctx, iter->bufsize);
		if (iter->buf == NULL)
			return (ISC_R_NOMEMORY);

		memset(&iter->lifc, 0, sizeof(iter->lifc));
#ifdef ISC_HAVE_LIFC_FAMILY
		iter->lifc.lifc_family = AF_UNSPEC;
#endif
#ifdef ISC_HAVE_LIFC_FLAGS
		iter->lifc.lifc_flags = 0;
#endif
		iter->lifc.lifc_len = iter->bufsize;
		iter->lifc.lifc_buf = iter->buf;
		/*
		 * Ignore the HP/UX warning about "interger overflow during
		 * conversion".  It comes from its own macro definition,
		 * and is really hard to shut up.
		 */
		if (ioctl(iter->socket, SIOCGLIFCONF, (char *)&iter->lifc)
		    == -1) {
#ifdef __hpux
			/*
			 * IPv6 interface scanning is not available on all
			 * kernels w/ IPv6 sockets.
			 */
			if (errno == ENOENT) {
				isc__strerror(errno, strbuf, sizeof(strbuf));
				isc_log_write(isc_lctx, ISC_LOGCATEGORY_GENERAL,
					      ISC_LOGMODULE_INTERFACE,
					      ISC_LOG_DEBUG(1),
					      isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_IFITERIOCTL,
							ISC_MSG_GETIFCONFIG,
							"get interface "
							"configuration: %s"),
					       strbuf);
				result = ISC_R_FAILURE;
				goto cleanup;
			}
#endif
			if (errno != EINVAL) {
				isc__strerror(errno, strbuf, sizeof(strbuf));
				UNEXPECTED_ERROR(__FILE__, __LINE__,
						 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_IFITERIOCTL,
							ISC_MSG_GETIFCONFIG,
							"get interface "
							"configuration: %s"),
						 strbuf);
				result = ISC_R_UNEXPECTED;
				goto cleanup;
			}
			/*
			 * EINVAL.  Retry with a bigger buffer.
			 */
		} else {
			/*
			 * The ioctl succeeded.
			 * Some OS's just return what will fit rather
			 * than set EINVAL if the buffer is too small
			 * to fit all the interfaces in.  If
			 * ifc.ifc_len is too near to the end of the
			 * buffer we will grow it just in case and
			 * retry.
			 */
			if (iter->lifc.lifc_len + 2 * sizeof(struct LIFREQ)
			    < iter->bufsize)
				break;
		}
		if (iter->bufsize >= IFCONF_BUFSIZE_MAX) {
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 isc_msgcat_get(isc_msgcat,
							ISC_MSGSET_IFITERIOCTL,
							ISC_MSG_BUFFERMAX,
							"get interface "
							"configuration: "
							"maximum buffer "
							"size exceeded"));
			result = ISC_R_UNEXPECTED;
			goto cleanup;
		}
		isc_mem_put(iter->mctx, iter->buf, iter->bufsize);

		iter->bufsize *= 2;
	}

	iter->mode = 6;
	return (ISC_R_SUCCESS);

 cleanup:
	isc_mem_put(iter->mctx, iter->buf, iter->bufsize);
	iter->buf = NULL;
	return (result);
#endif
}

isc_result_t
isc_interfaceiter_create(isc_mem_t *mctx, isc_interfaceiter_t **iterp) {
	isc_interfaceiter_t *iter;
	isc_result_t result;
	char strbuf[ISC_STRERRORSIZE];

	REQUIRE(mctx != NULL);
	REQUIRE(iterp != NULL);
	REQUIRE(*iterp == NULL);

	iter = isc_mem_get(mctx, sizeof(*iter));
	if (iter == NULL)
		return (ISC_R_NOMEMORY);

	iter->mctx = mctx;
	iter->buf = NULL;
	iter->mode = 0;

	/*
	 * Create an unbound datagram socket to do the SIOCGLIFADDR ioctl on.
	 */
	if ((iter->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 isc_msgcat_get(isc_msgcat,
						ISC_MSGSET_IFITERIOCTL,
						ISC_MSG_MAKESCANSOCKET,
						"making interface "
						"scan socket: %s"),
				 strbuf);
		result = ISC_R_UNEXPECTED;
		goto socket_failure;
	}

	/*
	 * Get the interface configuration, allocating more memory if
	 * necessary.
	 */

	result = isc_net_probeipv6();
	if (result == ISC_R_SUCCESS)
		result = getbuf6(iter);
	if (result != ISC_R_SUCCESS)
		result = getbuf4(iter);
	if (result != ISC_R_SUCCESS)
		goto ioctl_failure;

	/*
	 * A newly created iterator has an undefined position
	 * until isc_interfaceiter_first() is called.
	 */
#ifdef HAVE_TRUCLUSTER
	iter->clua_context = -1;
#endif
#ifdef __linux
	iter->proc = fopen("/proc/net/if_inet6", "r");
	iter->valid = ISC_R_FAILURE;
	iter->first = ISC_FALSE;
#endif
	iter->pos = (unsigned int) -1;
	iter->result = ISC_R_FAILURE;

	iter->magic = IFITER_MAGIC;
	*iterp = iter;
	return (ISC_R_SUCCESS);

 ioctl_failure:
	if (iter->buf != NULL)
		isc_mem_put(mctx, iter->buf, iter->bufsize);
	(void) close(iter->socket);

 socket_failure:
	isc_mem_put(mctx, iter, sizeof(*iter));
	return (result);
}

#ifdef HAVE_TRUCLUSTER
static void
get_inaddr(isc_netaddr_t *dst, struct in_addr *src) {
	dst->family = AF_INET;
	memcpy(&dst->type.in, src, sizeof(struct in_addr));
}

static isc_result_t
internal_current_clusteralias(isc_interfaceiter_t *iter) {
	struct sockaddr sa;
	struct clua_info ci;
	while (clua_getaliasaddress(&sa, &iter->clua_context) == CLUA_SUCCESS) {
		if (clua_getaliasinfo(&sa, &ci) != CLUA_SUCCESS)
			continue;
		memset(&iter->current, 0, sizeof(iter->current));
		iter->current.af = sa.sa_family;
		memset(iter->current.name, 0, sizeof(iter->current.name));
		sprintf(iter->current.name, "clua%d", ci.aliasid);
		iter->current.flags = INTERFACE_F_UP;
		get_inaddr(&iter->current.address, &ci.addr);
		get_inaddr(&iter->current.netmask, &ci.netmask);
		return (ISC_R_SUCCESS);
	}
	return (ISC_R_NOMORE);
}
#endif

#ifdef __linux
static isc_result_t
linux_if_inet6_next(isc_interfaceiter_t *iter) {
	if (iter->proc != NULL &&
	    fgets(iter->entry, sizeof(iter->entry), iter->proc) != NULL)
		iter->valid = ISC_R_SUCCESS;
	else
		iter->valid = ISC_R_NOMORE;
	return (iter->valid);
}

static void
linux_if_inet6_first(isc_interfaceiter_t *iter) {
	if (iter->proc != NULL) {
		rewind(iter->proc);
		(void)linux_if_inet6_next(iter);
	} else
		iter->valid = ISC_R_NOMORE;
	iter->first = ISC_FALSE;
}

static isc_result_t
linux_if_inet6_current(isc_interfaceiter_t *iter) {
	char address[33];
	char name[IF_NAMESIZE+1];
	struct in6_addr addr6;
	int ifindex, prefix, flag3, flag4;
	int res;
	unsigned int i;

	if (iter->valid != ISC_R_SUCCESS)
		return (iter->valid);
	if (iter->proc == NULL)
		return (ISC_R_FAILURE);

	res = sscanf(iter->entry, "%32[a-f0-9] %x %x %x %x %16s\n",
		     address, &ifindex, &prefix, &flag3, &flag4, name);
	if (res != 6)
		return (ISC_R_FAILURE);
	if (strlen(address) != 32)
		return (ISC_R_FAILURE);
	for (i = 0; i < 16; i++) {
		unsigned char byte;
		static const char hex[] = "0123456789abcdef";
		byte = ((index(hex, address[i * 2]) - hex) << 4) |
		       (index(hex, address[i * 2 + 1]) - hex);
		addr6.s6_addr[i] = byte;
	}
	iter->current.af = AF_INET6;
	iter->current.flags = INTERFACE_F_UP;
	isc_netaddr_fromin6(&iter->current.address, &addr6);
	if (isc_netaddr_islinklocal(&iter->current.address)) {
		isc_netaddr_setzone(&iter->current.address,
				    (isc_uint32_t)ifindex);
	}
	for (i = 0; i < 16; i++) {
		if (prefix > 8) {
			addr6.s6_addr[i] = 0xff;
			prefix -= 8;
		} else {
			addr6.s6_addr[i] = (0xff << (8 - prefix)) & 0xff;
			prefix = 0;
		}
	}
	isc_netaddr_fromin6(&iter->current.netmask, &addr6);
	strncpy(iter->current.name, name, sizeof(iter->current.name));
	return (ISC_R_SUCCESS);
}
#endif

/*
 * Get information about the current interface to iter->current.
 * If successful, return ISC_R_SUCCESS.
 * If the interface has an unsupported address family, or if
 * some operation on it fails, return ISC_R_IGNORE to make
 * the higher-level iterator code ignore it.
 */

static isc_result_t
internal_current4(isc_interfaceiter_t *iter) {
	struct ifreq *ifrp;
	struct ifreq ifreq;
	int family;
	char strbuf[ISC_STRERRORSIZE];
#if !defined(SIOCGLIFCONF) && defined(SIOCGLIFADDR)
	struct if_laddrreq if_laddrreq;
	int i, bits;
#endif
#ifdef __linux
	isc_result_t result;
#endif

	REQUIRE(VALID_IFITER(iter));
	REQUIRE (iter->pos < (unsigned int) iter->ifc.ifc_len);

#ifdef __linux
	result = linux_if_inet6_current(iter);
	if (result != ISC_R_NOMORE)
		return (result);
	iter->first = ISC_TRUE;
#endif

	ifrp = (struct ifreq *)((char *) iter->ifc.ifc_req + iter->pos);

	memset(&ifreq, 0, sizeof(ifreq));
	memcpy(&ifreq, ifrp, sizeof(ifreq));

	family = ifreq.ifr_addr.sa_family;
#if !defined (SIOCGLIFCONF) && defined(SIOCGLIFADDR) && \
    defined(ISC_PLATFORM_HAVEIPV6)
	if (family != AF_INET && family != AF_INET6)
#else
	if (family != AF_INET)
#endif
		return (ISC_R_IGNORE);

	memset(&iter->current, 0, sizeof(iter->current));
	iter->current.af = family;

	INSIST(sizeof(ifreq.ifr_name) <= sizeof(iter->current.name));
	memset(iter->current.name, 0, sizeof(iter->current.name));
	memcpy(iter->current.name, ifreq.ifr_name, sizeof(ifreq.ifr_name));

	get_addr(family, &iter->current.address,
		 (struct sockaddr *)&ifrp->ifr_addr);

	/*
	 * If the interface does not have a address ignore it.
	 */
	switch (family) {
	case AF_INET:
		if (iter->current.address.type.in.s_addr == htonl(INADDR_ANY))
			return (ISC_R_IGNORE);
		break;
	case AF_INET6:
		if (memcmp(&iter->current.address.type.in6, &in6addr_any,
			   sizeof(in6addr_any)) == 0)
			return (ISC_R_IGNORE);
		break;
	}

	/*
	 * Get interface flags.
	 */

	iter->current.flags = 0;

	/*
	 * Ignore the HP/UX warning about "interger overflow during
	 * conversion.  It comes from its own macro definition,
	 * and is really hard to shut up.
	 */
	if (ioctl(iter->socket, SIOCGIFFLAGS, (char *) &ifreq) < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "%s: getting interface flags: %s",
				 ifreq.ifr_name, strbuf);
		return (ISC_R_IGNORE);
	}

	if ((ifreq.ifr_flags & IFF_UP) != 0)
		iter->current.flags |= INTERFACE_F_UP;

#ifdef IFF_POINTTOPOINT
	if ((ifreq.ifr_flags & IFF_POINTOPOINT) != 0)
		iter->current.flags |= INTERFACE_F_POINTTOPOINT;
#endif

	if ((ifreq.ifr_flags & IFF_LOOPBACK) != 0)
		iter->current.flags |= INTERFACE_F_LOOPBACK;

#if !defined(SIOCGLIFCONF) && defined(SIOCGLIFADDR)
	if (family == AF_INET) 
		goto inet;

	memset(&if_laddrreq, 0, sizeof(if_laddrreq));
	memcpy(if_laddrreq.iflr_name, iter->current.name,
	       sizeof(if_laddrreq.iflr_name));
	memcpy(&if_laddrreq.addr, &iter->current.address.type.in6,
	       sizeof(iter->current.address.type.in6));

	if (ioctl(iter->socket, SIOCGLIFADDR, &if_laddrreq) < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "%s: getting interface address: %s",
				 ifreq.ifr_name, strbuf);
		return (ISC_R_IGNORE);
	}

	/*
	 * Netmask already zeroed.
	 */
	iter->current.netmask.family = family;
	for (i = 0; i < 16; i++) {
		if (if_laddrreq.prefixlen > 8) {
			bits = 0;
			if_laddrreq.prefixlen -= 8;
		} else {
			bits = 8 - if_laddrreq.prefixlen;
			if_laddrreq.prefixlen = 0;
		}
		iter->current.netmask.type.in6.s6_addr[i] = (~0 << bits) & 0xff;
	}
	return (ISC_R_SUCCESS);

 inet:
#endif
	if (family != AF_INET)
		return (ISC_R_IGNORE);
#ifdef IFF_POINTTOPOINT
	/*
	 * If the interface is point-to-point, get the destination address.
	 */
	if ((iter->current.flags & INTERFACE_F_POINTTOPOINT) != 0) {
		/*
		 * Ignore the HP/UX warning about "interger overflow during
		 * conversion.  It comes from its own macro definition,
		 * and is really hard to shut up.
		 */
		if (ioctl(iter->socket, SIOCGIFDSTADDR, (char *)&ifreq)
		    < 0) {
			isc__strerror(errno, strbuf, sizeof(strbuf));
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				isc_msgcat_get(isc_msgcat,
					       ISC_MSGSET_IFITERIOCTL,
					       ISC_MSG_GETDESTADDR,
					       "%s: getting "
					       "destination address: %s"),
					 ifreq.ifr_name, strbuf);
			return (ISC_R_IGNORE);
		}
		get_addr(family, &iter->current.dstaddress,
			 (struct sockaddr *)&ifreq.ifr_dstaddr);
	}
#endif

	/*
	 * Get the network mask.
	 */
	memset(&ifreq, 0, sizeof(ifreq));
	memcpy(&ifreq, ifrp, sizeof(ifreq));
	/*
	 * Ignore the HP/UX warning about "interger overflow during
	 * conversion.  It comes from its own macro definition,
	 * and is really hard to shut up.
	 */
	if (ioctl(iter->socket, SIOCGIFNETMASK, (char *)&ifreq) < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
			isc_msgcat_get(isc_msgcat,
				       ISC_MSGSET_IFITERIOCTL,
				       ISC_MSG_GETNETMASK,
				       "%s: getting netmask: %s"),
				       ifreq.ifr_name, strbuf);
		return (ISC_R_IGNORE);
	}
	get_addr(family, &iter->current.netmask,
		 (struct sockaddr *)&ifreq.ifr_addr);
	return (ISC_R_SUCCESS);
}

static isc_result_t
internal_current6(isc_interfaceiter_t *iter) {
#if !defined(SIOCGLIFCONF) || !defined(SIOCGLIFADDR)
	UNUSED(iter);
	return (ISC_R_NOTIMPLEMENTED);
#else
	struct LIFREQ *ifrp;
	struct LIFREQ lifreq;
	int family;
	char strbuf[ISC_STRERRORSIZE];
	int fd;

	REQUIRE(VALID_IFITER(iter));
	REQUIRE (iter->pos < (unsigned int) iter->lifc.lifc_len);

	ifrp = (struct LIFREQ *)((char *) iter->lifc.lifc_req + iter->pos);

	memset(&lifreq, 0, sizeof(lifreq));
	memcpy(&lifreq, ifrp, sizeof(lifreq));

	family = lifreq.lifr_addr.ss_family;
#ifdef ISC_PLATFORM_HAVEIPV6
	if (family != AF_INET && family != AF_INET6)
#else
	if (family != AF_INET)
#endif
		return (ISC_R_IGNORE);

	memset(&iter->current, 0, sizeof(iter->current));
	iter->current.af = family;

	INSIST(sizeof(lifreq.lifr_name) <= sizeof(iter->current.name));
	memset(iter->current.name, 0, sizeof(iter->current.name));
	memcpy(iter->current.name, lifreq.lifr_name, sizeof(lifreq.lifr_name));

	get_addr(family, &iter->current.address,
		 (struct sockaddr *)&lifreq.lifr_addr);

	/*
	 * If the interface does not have a address ignore it.
	 */
	switch (family) {
	case AF_INET:
		if (iter->current.address.type.in.s_addr == htonl(INADDR_ANY))
			return (ISC_R_IGNORE);
		break;
	case AF_INET6:
		if (memcmp(&iter->current.address.type.in6, &in6addr_any,
			   sizeof(in6addr_any)) == 0)
			return (ISC_R_IGNORE);
		break;
	}

	/*
	 * Get interface flags.
	 */

	iter->current.flags = 0;

	fd = socket(family, SOCK_DGRAM, 0);
	if (fd < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "%s: socket: %s",
				 lifreq.lifr_name, strbuf);
		return (ISC_R_IGNORE);
	}

	/*
	 * Ignore the HP/UX warning about "interger overflow during
	 * conversion.  It comes from its own macro definition,
	 * and is really hard to shut up.
	 */
	if (ioctl(fd, SIOCGLIFFLAGS, (char *) &lifreq) < 0) {
		isc__strerror(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "%s: getting interface flags: %s",
				 lifreq.lifr_name, strbuf);
		close(fd);
		return (ISC_R_IGNORE);
	}

	if ((lifreq.lifr_flags & IFF_UP) != 0)
		iter->current.flags |= INTERFACE_F_UP;

#ifdef IFF_POINTTOPOINT
	if ((lifreq.lifr_flags & IFF_POINTOPOINT) != 0)
		iter->current.flags |= INTERFACE_F_POINTTOPOINT;
#endif

	if ((lifreq.lifr_flags & IFF_LOOPBACK) != 0)
		iter->current.flags |= INTERFACE_F_LOOPBACK;

	/*
	 * If the interface is point-to-point, get the destination address.
	 */
#ifdef IFF_POINTTOPOINT
	if ((iter->current.flags & INTERFACE_F_POINTTOPOINT) != 0) {
		/*
		 * Ignore the HP/UX warning about "interger overflow during
		 * conversion.  It comes from its own macro definition,
		 * and is really hard to shut up.
		 */
		if (ioctl(fd, SIOCGLIFDSTADDR, (char *)&lifreq)
		    < 0) {
			isc__strerror(errno, strbuf, sizeof(strbuf));
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				isc_msgcat_get(isc_msgcat,
					       ISC_MSGSET_IFITERIOCTL,
					       ISC_MSG_GETDESTADDR,
					       "%s: getting "
					       "destination address: %s"),
					 lifreq.lifr_name, strbuf);
			close(fd);
			return (ISC_R_IGNORE);
		}
		get_addr(family, &iter->current.dstaddress,
			 (struct sockaddr *)&lifreq.lifr_dstaddr);
	}
#endif

	/*
	 * Get the network mask.
	 */
	memset(&lifreq, 0, sizeof(lifreq));
	memcpy(&lifreq, ifrp, sizeof(lifreq));
	switch (family) {
	case AF_INET:
		/*
		 * Ignore the HP/UX warning about "interger overflow during
		 * conversion.  It comes from its own macro definition,
		 * and is really hard to shut up.
		 */
		if (ioctl(fd, SIOCGLIFNETMASK, (char *)&lifreq)
		    < 0) {
			isc__strerror(errno, strbuf, sizeof(strbuf));
			UNEXPECTED_ERROR(__FILE__, __LINE__,
				isc_msgcat_get(isc_msgcat,
					       ISC_MSGSET_IFITERIOCTL,
					       ISC_MSG_GETNETMASK,
					       "%s: getting netmask: %s"),
					 lifreq.lifr_name, strbuf);
			close(fd);
			return (ISC_R_IGNORE);
		}
		get_addr(family, &iter->current.netmask,
			 (struct sockaddr *)&lifreq.lifr_addr);
		break;
	case AF_INET6: {
#ifdef lifr_addrlen
		int i, bits;

		/*
		 * Netmask already zeroed.
		 */
		iter->current.netmask.family = family;
		for (i = 0; i < lifreq.lifr_addrlen; i += 8) {
			bits = lifreq.lifr_addrlen - i;
			bits = (bits < 8) ? (8 - bits) : 0;
			iter->current.netmask.type.in6.s6_addr[i / 8] =
				(~0 << bits) & 0xff;
		}
#endif
		break;
	}
	}

	close(fd);
	return (ISC_R_SUCCESS);
#endif
}

static isc_result_t
internal_current(isc_interfaceiter_t *iter) {
	if (iter->mode == 6)
		return (internal_current6(iter));
	return (internal_current4(iter));
}

/*
 * Step the iterator to the next interface.  Unlike
 * isc_interfaceiter_next(), this may leave the iterator
 * positioned on an interface that will ultimately
 * be ignored.  Return ISC_R_NOMORE if there are no more
 * interfaces, otherwise ISC_R_SUCCESS.
 */
static isc_result_t
internal_next4(isc_interfaceiter_t *iter) {
	struct ifreq *ifrp;

	REQUIRE (iter->pos < (unsigned int) iter->ifc.ifc_len);

#ifdef HAVE_TRUCLUSTER
	if (internal_current_clusteralias(iter) == ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);
#endif
#ifdef __linux
	if (linux_if_inet6_next(iter) == ISC_R_SUCCESS)
		return (ISC_R_SUCCESS);
	if (!iter->first)
		return (ISC_R_SUCCESS);
#endif
	ifrp = (struct ifreq *)((char *) iter->ifc.ifc_req + iter->pos);

#ifdef ISC_PLATFORM_HAVESALEN
	if (ifrp->ifr_addr.sa_len > sizeof(struct sockaddr))
		iter->pos += sizeof(ifrp->ifr_name) + ifrp->ifr_addr.sa_len;
	else
#endif
		iter->pos += sizeof(*ifrp);

	if (iter->pos >= (unsigned int) iter->ifc.ifc_len)
		return (ISC_R_NOMORE);

	return (ISC_R_SUCCESS);
}

static isc_result_t
internal_next6(isc_interfaceiter_t *iter) {
#if !defined(SIOCGLIFCONF) || !defined(SIOCGLIFADDR)
	UNUSED(iter);
	return (ISC_R_NOTIMPLEMENTED);
#else
	struct LIFREQ *ifrp;

	REQUIRE (iter->pos < (unsigned int) iter->lifc.lifc_len);

	ifrp = (struct LIFREQ *)((char *) iter->lifc.lifc_req + iter->pos);

#ifdef ISC_PLATFORM_HAVESALEN
	if (ifrp->lifr_addr.sa_len > sizeof(struct sockaddr))
		iter->pos += sizeof(ifrp->lifr_name) + ifrp->lifr_addr.sa_len;
	else
#endif
		iter->pos += sizeof(*ifrp);

	if (iter->pos >= (unsigned int) iter->lifc.lifc_len)
		return (ISC_R_NOMORE);

	return (ISC_R_SUCCESS);
#endif
}

static isc_result_t
internal_next(isc_interfaceiter_t *iter) {
	if (iter->mode == 6)
		return (internal_next6(iter));
	return (internal_next4(iter));
}

static void
internal_destroy(isc_interfaceiter_t *iter) {
	(void) close(iter->socket);
#ifdef __linux
	if (iter->proc != NULL)
		fclose(iter->proc);
#endif
}

static
void internal_first(isc_interfaceiter_t *iter) {
	iter->pos = 0;
#ifdef HAVE_TRUCLUSTER
	iter->clua_context = 0;
#endif
#ifdef __linux
	linux_if_inet6_first(iter);
#endif
}
