/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <unistd.h>

#include <isc/mem.h>
#include <isc/util.h>
#include <isc/uv.h>

/*%
 * Convert a libuv error value into an isc_result_t.  The
 * list of supported error values is not complete; new users
 * of this function should add any expected errors that are
 * not already there.
 */
isc_result_t
isc__uverr2result(int uverr, bool dolog, const char *file, unsigned int line,
		  const char *func) {
	switch (uverr) {
	case 0:
		return ISC_R_SUCCESS;
	case UV_ENOTDIR:
	case UV_ELOOP:
	case UV_EINVAL: /* XXX sometimes this is not for files */
	case UV_ENAMETOOLONG:
	case UV_EBADF:
		return ISC_R_INVALIDFILE;
	case UV_ENOENT:
		return ISC_R_FILENOTFOUND;
	case UV_EAGAIN:
		return ISC_R_NOCONN;
	case UV_EACCES:
	case UV_EPERM:
		return ISC_R_NOPERM;
	case UV_EEXIST:
		return ISC_R_FILEEXISTS;
	case UV_EIO:
		return ISC_R_IOERROR;
	case UV_ENOMEM:
		return ISC_R_NOMEMORY;
	case UV_ENFILE:
	case UV_EMFILE:
		return ISC_R_TOOMANYOPENFILES;
	case UV_ENOSPC:
		return ISC_R_DISCFULL;
	case UV_EPIPE:
	case UV_ECONNRESET:
	case UV_ECONNABORTED:
		return ISC_R_CONNECTIONRESET;
	case UV_ENOTCONN:
		return ISC_R_NOTCONNECTED;
	case UV_ETIMEDOUT:
		return ISC_R_TIMEDOUT;
	case UV_ENOBUFS:
		return ISC_R_NORESOURCES;
	case UV_EAFNOSUPPORT:
		return ISC_R_FAMILYNOSUPPORT;
	case UV_ENETDOWN:
		return ISC_R_NETDOWN;
	case UV_EHOSTDOWN:
		return ISC_R_HOSTDOWN;
	case UV_ENETUNREACH:
		return ISC_R_NETUNREACH;
	case UV_EHOSTUNREACH:
		return ISC_R_HOSTUNREACH;
	case UV_EADDRINUSE:
		return ISC_R_ADDRINUSE;
	case UV_EADDRNOTAVAIL:
		return ISC_R_ADDRNOTAVAIL;
	case UV_ECONNREFUSED:
		return ISC_R_CONNREFUSED;
	case UV_ECANCELED:
		return ISC_R_CANCELED;
	case UV_EOF:
		return ISC_R_EOF;
	case UV_EMSGSIZE:
		return ISC_R_MAXSIZE;
	case UV_ENOTSUP:
		return ISC_R_FAMILYNOSUPPORT;
	case UV_ENOPROTOOPT:
	case UV_EPROTONOSUPPORT:
		return ISC_R_INVALIDPROTO;
	default:
		if (dolog) {
			UNEXPECTED_ERROR("unable to convert libuv error code "
					 "in %s (%s:%d) to isc_result: %d: %s",
					 func, file, line, uverr,
					 uv_strerror(uverr));
		}
		return ISC_R_UNEXPECTED;
	}
}

#if UV_VERSION_HEX >= UV_VERSION(1, 38, 0)
static isc_mem_t *isc__uv_mctx = NULL;

static void *
isc__uv_malloc(size_t size) {
	return isc_mem_allocate(isc__uv_mctx, size);
}

static void *
isc__uv_realloc(void *ptr, size_t size) {
	return isc_mem_reallocate(isc__uv_mctx, ptr, size);
}

static void *
isc__uv_calloc(size_t count, size_t size) {
	return isc_mem_callocate(isc__uv_mctx, count, size);
}

static void
isc__uv_free(void *ptr) {
	if (ptr == NULL) {
		return;
	}
	isc_mem_free(isc__uv_mctx, ptr);
}
#endif /* UV_VERSION_HEX >= UV_VERSION(1, 38, 0) */

void
isc__uv_initialize(void) {
#if UV_VERSION_HEX >= UV_VERSION(1, 38, 0)
	int r;
	isc_mem_create("uv", &isc__uv_mctx);
	isc_mem_setdestroycheck(isc__uv_mctx, false);

	r = uv_replace_allocator(isc__uv_malloc, isc__uv_realloc,
				 isc__uv_calloc, isc__uv_free);
	UV_RUNTIME_CHECK(uv_replace_allocator, r);
#endif /* UV_VERSION_HEX >= UV_VERSION(1, 38, 0) */
}

void
isc__uv_shutdown(void) {
#if UV_VERSION_HEX >= UV_VERSION(1, 38, 0)
	uv_library_shutdown();
	isc_mem_detach(&isc__uv_mctx);
#endif /* UV_VERSION_HEX < UV_VERSION(1, 38, 0) */
}

void
isc__uv_setdestroycheck(bool check) {
#if UV_VERSION_HEX >= UV_VERSION(1, 38, 0)
	isc_mem_setdestroycheck(isc__uv_mctx, check);
#else
	UNUSED(check);
#endif /* UV_VERSION_HEX >= UV_VERSION(1, 6, 0) */
}
