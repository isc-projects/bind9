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

#include "uv-compat.h"
#include <unistd.h>

#include <isc/util.h>

#include "netmgr-int.h"

#if UV_VERSION_HEX < UV_VERSION(1, 27, 0)
int
isc_uv_udp_connect(uv_udp_t *handle, const struct sockaddr *addr) {
	int err = 0;

	do {
		int addrlen = (addr->sa_family == AF_INET)
				      ? sizeof(struct sockaddr_in)
				      : sizeof(struct sockaddr_in6);
		err = connect(handle->io_watcher.fd, addr, addrlen);
	} while (err == -1 && errno == EINTR);

	if (err) {
#if UV_VERSION_HEX >= UV_VERSION(1, 10, 0)
		return (uv_translate_sys_error(errno));
#else
		return (-errno);
#endif /* UV_VERSION_HEX >= UV_VERSION(1, 10, 0) */
	}

	return (0);
}
#endif /* UV_VERSION_HEX < UV_VERSION(1, 27, 0) */

#if UV_VERSION_HEX < UV_VERSION(1, 32, 0)
int
uv_tcp_close_reset(uv_tcp_t *handle, uv_close_cb close_cb) {
	if (setsockopt(handle->io_watcher.fd, SOL_SOCKET, SO_LINGER,
		       &(struct linger){ 1, 0 }, sizeof(struct linger)) == -1)
	{
#if UV_VERSION_HEX >= UV_VERSION(1, 10, 0)
		return (uv_translate_sys_error(errno));
#else
		return (-errno);
#endif /* UV_VERSION_HEX >= UV_VERSION(1, 10, 0) */
	}

	uv_close((uv_handle_t *)handle, close_cb);
	return (0);
}
#endif /* UV_VERSION_HEX < UV_VERSION(1, 32, 0) */
