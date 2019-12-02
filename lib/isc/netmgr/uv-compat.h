/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once
#include <uv.h>

/*
 * Those functions were introduced in newer libuv, we still
 * want BIND9 compile on older ones so we emulate them.
 * They're inline to avoid conflicts when running with a newer
 * library version.
 */

#ifndef HAVE_UV_HANDLE_GET_DATA
static inline void*
uv_handle_get_data(const uv_handle_t* handle) {
    return (handle->data);
}
#endif

#ifndef HAVE_UV_HANDLE_SET_DATA
static inline void
uv_handle_set_data(uv_handle_t* handle, void* data) {
    handle->data = data;
};
#endif
