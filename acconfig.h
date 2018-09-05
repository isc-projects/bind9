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

/*! \file */

/***
 *** This file is not to be included by any public header files, because
 *** it does not get installed.
 ***/
@TOP@

/** define if pthread_attr_getstacksize() is available */
#undef HAVE_PTHREAD_ATTR_GETSTACKSIZE

/** define if pthread_attr_setstacksize() is available */
#undef HAVE_PTHREAD_ATTR_SETSTACKSIZE

/** define if you have strerror in the C library. */
#undef HAVE_STRERROR

/* Define to the length type used by the socket API (socklen_t, size_t, int). */
#undef ISC_SOCKADDR_LEN_T

/* Define if threads need PTHREAD_SCOPE_SYSTEM */
#undef NEED_PTHREAD_SCOPE_SYSTEM

/* Define to 1 if you have the uname library function. */
#undef HAVE_UNAME
