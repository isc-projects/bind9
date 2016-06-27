/*
 * Copyright (C) 2011, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: gssapi_krb.c,v 1.3 2011/04/05 19:16:54 smann Exp $ */

#include <config.h>

int
main() {
#if (defined(HAVE_GSSAPI_H) || \
     defined(HAVE_GSSAPI_GSSAPI_H)) && \
    (defined(HAVE_KRB5_H) || \
     defined(HAVE_KRB5_KRB5_H) || \
     defined(HAVE_GSSAPI_GSSAPI_KRB5_H) || \
     defined(HAVE_GSSAPI_KRB5_H) || \
     defined(HAVE_KERBEROSV5_KRB5_H))
	return (0);
#else
	return (1);
#endif
}
