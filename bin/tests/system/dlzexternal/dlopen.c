/*
 * Copyright (C) 2011, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: dlopen.c,v 1.2 2011/03/10 04:36:15 each Exp $ */

#include <config.h>

int
main() {
#if defined(HAVE_DLOPEN) && defined(ISC_DLZ_DLOPEN)
	return (0);
#else
	return (1);
#endif
}
