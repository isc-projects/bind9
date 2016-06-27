/*
 * Copyright (C) 2009, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/* $Id: os.c,v 1.3 2009/06/11 23:47:55 tbox Exp $ */

#include <config.h>

#include <confgen/os.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <io.h>
#include <sys/stat.h>

int
set_user(FILE *fd, const char *user) {
	return (0);
}
