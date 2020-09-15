/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef NS_OS_H
#define NS_OS_H 1

/*! \file */

#include <pwd.h>
#include <stdbool.h>

#include <isc/types.h>

void
ns_os_init(const char *progname);

void
ns_os_daemonize(void);

void
ns_os_opendevnull(void);

void
ns_os_closedevnull(void);

void
ns_os_chroot(const char *root);

void
ns_os_inituserinfo(const char *username);

void
ns_os_changeuser(void);

uid_t
ns_os_uid(void);

void
ns_os_adjustnofile(void);

void
ns_os_minprivs(void);

FILE *
ns_os_openfile(const char *filename, mode_t mode, bool switch_user);

void
ns_os_writepidfile(const char *filename, bool first_time);

bool
ns_os_issingleton(const char *filename);

void
ns_os_shutdown(void);

isc_result_t
ns_os_gethostname(char *buf, size_t len);

void
ns_os_shutdownmsg(char *command, isc_buffer_t *text);

void
ns_os_tzset(void);

void
ns_os_started(void);

const char *
ns_os_uname(void);

#endif /* NS_OS_H */
