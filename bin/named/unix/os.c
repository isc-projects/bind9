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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <isc/result.h>

#include <named/main.h>
#include <named/os.h>


#ifdef HAVE_LINUX_CAPABILITY_H
#include <sys/syscall.h>
#include <linux/capability.h>

#ifndef SYS_capset
#define SYS_capset __NR_capset
#endif

static void
linux_dropprivs() {
	struct __user_cap_header_struct caphead;
	struct __user_cap_data_struct cap;
	unsigned int caps;

	if (getuid() != 0)
		return;

	/*
	 * Drop all root privileges except the ability to bind() to
	 * privileged ports.
	 */

	caps = CAP_NET_BIND_SERVICE;

	memset(&caphead, 0, sizeof caphead);
	caphead.version = _LINUX_CAPABILITY_VERSION;
	caphead.pid = 0;
	memset(&cap, 0, sizeof cap);
	cap.effective = caps;
	cap.permitted = caps;
	cap.inheritable = caps;
	if (syscall(SYS_capset, &caphead, &cap) < 0)
		ns_main_earlyfatal("syscall(capset): %s", strerror(errno));
}
#endif

static void
setup_syslog(void) {
	int options;

	options = LOG_PID;
#ifdef LOG_NDELAY
	options |= LOG_NDELAY;
#endif

	openlog("named", options, LOG_DAEMON);
}

isc_result_t
ns_os_init(void) {

	setup_syslog();

#ifdef HAVE_LINUX_CAPABILITY_H
	linux_dropprivs();
#endif

	return (ISC_R_SUCCESS);
}

void
ns_os_shutdown(void) {
	closelog();
}
