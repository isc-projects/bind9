/*
 * Copyright (C) 1999, 2000  Internet Software Consortium.
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
#include <sys/stat.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <isc/result.h>
#include <isc/boolean.h>

#include <named/main.h>
#include <named/os.h>

static char *pidfile = NULL;
#ifdef HAVE_LINUXTHREADS
static pid_t mainpid = 0;
#endif

#ifdef HAVE_LINUX_CAPABILITY_H

#include <sys/syscall.h>
#include <linux/capability.h>

#ifndef SYS_capset
#define SYS_capset __NR_capset
#endif

static void
linux_setcaps(unsigned int caps) {
	struct __user_cap_header_struct caphead;
	struct __user_cap_data_struct cap;

	if (getuid() != 0)
		return;

	memset(&caphead, 0, sizeof caphead);
	caphead.version = _LINUX_CAPABILITY_VERSION;
	caphead.pid = 0;
	memset(&cap, 0, sizeof cap);
	cap.effective = caps;
	cap.permitted = caps;
	cap.inheritable = caps;
	if (syscall(SYS_capset, &caphead, &cap) < 0)
		ns_main_earlyfatal("capset failed: %s", strerror(errno));
}

static void
linux_initialprivs(void) {
	unsigned int caps;

	/*
	 * Drop all privileges except the abilities to bind() to privileged
	 * ports and chroot().
	 */

	caps = 0;
	caps |= (1 << CAP_NET_BIND_SERVICE);
	caps |= (1 << CAP_SYS_CHROOT);
	/*
	 * XXX  We might want to add CAP_SYS_RESOURCE, though it's not
	 *      clear it would work right given the way linuxthreads work.
	 */
	linux_setcaps(caps);
}

static void
linux_minprivs(void) {
	unsigned int caps;

	/*
	 * Drop all privileges except the abilities to bind() to privileged
	 * ports.
	 */

	caps = 0;
	caps |= (1 << CAP_NET_BIND_SERVICE);

	linux_setcaps(caps);
}

#endif	/* HAVE_LINUX_CAPABILITY_H */


static void
setup_syslog(void) {
	int options;

	options = LOG_PID;
#ifdef LOG_NDELAY
	options |= LOG_NDELAY;
#endif

	openlog("named", options, LOG_DAEMON);
}

void
ns_os_init(void) {
	setup_syslog();
#ifdef HAVE_LINUX_CAPABILITY_H
	linux_initialprivs();
#endif
#ifdef HAVE_LINUXTHREADS
	mainpid = getpid();
#endif
}

void
ns_os_daemonize(void) {
	pid_t pid;
	int fd;

	pid = fork();
	if (pid == -1)
		ns_main_earlyfatal("fork(): %s", strerror(errno));
	if (pid != 0)
                _exit(0);

	/*
	 * We're the child.
	 */

#ifdef HAVE_LINUXTHREADS
	mainpid = getpid();
#endif

        if (setsid() == -1)
		ns_main_earlyfatal("setsid(): %s", strerror(errno));

	/*
	 * Try to set stdin, stdout, and stderr to /dev/null, but press
	 * on even if it fails.
	 */
	fd = open("/dev/null", O_RDWR, 0);
	if (fd != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd != STDIN_FILENO &&
		    fd != STDOUT_FILENO &&
		    fd != STDERR_FILENO)
			(void)close(fd);
	}
}

static isc_boolean_t
all_digits(const char *s) {
	if (*s == '\0')
		return (ISC_FALSE);
	while (*s != '\0') {
		if (!isdigit((*s)&0xff))
			return (ISC_FALSE);
		s++;
	}
	return (ISC_TRUE);
}

void
ns_os_chroot(const char *root) {
	if (root != NULL) {
		if (chroot(root) < 0)
			ns_main_earlyfatal("chroot(): %s", strerror(errno));
		if (chdir("/") < 0)
			ns_main_earlyfatal("chdir(/): %s", strerror(errno));
	}
#ifdef HAVE_LINUX_CAPABILITY_H
	/*
	 * We must drop the chroot() capability, otherwise it could be used
	 * to escape.
	 */
	linux_minprivs();
#endif
}

void
ns_os_changeuser(const char *username) {
	struct passwd *pw;

	if (username == NULL || getuid() != 0)
		return;

	if (all_digits(username))
		pw = getpwuid((uid_t)atoi(username));
	else
		pw = getpwnam(username);
	endpwent();
	if (pw == NULL)
		ns_main_earlyfatal("user '%s' unknown", username);
	if (initgroups(pw->pw_name, pw->pw_gid) < 0)
		ns_main_earlyfatal("initgroups(): %s", strerror(errno));
	if (setgid(pw->pw_gid) < 0)
		ns_main_earlyfatal("setgid(): %s", strerror(errno));
	if (setuid(pw->pw_uid) < 0)
		ns_main_earlyfatal("setuid(): %s", strerror(errno));
}

static int
safe_open(const char *filename) {
        struct stat sb;

        if (stat(filename, &sb) == -1) {
                if (errno != ENOENT)
			return (-1);
        } else if ((sb.st_mode & S_IFREG) == 0)
		return (-1);

        (void)unlink(filename);
        return (open(filename, O_WRONLY|O_CREAT|O_EXCL,
		     S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH));
}

static void
cleanup_pidfile(void) {
	if (pidfile != NULL)
		(void)unlink(pidfile);
	free(pidfile);
	pidfile = NULL;
}

void
ns_os_writepidfile(const char *filename) {
        int fd;
	FILE *lockfile;
	size_t len;
	pid_t pid;

	/*
	 * The caller must ensure any required synchronization.
	 */

	cleanup_pidfile();

	len = strlen(filename);
	pidfile = malloc(len + 1);
	if (pidfile == NULL)
                ns_main_earlyfatal("couldn't malloc '%s': %s",
				   filename, strerror(errno));
	/* This is safe. */
	strcpy(pidfile, filename);

        fd = safe_open(filename);
        if (fd < 0)
                ns_main_earlyfatal("couldn't open pid file '%s': %s",
				   filename, strerror(errno));
        lockfile = fdopen(fd, "w");
        if (lockfile == NULL)
		ns_main_earlyfatal("could not fdopen() pid file '%s': %s",
				   filename, strerror(errno));
#ifdef HAVE_LINUXTHREADS
	pid = mainpid;
#else
	pid = getpid();
#endif
        if (fprintf(lockfile, "%ld\n", (long)pid) < 0)
                ns_main_earlyfatal("fprintf() to pid file '%s' failed",
				   filename);
        if (fflush(lockfile) == EOF)
                ns_main_earlyfatal("fflush() to pid file '%s' failed",
				   filename);
	(void)fclose(lockfile);
}

void
ns_os_shutdown(void) {
	closelog();
	cleanup_pidfile();
}
