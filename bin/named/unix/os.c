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

/* $Id: os.c,v 1.18.2.2 2000/07/10 21:35:38 gson Exp $ */

#include <config.h>

#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>		/* Required for initgroups() on IRIX. */
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <isc/string.h>

#include <named/main.h>
#include <named/os.h>

static char *pidfile = NULL;
#ifdef HAVE_LINUXTHREADS
static pid_t mainpid = 0;
static isc_boolean_t non_root_caps = ISC_FALSE;
static isc_boolean_t non_root = ISC_FALSE;
#endif

static struct passwd *runas_pw = NULL;
static isc_boolean_t done_setuid = ISC_FALSE;

#ifdef HAVE_LINUX_CAPABILITY_H

/*
 * We define _LINUX_FS_H to prevent it from being included.  We don't need
 * anything from it, and the files it includes cause warnings with 2.2
 * kernels, and compilation failures (due to conflicts between <linux/string.h>
 * and <string.h>) on 2.3 kernels.
 */
#define _LINUX_FS_H

#include <sys/syscall.h>	/* Required for syscall(). */
#include <linux/capability.h>	/* Required for _LINUX_CAPABILITY_VERSION. */

#ifdef HAVE_LINUX_PRCTL_H
#include <sys/prctl.h>		/* Required for prctl(). */
#endif

#ifndef SYS_capset
#define SYS_capset __NR_capset
#endif

static void
linux_setcaps(unsigned int caps) {
	struct __user_cap_header_struct caphead;
	struct __user_cap_data_struct cap;

	if ((getuid() != 0 && !non_root_caps) || non_root)
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
	 * We don't need most privileges, so we drop them right away.
	 * Later on linux_minprivs() will be called, which will drop our
	 * capabilities to the minimum needed to run the server.
	 */

	caps = 0;

	/*
	 * We need to be able to bind() to privileged ports, notably port 53!
	 */
	caps |= (1 << CAP_NET_BIND_SERVICE);

	/*
	 * We need chroot() initially too.
	 */
	caps |= (1 << CAP_SYS_CHROOT);

#if defined(HAVE_LINUX_PRCTL_H) && defined(PR_SET_KEEPCAPS)
	/*
	 * If the kernel supports keeping capabilities after setuid(), we
	 * also want the setuid capability.
	 *
	 * There's no point turning this on if we don't have PR_SET_KEEPCAPS,
	 * because changing user ids only works right with linuxthreads if
	 * we can do it early (before creating threads).
	 */
	caps |= (1 << CAP_SETUID);
#endif

	/*
	 * Since we call initgroups, we need this.
	 */
	caps |= (1 << CAP_SETGID);

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
	 * Drop all privileges except the ability to bind() to privileged
	 * ports.
	 *
	 * It's important that we drop CAP_SYS_CHROOT.  If we didn't, it
	 * chroot() could be used to escape from the chrooted area.
	 */

	caps = 0;
	caps |= (1 << CAP_NET_BIND_SERVICE);

	linux_setcaps(caps);
}

#if defined(HAVE_LINUX_PRCTL_H) && defined(PR_SET_KEEPCAPS)
static void
linux_keepcaps(void) {
	/*
	 * Ask the kernel to allow us to keep our capabilities after we
	 * setuid().
	 */

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
		if (errno != EINVAL)
			ns_main_earlyfatal("prctl() failed: %s",
					   strerror(errno));
	} else {
		non_root_caps = ISC_TRUE;
		if (getuid() != 0)
			non_root = ISC_TRUE;
	}
}
#endif

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
	 *
	 * XXXMLG The close() calls here are unneeded on all but NetBSD, but
	 * are harmless to include everywhere.  dup2() is supposed to close
	 * the FD if it is in use, but unproven-pthreads-0.16 is broken
	 * and will end up closing the wrong FD.  This will be fixed eventually,
	 * and these calls will be removed.
	 */
	fd = open("/dev/null", O_RDWR, 0);
	if (fd != -1) {
		close(STDIN_FILENO);
		(void)dup2(fd, STDIN_FILENO);
		close(STDOUT_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		close(STDERR_FILENO);
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
}

void
ns_os_inituserinfo(const char *username) {
	if (username == NULL)
		return;

	if (all_digits(username))
		runas_pw = getpwuid((uid_t)atoi(username));
	else
		runas_pw = getpwnam(username);
	endpwent();

	if (runas_pw == NULL)
		ns_main_earlyfatal("user '%s' unknown", username);

	if (getuid() == 0) {
		if (initgroups(runas_pw->pw_name, runas_pw->pw_gid) < 0)
			ns_main_earlyfatal("initgroups(): %s", strerror(errno));
	}

}

void
ns_os_changeuser(void) {
	if (runas_pw == NULL || done_setuid)
		return;

	done_setuid = ISC_TRUE;

#ifdef HAVE_LINUXTHREADS
	if (!non_root_caps)
		ns_main_earlyfatal(
		   "-u not supported on Linux kernels older than 2.3.99-pre3");
#endif	

	if (setgid(runas_pw->pw_gid) < 0)
		ns_main_earlyfatal("setgid(): %s", strerror(errno));

	if (setuid(runas_pw->pw_uid) < 0)
		ns_main_earlyfatal("setuid(): %s", strerror(errno));
}

void
ns_os_minprivs(void) {
#ifdef HAVE_LINUX_CAPABILITY_H
#if defined(HAVE_LINUX_PRCTL_H) && defined(PR_SET_KEEPCAPS)
	linux_keepcaps();
	ns_os_changeuser();
#endif

	linux_minprivs();

#endif /* HAVE_LINUX_CAPABILITY_H */
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
