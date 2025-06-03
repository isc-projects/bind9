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

/*! \file */
#include <stdarg.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h> /* dev_t FreeBSD 2.1 */
#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif /* ifdef HAVE_UNAME */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#ifdef HAVE_TZSET
#include <time.h>
#endif /* ifdef HAVE_TZSET */
#include <unistd.h>

#include <isc/buffer.h>
#include <isc/errno.h>
#include <isc/file.h>
#include <isc/result.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

#include <named/globals.h>
#include <named/log.h>
#include <named/main.h>
#include <named/os.h>
#ifdef HAVE_LIBSCF
#include <named/smf_globals.h>
#endif /* ifdef HAVE_LIBSCF */

static char *pidfile = NULL;
static int devnullfd = -1;

#ifndef ISC_FACILITY
#define ISC_FACILITY LOG_DAEMON
#endif /* ifndef ISC_FACILITY */

static struct passwd *runas_pw = NULL;
static bool done_setuid = false;
static int dfd[2] = { -1, -1 };
static int notify_fd = -1;

static uid_t saved_uid = (uid_t)-1;
static gid_t saved_gid = (gid_t)-1;

#if HAVE_LIBCAP

static bool non_root = false;
static bool non_root_caps = false;

#include <sys/capability.h>
#include <sys/prctl.h>

static void
linux_setcaps(cap_t caps) {
	char strbuf[ISC_STRERRORSIZE];

	if ((getuid() != 0 && !non_root_caps) || non_root) {
		return;
	}
	if (cap_set_proc(caps) < 0) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlyfatal("cap_set_proc() failed: %s:"
				      " please ensure that the capset kernel"
				      " module is loaded.  see insmod(8)",
				      strbuf);
	}
}

#define SET_CAP(flag)                                                         \
	do {                                                                  \
		cap_flag_value_t curval;                                      \
		capval = (flag);                                              \
		err = cap_get_flag(curcaps, capval, CAP_PERMITTED, &curval);  \
		if (err != -1 && curval) {                                    \
			err = cap_set_flag(caps, CAP_EFFECTIVE, 1, &capval,   \
					   CAP_SET);                          \
			if (err == -1) {                                      \
				strerror_r(errno, strbuf, sizeof(strbuf));    \
				named_main_earlyfatal("cap_set_proc failed: " \
						      "%s",                   \
						      strbuf);                \
			}                                                     \
                                                                              \
			err = cap_set_flag(caps, CAP_PERMITTED, 1, &capval,   \
					   CAP_SET);                          \
			if (err == -1) {                                      \
				strerror_r(errno, strbuf, sizeof(strbuf));    \
				named_main_earlyfatal("cap_set_proc failed: " \
						      "%s",                   \
						      strbuf);                \
			}                                                     \
		}                                                             \
	} while (0)
#define INIT_CAP                                                              \
	do {                                                                  \
		caps = cap_init();                                            \
		if (caps == NULL) {                                           \
			strerror_r(errno, strbuf, sizeof(strbuf));            \
			named_main_earlyfatal("cap_init failed: %s", strbuf); \
		}                                                             \
		curcaps = cap_get_proc();                                     \
		if (curcaps == NULL) {                                        \
			strerror_r(errno, strbuf, sizeof(strbuf));            \
			named_main_earlyfatal("cap_get_proc failed: %s",      \
					      strbuf);                        \
		}                                                             \
	} while (0)
#define FREE_CAP                   \
	{                          \
		cap_free(caps);    \
		cap_free(curcaps); \
	}                          \
	while (0)

static void
linux_initialprivs(void) {
	cap_t caps;
	cap_t curcaps;
	cap_value_t capval;
	char strbuf[ISC_STRERRORSIZE];
	int err;

	/*%
	 * We don't need most privileges, so we drop them right away.
	 * Later on linux_minprivs() will be called, which will drop our
	 * capabilities to the minimum needed to run the server.
	 */
	INIT_CAP;

	/*
	 * We need to be able to bind() to privileged ports, notably port 53!
	 */
	SET_CAP(CAP_NET_BIND_SERVICE);

	/*
	 * We need chroot() initially too.
	 */
	SET_CAP(CAP_SYS_CHROOT);

	/*
	 * We need setuid() as the kernel supports keeping capabilities after
	 * setuid().
	 */
	SET_CAP(CAP_SETUID);

	/*
	 * Since we call initgroups, we need this.
	 */
	SET_CAP(CAP_SETGID);

	/*
	 * Without this, we run into problems reading a configuration file
	 * owned by a non-root user and non-world-readable on startup.
	 */
	SET_CAP(CAP_DAC_READ_SEARCH);

	/*
	 * XXX  We might want to add CAP_SYS_RESOURCE, though it's not
	 *      clear it would work right given the way linuxthreads work.
	 * XXXDCL But since we need to be able to set the maximum number
	 * of files, the stack size, data size, and core dump size to
	 * support named.conf options, this is now being added to test.
	 */
	SET_CAP(CAP_SYS_RESOURCE);

	/*
	 * We need to be able to set the ownership of the containing
	 * directory of the pid file when we create it.
	 */
	SET_CAP(CAP_CHOWN);

	linux_setcaps(caps);

	FREE_CAP;
}

static void
linux_minprivs(void) {
	cap_t caps;
	cap_t curcaps;
	cap_value_t capval;
	char strbuf[ISC_STRERRORSIZE];
	int err;

	INIT_CAP;
	/*%
	 * Drop all privileges except the ability to bind() to privileged
	 * ports.
	 *
	 * It's important that we drop CAP_SYS_CHROOT.  If we didn't, it
	 * chroot() could be used to escape from the chrooted area.
	 */

	SET_CAP(CAP_NET_BIND_SERVICE);

	/*
	 * XXX  We might want to add CAP_SYS_RESOURCE, though it's not
	 *      clear it would work right given the way linuxthreads work.
	 * XXXDCL But since we need to be able to set the maximum number
	 * of files, the stack size, data size, and core dump size to
	 * support named.conf options, this is now being added to test.
	 */
	SET_CAP(CAP_SYS_RESOURCE);

	linux_setcaps(caps);

	FREE_CAP;
}

static void
linux_keepcaps(void) {
	char strbuf[ISC_STRERRORSIZE];
	/*%
	 * Ask the kernel to allow us to keep our capabilities after we
	 * setuid().
	 */

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
		if (errno != EINVAL) {
			strerror_r(errno, strbuf, sizeof(strbuf));
			named_main_earlyfatal("prctl() failed: %s", strbuf);
		}
	} else {
		non_root_caps = true;
		if (getuid() != 0) {
			non_root = true;
		}
	}
}

#endif /* HAVE_LIBCAP */

static void
setperms(uid_t uid, gid_t gid) {
	char strbuf[ISC_STRERRORSIZE];

	/*
	 * Drop the gid privilege first, because in some cases the gid privilege
	 * cannot be dropped after the uid privilege has been dropped.
	 */
	if (setegid(gid) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlywarning("unable to set effective gid to %d: %s",
					gid, strbuf);
	}

	if (seteuid(uid) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlywarning("unable to set effective uid to %d: %s",
					uid, strbuf);
	}
}

#ifdef __linux__
static isc_result_t
connect_systemd_notify_unix(char *path) {
	struct sockaddr_un addr;
	isc_result_t result = ISC_R_SUCCESS;
	size_t len;

	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		return ISC_R_NOSPACE;
	}

	/* Convert abstract unix sockets */
	if (addr.sun_path[0] == '@') {
		addr.sun_path[0] = '\0';
	}

	notify_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (notify_fd < 0) {
		return isc_errno_toresult(errno);
	}

	if (connect(notify_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		result = isc_errno_toresult(errno);
		close(notify_fd);
		notify_fd = -1;
	}

	return result;
}

static void
setup_systemd_notify(void) {
	isc_result_t result;
	char *path;

	REQUIRE(notify_fd == -1);

	path = getenv("NOTIFY_SOCKET");

	/* systemd notification is not set, oh well. */
	if (path == NULL) {
		return;
	}

	if (path[0] == '/' || path[0] == '@') {
		result = connect_systemd_notify_unix(path);
	} else if (strncmp(path, "vsock", 5) == 0) {
		result = ISC_R_FAMILYNOSUPPORT;
	} else {
		result = ISC_R_INVALIDPROTO;
	}

	if (result != ISC_R_SUCCESS) {
		RUNTIME_CHECK(notify_fd == -1);
		named_main_earlywarning(
			"failed to connect to notification socket '%s': %s",
			path, isc_result_totext(result));
	} else {
		RUNTIME_CHECK(notify_fd != -1);
	}
}
#else /* __linux__ */
#define setup_systemd_notify(...)
#endif /* __linux__ */

static void
setup_syslog(const char *progname) {
	int options;

	options = LOG_PID;
#ifdef LOG_NDELAY
	options |= LOG_NDELAY;
#endif /* ifdef LOG_NDELAY */
	openlog(isc_file_basename(progname), options, ISC_FACILITY);
}

void
named_os_init(const char *progname) {
	setup_syslog(progname);
	setup_systemd_notify();
#if HAVE_LIBCAP
	linux_initialprivs();
#endif /* HAVE_LIBCAP */
#ifdef SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif /* ifdef SIGXFSZ */
}

void
named_os_daemonize(void) {
	pid_t pid;
	char strbuf[ISC_STRERRORSIZE];

	if (pipe(dfd) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlyfatal("pipe(): %s", strbuf);
	}

	pid = fork();
	if (pid == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlyfatal("fork(): %s", strbuf);
	}
	if (pid != 0) {
		int n;
		/*
		 * Wait for the child to finish loading for the first time.
		 * This would be so much simpler if fork() worked once we
		 * were multi-threaded.
		 */
		(void)close(dfd[1]);
		do {
			char buf;
			n = read(dfd[0], &buf, 1);
			if (n == 1) {
				_exit(EXIT_SUCCESS);
			}
		} while (n == -1 && errno == EINTR);
		_exit(EXIT_FAILURE);
	}
	(void)close(dfd[0]);

	/*
	 * We're the child.
	 */

	if (setsid() == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlyfatal("setsid(): %s", strbuf);
	}

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
	if (devnullfd != -1) {
		if (devnullfd != STDIN_FILENO) {
			(void)close(STDIN_FILENO);
			(void)dup2(devnullfd, STDIN_FILENO);
		}
		if (devnullfd != STDOUT_FILENO) {
			(void)close(STDOUT_FILENO);
			(void)dup2(devnullfd, STDOUT_FILENO);
		}
		if (devnullfd != STDERR_FILENO && !named_g_keepstderr) {
			(void)close(STDERR_FILENO);
			(void)dup2(devnullfd, STDERR_FILENO);
		}
	}

	/*
	 * Will be closed from SOCK_CLOEXEC but should be set to -1 again before
	 * reconnecting to the notification socket.
	 */
	notify_fd = -1;
	setup_systemd_notify();
}

void
named_os_started(void) {
	char buf = 0;

	/*
	 * Signal to the parent that we started successfully.
	 */
	if (dfd[0] != -1 && dfd[1] != -1) {
		if (write(dfd[1], &buf, 1) != 1) {
			named_main_earlyfatal("unable to signal parent that we "
					      "otherwise started "
					      "successfully.");
		}
		close(dfd[1]);
		dfd[0] = dfd[1] = -1;
	}
}

void
named_os_opendevnull(void) {
	devnullfd = open("/dev/null", O_RDWR, 0);
}

void
named_os_closedevnull(void) {
	if (devnullfd != STDIN_FILENO && devnullfd != STDOUT_FILENO &&
	    devnullfd != STDERR_FILENO)
	{
		close(devnullfd);
		devnullfd = -1;
	}
}

static bool
all_digits(const char *s) {
	if (*s == '\0') {
		return false;
	}
	while (*s != '\0') {
		if (!isdigit((unsigned char)(*s))) {
			return false;
		}
		s++;
	}
	return true;
}

void
named_os_chroot(const char *root) {
	char strbuf[ISC_STRERRORSIZE];
#ifdef HAVE_LIBSCF
	named_smf_chroot = 0;
#endif /* ifdef HAVE_LIBSCF */
	if (root != NULL) {
#ifdef HAVE_CHROOT
		if (chroot(root) < 0) {
			strerror_r(errno, strbuf, sizeof(strbuf));
			named_main_earlyfatal("chroot(): %s", strbuf);
		}
#else  /* ifdef HAVE_CHROOT */
		named_main_earlyfatal("chroot(): disabled");
#endif /* ifdef HAVE_CHROOT */
		if (chdir("/") < 0) {
			strerror_r(errno, strbuf, sizeof(strbuf));
			named_main_earlyfatal("chdir(/): %s", strbuf);
		}
#ifdef HAVE_LIBSCF
		/* Set named_smf_chroot flag on successful chroot. */
		named_smf_chroot = 1;
#endif /* ifdef HAVE_LIBSCF */
	}
}

void
named_os_inituserinfo(const char *username) {
	if (username == NULL) {
		return;
	}

	if (all_digits(username)) {
		runas_pw = getpwuid((uid_t)atoi(username));
	} else {
		runas_pw = getpwnam(username);
	}
	endpwent();

	if (runas_pw == NULL) {
		named_main_earlyfatal("user '%s' unknown", username);
	}

	if (getuid() == 0) {
		char strbuf[ISC_STRERRORSIZE];
		if (initgroups(runas_pw->pw_name, runas_pw->pw_gid) < 0) {
			strerror_r(errno, strbuf, sizeof(strbuf));
			named_main_earlyfatal("initgroups(): %s", strbuf);
		}
	}
}

void
named_os_restoreuser(void) {
	if (runas_pw == NULL || done_setuid) {
		return;
	}

	REQUIRE(saved_uid != (uid_t)-1);
	REQUIRE(saved_gid != (gid_t)-1);

	setperms(saved_uid, saved_gid);
}

void
named_os_changeuser(bool permanent) {
	char strbuf[ISC_STRERRORSIZE];
	if (runas_pw == NULL || done_setuid) {
		return;
	}

	if (!permanent) {
		saved_uid = getuid();
		saved_gid = getgid();

		setperms(runas_pw->pw_uid, runas_pw->pw_gid);

		return;
	}

	done_setuid = true;

	if (setgid(runas_pw->pw_gid) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlyfatal("setgid(): %s", strbuf);
	}

	if (setuid(runas_pw->pw_uid) == -1) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlyfatal("setuid(): %s", strbuf);
	}

#if HAVE_LIBCAP
	/*
	 * Restore the ability of named to drop core after the setuid()
	 * call has disabled it.
	 */
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlywarning("prctl(PR_SET_DUMPABLE) failed: %s",
					strbuf);
	}

	linux_minprivs();
#endif /* HAVE_LIBCAP */
}

uid_t
named_os_uid(void) {
	if (runas_pw == NULL) {
		return 0;
	}
	return runas_pw->pw_uid;
}

void
named_os_adjustnofile(void) {
	int r;
	struct rlimit rl;
	rlim_t rlim_old;
	char strbuf[ISC_STRERRORSIZE];

	r = getrlimit(RLIMIT_NOFILE, &rl);
	if (r != 0) {
		goto fail;
	}

	rlim_old = rl.rlim_cur;

	if (rl.rlim_cur == rl.rlim_max) {
		isc_log_write(named_g_lctx, NAMED_LOGCATEGORY_GENERAL,
			      NAMED_LOGMODULE_MAIN, ISC_LOG_NOTICE,
			      "the limit on open files is already at the "
			      "maximum allowed value: "
			      "%" PRIu64,
			      (uint64_t)rl.rlim_max);
		return;
	}

	rl.rlim_cur = rl.rlim_max;
	r = setrlimit(RLIMIT_NOFILE, &rl);
	if (r != 0) {
		goto fail;
	}

	isc_log_write(named_g_lctx, NAMED_LOGCATEGORY_GENERAL,
		      NAMED_LOGMODULE_MAIN, ISC_LOG_NOTICE,
		      "adjusted limit on open files from "
		      "%" PRIu64 " to "
		      "%" PRIu64,
		      (uint64_t)rlim_old, (uint64_t)rl.rlim_cur);
	return;

fail:
	strerror_r(errno, strbuf, sizeof(strbuf));
	named_main_earlywarning("adjusting limit on open files failed: %s",
				strbuf);
	return;
}

void
named_os_minprivs(void) {
#if HAVE_LIBCAP
	linux_keepcaps();
	named_os_changeuser(true);
	linux_minprivs();
#endif /* HAVE_LIBCAP */
}

static int
safe_open(const char *filename, mode_t mode, bool append) {
	int fd;
	struct stat sb;

	if (stat(filename, &sb) == -1) {
		if (errno != ENOENT) {
			return -1;
		}
	} else if ((sb.st_mode & S_IFREG) == 0) {
		errno = EOPNOTSUPP;
		return -1;
	}

	if (append) {
		fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, mode);
	} else {
		if (unlink(filename) < 0 && errno != ENOENT) {
			return -1;
		}
		fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, mode);
	}
	return fd;
}

static void
cleanup_pidfile(void) {
	int n;
	if (pidfile != NULL) {
		n = unlink(pidfile);
		if (n == -1 && errno != ENOENT) {
			named_main_earlywarning("unlink '%s': failed", pidfile);
		}
		free(pidfile);
	}
	pidfile = NULL;
}

/*
 * Ensure that a directory exists.
 * NOTE: This function overwrites the '/' characters in 'filename' with
 * nulls. The caller should copy the filename to a fresh buffer first.
 */
static int
mkdirpath(char *filename, void (*report)(const char *, ...)) {
	char *slash = strrchr(filename, '/');
	char strbuf[ISC_STRERRORSIZE];
	unsigned int mode;

	if (slash != NULL && slash != filename) {
		struct stat sb;
		*slash = '\0';

		if (stat(filename, &sb) == -1) {
			if (errno != ENOENT) {
				strerror_r(errno, strbuf, sizeof(strbuf));
				(*report)("couldn't stat '%s': %s", filename,
					  strbuf);
				goto error;
			}
			if (mkdirpath(filename, report) == -1) {
				goto error;
			}
			/*
			 * Handle "//", "/./" and "/../" in path.
			 */
			if (!strcmp(slash + 1, "") || !strcmp(slash + 1, ".") ||
			    !strcmp(slash + 1, ".."))
			{
				*slash = '/';
				return 0;
			}
			mode = S_IRUSR | S_IWUSR | S_IXUSR; /* u=rwx */
			mode |= S_IRGRP | S_IXGRP;	    /* g=rx */
			mode |= S_IROTH | S_IXOTH;	    /* o=rx */
			if (mkdir(filename, mode) == -1) {
				strerror_r(errno, strbuf, sizeof(strbuf));
				(*report)("couldn't mkdir '%s': %s", filename,
					  strbuf);
				goto error;
			}
			if (runas_pw != NULL &&
			    chown(filename, runas_pw->pw_uid,
				  runas_pw->pw_gid) == -1)
			{
				strerror_r(errno, strbuf, sizeof(strbuf));
				(*report)("couldn't chown '%s': %s", filename,
					  strbuf);
			}
		}
		*slash = '/';
	}
	return 0;

error:
	*slash = '/';
	return -1;
}

FILE *
named_os_openfile(const char *filename, mode_t mode, bool switch_user) {
	char strbuf[ISC_STRERRORSIZE], *f;
	FILE *fp;
	int fd;

	/*
	 * Make the containing directory if it doesn't exist.
	 */
	f = strdup(filename);
	if (f == NULL) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlywarning("couldn't strdup() '%s': %s", filename,
					strbuf);
		return NULL;
	}
	if (mkdirpath(f, named_main_earlywarning) == -1) {
		free(f);
		return NULL;
	}
	free(f);

	if (switch_user && runas_pw != NULL) {
		/*
		 * Temporarily set UID/GID to the one we'll be running with
		 * eventually.
		 */
		named_os_changeuser(false);

		fd = safe_open(filename, mode, false);

		/* Restore UID/GID to previous uid/gid */
		named_os_restoreuser();

		if (fd == -1) {
			fd = safe_open(filename, mode, false);
			if (fd != -1) {
				named_main_earlywarning("Required root "
							"permissions to open "
							"'%s'.",
							filename);
			} else {
				named_main_earlywarning("Could not open "
							"'%s'.",
							filename);
			}
			named_main_earlywarning("Please check file and "
						"directory permissions "
						"or reconfigure the filename.");
		}
	} else {
		fd = safe_open(filename, mode, false);
	}

	if (fd < 0) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlywarning("could not open file '%s': %s",
					filename, strbuf);
		return NULL;
	}

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		named_main_earlywarning("could not fdopen() file '%s': %s",
					filename, strbuf);
	}

	return fp;
}

void
named_os_writepidfile(const char *filename, bool first_time) {
	FILE *fh;
	pid_t pid;
	char strbuf[ISC_STRERRORSIZE];
	void (*report)(const char *, ...);

	/*
	 * The caller must ensure any required synchronization.
	 */

	report = first_time ? named_main_earlyfatal : named_main_earlywarning;

	cleanup_pidfile();

	if (filename == NULL) {
		return;
	}

	pidfile = strdup(filename);
	if (pidfile == NULL) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		(*report)("couldn't strdup() '%s': %s", filename, strbuf);
		return;
	}

	fh = named_os_openfile(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
			       first_time);
	if (fh == NULL) {
		cleanup_pidfile();
		return;
	}
	pid = getpid();
	if (fprintf(fh, "%ld\n", (long)pid) < 0) {
		(*report)("fprintf() to pid file '%s' failed", filename);
		(void)fclose(fh);
		cleanup_pidfile();
		return;
	}
	if (fflush(fh) == EOF) {
		(*report)("fflush() to pid file '%s' failed", filename);
		(void)fclose(fh);
		cleanup_pidfile();
		return;
	}
	(void)fclose(fh);
}

void
named_os_shutdown(void) {
	closelog();
	cleanup_pidfile();
}

void
named_os_shutdownmsg(char *command, isc_buffer_t *text) {
	char *last, *ptr;
	pid_t pid;

	/* Skip the command name. */
	if (strtok_r(command, " \t", &last) == NULL) {
		return;
	}

	if ((ptr = strtok_r(NULL, " \t", &last)) == NULL) {
		return;
	}

	if (strcmp(ptr, "-p") != 0) {
		return;
	}

	pid = getpid();

	(void)isc_buffer_printf(text, "pid: %ld", (long)pid);
}

void
named_os_tzset(void) {
#ifdef HAVE_TZSET
	tzset();
#endif /* ifdef HAVE_TZSET */
}

#ifdef HAVE_UNAME
static char unamebuf[sizeof(struct utsname)];
#else
static const char unamebuf[] = { "unknown architecture" };
#endif
static const char *unamep = NULL;

static void
getuname(void) {
#ifdef HAVE_UNAME
	struct utsname uts;

	memset(&uts, 0, sizeof(uts));
	if (uname(&uts) < 0) {
		snprintf(unamebuf, sizeof(unamebuf), "unknown architecture");
		return;
	}

	snprintf(unamebuf, sizeof(unamebuf), "%s %s %s %s", uts.sysname,
		 uts.machine, uts.release, uts.version);
#endif /* ifdef HAVE_UNAME */
	unamep = unamebuf;
}

const char *
named_os_uname(void) {
	if (unamep == NULL) {
		getuname();
	}
	return unamep;
}

#ifdef __linux__
void
named_os_notify_systemd(const char *restrict format, ...) {
	char buffer[512];
	va_list ap;
	int len;

	if (notify_fd == -1 || format == NULL) {
		return;
	}

	va_start(ap, format);
	len = vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	/* Be very loud if notification is too long */
	RUNTIME_CHECK(len > 0 && len < (int)sizeof(buffer));

	if (write(notify_fd, buffer, len) != len) {
		isc_log_write(named_g_lctx, NAMED_LOGCATEGORY_GENERAL,
			      NAMED_LOGMODULE_MAIN, ISC_LOG_ERROR,
			      "failed writing to notification socket '%s'",
			      isc_result_totext(isc_errno_toresult(errno)));
	}
}

void
named_os_notify_close(void) {
	if (notify_fd != -1) {
		close(notify_fd);
		notify_fd = -1;
	}
}
#endif /* __linux__ */
