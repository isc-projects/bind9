/*
 * Copyright (C) 2014, 2016, 2017  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef NAMED_SECCOMP_H
#define NAMED_SECCOMP_H 1

/*! \file */

#ifdef HAVE_LIBSECCOMP
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>
#include <seccomp.h>
#include <isc/platform.h>

/*%
 * For each architecture, the scmp_syscalls and
 * scmp_syscall_names arrays MUST be kept in sync.
 */
#ifdef __x86_64__
int scmp_syscalls[] = {
	SCMP_SYS(access),
	SCMP_SYS(open),
	SCMP_SYS(openat),
	SCMP_SYS(lseek),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(time),
	SCMP_SYS(read),
	SCMP_SYS(write),
	SCMP_SYS(close),
	SCMP_SYS(brk),
	SCMP_SYS(poll),
	SCMP_SYS(select),
	SCMP_SYS(madvise),
	SCMP_SYS(mmap),
	SCMP_SYS(munmap),
	SCMP_SYS(exit_group),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(fsync),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(setsid),
	SCMP_SYS(chdir),
	SCMP_SYS(futex),
	SCMP_SYS(stat),
	SCMP_SYS(rt_sigsuspend),
	SCMP_SYS(fstat),
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(gettimeofday),
	SCMP_SYS(getpid),
#ifdef HAVE_GETRANDOM
	SCMP_SYS(getrandom),
#endif
	SCMP_SYS(rename),
	SCMP_SYS(unlink),
	SCMP_SYS(socket),
	SCMP_SYS(sendto),
};
const char *scmp_syscall_names[] = {
	"access",
	"open",
	"openat",
	"lseek",
	"clock_gettime",
	"time",
	"read",
	"write",
	"close",
	"brk",
	"poll",
	"select",
	"madvise",
	"mmap",
	"munmap",
	"exit_group",
	"rt_sigprocmask",
	"rt_sigaction",
	"fsync",
	"rt_sigreturn",
	"setsid",
	"chdir",
	"futex",
	"stat",
	"rt_sigsuspend",
	"fstat",
	"epoll_ctl",
	"gettimeofday",
	"getpid",
#ifdef HAVE_GETRANDOM
	"getrandom",
#endif
	"rename",
	"unlink",
	"socket",
	"sendto",
};
#endif /* __x86_64__ */
#ifdef __i386__
int scmp_syscalls[] = {
	SCMP_SYS(access),
	SCMP_SYS(open),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(time),
	SCMP_SYS(read),
	SCMP_SYS(write),
	SCMP_SYS(close),
	SCMP_SYS(brk),
	SCMP_SYS(poll),
	SCMP_SYS(_newselect),
	SCMP_SYS(select),
	SCMP_SYS(madvise),
	SCMP_SYS(mmap2),
	SCMP_SYS(mmap),
	SCMP_SYS(munmap),
	SCMP_SYS(exit_group),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(sigprocmask),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(socketcall),
	SCMP_SYS(fsync),
	SCMP_SYS(sigreturn),
	SCMP_SYS(setsid),
	SCMP_SYS(chdir),
	SCMP_SYS(futex),
	SCMP_SYS(stat64),
	SCMP_SYS(rt_sigsuspend),
	SCMP_SYS(fstat64),
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(gettimeofday),
	SCMP_SYS(getpid),
#ifdef HAVE_GETRANDOM
	SCMP_SYS(getrandom),
#endif
	SCMP_SYS(unlink),
};
const char *scmp_syscall_names[] = {
	"access",
	"open",
	"clock_gettime",
	"time",
	"read",
	"write",
	"close",
	"brk",
	"poll",
	"_newselect",
	"select",
	"madvise",
	"mmap2",
	"mmap",
	"munmap",
	"exit_group",
	"rt_sigprocmask",
	"sigprocmask",
	"rt_sigaction",
	"socketcall",
	"fsync",
	"sigreturn",
	"setsid",
	"chdir",
	"futex",
	"stat64",
	"rt_sigsuspend",
	"fstat64",
	"epoll_ctl",
	"gettimeofday",
	"getpid",
#ifdef HAVE_GETRANDOM
	"getrandom",
#endif
	"unlink",
};
#endif /* __i386__ */
#endif /* HAVE_LIBSECCOMP */

#endif /* NAMED_SECCOMP_H */
