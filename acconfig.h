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

/***
 *** This file is not to be included by any public header files, because
 *** it does not get installed.
 ***/
@TOP@

/* define on DEC OSF to enable 4.4BSD style sa_len support */
#undef _SOCKADDR_LEN

/* define if your system needs pthread_init() before using pthreads */
#undef NEED_PTHREAD_INIT

/* define if your system has sigwait() */
#undef HAVE_SIGWAIT

/* define if sigwait() is the UnixWare flavor */
#undef HAVE_UNIXWARE_SIGWAIT

/* define on Solaris to get sigwait() to work using pthreads semantics */
#undef _POSIX_PTHREAD_SEMANTICS

/* define if LinuxThreads is in use */
#undef HAVE_LINUXTHREADS

/* define if catgets() is available */
#undef HAVE_CATGETS

/* define if you have the NET_RT_IFLIST sysctl variable. */
#undef HAVE_IFLIST_SYSCTL

/* define if you need to #define _XPG4_2 before including sys/socket.h */
#undef NEED_XPG4_2_BEFORE_SOCKET_H

/* define if you need to #define _XOPEN_SOURCE_ENTENDED before including
 * sys/socket.h
 */
#undef NEED_XSE_BEFORE_SOCKET_H

/* define if chroot() is available */
#undef HAVE_CHROOT

/* Shut up warnings about sputaux in stdio.h on BSD/OS pre-4.1 */
#undef SHUTUP_SPUTAUX
#ifdef SHUTUP_SPUTAUX
struct __sFILE;
extern __inline int __sputaux(int _c, struct __sFILE *_p);
#endif
