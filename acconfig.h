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

/* define if you need inet_aton() */
#undef NEED_INET_ATON

/* define if you need inet_ntop() */
#undef NEED_INET_NTOP

/* define if you need inet_pton() */
#undef NEED_INET_PTON

/* define if you need AF_INET6 */
#undef NEED_AF_INET6

/* define if your struct sockaddr has a sa_len member */
#undef HAVE_SA_LEN

/* define on DEC OSF to enable 4.4BSD style sa_len support */
#undef _SOCKADDR_LEN

/* define if your system needs pthread_init() before using pthreads */
#undef NEED_PTHREAD_INIT

/* define if your system has sigwait() */
#undef HAVE_SIGWAIT

/* define on Solaris to get sigwait() to work using pthreads semantics */
#undef _POSIX_PTHREAD_SEMANTICS
