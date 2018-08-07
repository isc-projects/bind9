# Hey Emacs, this is -*- makefile-automake -*- file!

IRS_INCLUDES = \
	-I$(top_srcdir)/lib/irs/include

lib_LTLIBRARIES += libirs.la

libirs_ladir = $(includedir)/irs
libirs_la_HEADERS =			\
	%reldir%/include/irs/context.h	\
	%reldir%/include/irs/dnsconf.h	\
	%reldir%/include/irs/resconf.h	\
	%reldir%/include/irs/types.h

libirs_la_SOURCES =			\
	$(libirs_la_HEADERS)		\
	%reldir%/context.c		\
	%reldir%/dnsconf.c		\
	%reldir%/gai_strerror.c		\
	%reldir%/getaddrinfo.c		\
	%reldir%/getnameinfo.c		\
	%reldir%/resconf.c

libirs_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(ISC_INCLUDES)			\
	$(DNS_INCLUDES)			\
	$(ISCCFG_INCLUDES)		\
	$(IRS_INCLUDES)
