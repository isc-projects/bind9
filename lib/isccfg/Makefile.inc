# Hey Emacs, this is -*- makefile-automake -*- file!

ISCCFG_INCLUDES = \
	-I$(top_srcdir)/lib/isccfg/include

lib_LTLIBRARIES += libisccfg.la

libisccfg_ladir = $(includedir)/isccfg
libisccfg_la_HEADERS = 				\
	%reldir%/include/isccfg/aclconf.h	\
	%reldir%/include/isccfg/cfg.h		\
	%reldir%/include/isccfg/dnsconf.h	\
	%reldir%/include/isccfg/grammar.h	\
	%reldir%/include/isccfg/log.h		\
	%reldir%/include/isccfg/namedconf.h

libisccfg_la_SOURCES =				\
	$(libisccfg_la_HEADERS)			\
	%reldir%/aclconf.c			\
	%reldir%/dnsconf.c			\
	%reldir%/log.c				\
	%reldir%/namedconf.c			\
	%reldir%/parser.c

libisccfg_la_CPPFLAGS =				\
	$(AM_CPPFLAGS)				\
	$(ISC_INCLUDES)				\
	$(DNS_INCLUDES)				\
	$(ISCCFG_INCLUDES)

libisccfg_la_LIBADD =	\
	libisc.la	\
	libdns.la
