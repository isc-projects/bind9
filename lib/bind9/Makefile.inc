# Hey Emacs, this is -*- makefile-automake -*- file!

BIND9_INCLUDES = \
	-I$(top_srcdir)/lib/bind9/include

lib_LTLIBRARIES += libbind9.la

libbind9_ladir = $(include_dir)/bind9
libbind9_la_HEADERS =			\
	%reldir%/include/bind9/check.h	\
	%reldir%/include/bind9/getaddresses.h

libbind9_la_SOURCES =			\
	$(libbind9_la_HEADERS)		\
	%reldir%/check.c		\
	%reldir%/getaddresses.c

libbind9_la_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(ISC_INCLUDES)			\
	$(DNS_INCLUDES)			\
	$(ISCCFG_INCLUDES)		\
	$(BIND9_INCLUDES)		\
	$(OPENSSL_CFLAGS)		\
	$(OPENSSL_INCLUDES)

libbind9_la_LIBADD =			\
	libisc.la			\
	libdns.la			\
	libisccfg.la
