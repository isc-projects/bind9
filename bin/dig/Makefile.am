include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)	\
	$(LIBIDN2_CFLAGS)	\
	$(OPENSSL_CFLAGS)	\
	$(LIBEDIT_CFLAGS)	\
	$(LIBUV_CFLAGS)		\
	$(OPENSSL_CFLAGS)

LDADD +=			\
	libdighost.la		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBISCCFG_LIBS)	\
	$(OPENSSL_LIBS)		\
	$(LIBEDIT_LIBS)		\
	$(LIBIDN2_LIBS)

noinst_LTLIBRARIES = libdighost.la

libdighost_la_SOURCES =		\
	dighost.h		\
	dighost.c

bin_PROGRAMS = dig host nslookup
