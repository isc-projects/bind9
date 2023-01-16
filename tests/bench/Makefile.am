include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	-I$(top_srcdir)/fuzz

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)

noinst_PROGRAMS =		\
	ascii			\
	compress		\
	iterated_hash		\
	dns_name_fromwire	\
	siphash

dns_name_fromwire_SOURCES =		\
	$(top_builddir)/fuzz/old.c	\
	$(top_builddir)/fuzz/old.h	\
	dns_name_fromwire.c
