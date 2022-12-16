include $(top_srcdir)/Makefile.top

lib_LTLIBRARIES = libbind9.la

libbind9_ladir = $(includedir)/bind9

libbind9_la_HEADERS =

libbind9_la_SOURCES =		\
	$(libbind9_la_HEADERS)

libbind9_la_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBBIND9_CFLAGS)	\
	$(OPENSSL_CFLAGS)

libbind9_la_LIBADD =		\
	$(LIBNS_LIBS)		\
	$(LIBISCCFG_LIBS)	\
	$(LIBDNS_LIBS)		\
	$(LIBISC_LIBS)

libbind9_la_LDFLAGS =		\
	$(AM_LDFLAGS)		\
	-release "$(PACKAGE_VERSION)"

if HAVE_DNSTAP
libbind9_la_CPPFLAGS += $(DNSTAP_CFLAGS)
endif
