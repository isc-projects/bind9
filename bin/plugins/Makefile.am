include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBISCCFG_CFLAGS)

pkglib_LTLIBRARIES = filter-aaaa.la

filter_aaaa_la_SOURCES = filter-aaaa.c
filter_aaaa_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
