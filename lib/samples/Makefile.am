include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBIRS_CFLAGS)

noinst_PROGRAMS =		\
	resolve			\
	sample-async

resolve_SOURCES = resolve.c
resolve_LDADD = $(LIBISC_LIBS) $(LIBIRS_LIBS) $(LIBDNS_LIBS)

sample_async_SOURCES = sample-async.c
sample_async_LDADD = $(LIBISC_LIBS) $(LIBDNS_LIBS)
