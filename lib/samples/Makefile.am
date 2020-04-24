include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBIRS_CFLAGS)

noinst_PROGRAMS =		\
	resolve			\
	sample-async		\
	sample-update		\
	sample-request		\
	nsprobe

resolve_SOURCES = resolve.c
resolve_LDADD = $(LIBISC_LIBS) $(LIBIRS_LIBS) $(LIBDNS_LIBS)

sample_async_SOURCES = sample-async.c
sample_async_LDADD = $(LIBISC_LIBS) $(LIBDNS_LIBS)

sample_update_SOURCES = sample-update.c
sample_update_LDADD = $(LIBISC_LIBS) $(LIBDNS_LIBS)

sample_request_SOURCES = sample-request.c
sample_request_LDADD = $(LIBISC_LIBS) $(LIBDNS_LIBS)

nsprobe_SOURCES = nsprobe.c
nsprobe_LDADD = $(LIBISC_LIBS) $(LIBDNS_LIBS)
