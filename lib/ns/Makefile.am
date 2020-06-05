include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=				\
	-DNAMED_PLUGINDIR=\"$(libdir)/named\"

lib_LTLIBRARIES = libns.la

libns_ladir = $(includedir)/ns

libns_la_HEADERS =			\
	include/ns/client.h		\
	include/ns/hooks.h		\
	include/ns/interfacemgr.h	\
	include/ns/lib.h		\
	include/ns/listenlist.h		\
	include/ns/log.h		\
	include/ns/notify.h		\
	include/ns/query.h		\
	include/ns/server.h		\
	include/ns/sortlist.h		\
	include/ns/stats.h		\
	include/ns/types.h		\
	include/ns/update.h		\
	include/ns/xfrout.h

libns_la_SOURCES =		\
	$(libns_la_HEADERS)	\
	client.c		\
	hooks.c			\
	interfacemgr.c		\
	lib.c			\
	listenlist.c		\
	log.c			\
	notify.c		\
	query.c			\
	server.c		\
	sortlist.c		\
	stats.c			\
	update.c		\
	xfrout.c

libns_la_CPPFLAGS =				\
	$(AM_CPPFLAGS)				\
	$(LIBISC_CFLAGS)			\
	$(LIBDNS_CFLAGS)			\
	$(LIBNS_CFLAGS)				\
	$(LIBLTDL_CFLAGS)

libns_la_LIBADD =	\
	$(LIBISC_LIBS)	\
	$(LIBDNS_LIBS)

libns_la_LDFLAGS =		\
	$(libns_VERSION_INFO)

if HAVE_CMOCKA
SUBDIRS = tests
endif

EXTRA_DIST = api
