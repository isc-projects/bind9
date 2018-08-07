include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)

dyndb_LTLIBRARIES = sample.la
dyndbdir = $(abs_builddir)

sample_la_SOURCES =	\
	db.c		\
	driver.c	\
	instance.c	\
	lock.c		\
	log.c		\
	syncptr.c	\
	zone.c

sample_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
