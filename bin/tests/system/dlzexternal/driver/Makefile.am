include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)

dlzexternal_LTLIBRARIES = dlzexternal.la
dlzexternaldir = $(abs_builddir)

dlzexternal_la_SOURCES =	\
	driver.c		\
	driver.h

dlzexternal_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
