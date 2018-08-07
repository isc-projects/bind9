ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

SUBDIRS = # . samples

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h	\
	$(ALWAYS_DEFINES)

# dummy definitions to allow appending from the fragments
lib_LTLIBRARIES =
BUILT_SOURCES =
CLEANFILES =

include $(top_srcdir)/lib/isc/Makefile.inc
include $(top_srcdir)/lib/isccc/Makefile.inc
include $(top_srcdir)/lib/dns/Makefile.inc
include $(top_srcdir)/lib/ns/Makefile.inc
include $(top_srcdir)/lib/isccfg/Makefile.inc
include $(top_srcdir)/lib/bind9/Makefile.inc
include $(top_srcdir)/lib/irs/Makefile.inc
