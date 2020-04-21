include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBNS_CFLAGS)		\
	$(LIBISCCFG_CFLAGS)	\
	$(LIBBIND9_CFLAGS)

AM_CPPFLAGS +=						\
	-DNAMED_CONFFILE=\"${sysconfdir}/named.conf\"

noinst_LTLIBRARIES = libcheck-tool.la

libcheck_tool_la_SOURCES =	\
	check-tool.h		\
	check-tool.c

LDADD =				\
	libcheck-tool.la	\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBNS_LIBS)		\
	$(LIBISCCFG_LIBS)	\
	$(LIBBIND9_LIBS)

sbin_PROGRAMS = named-checkconf named-checkzone

install-exec-hook:
	ln -f $(DESTDIR)$(sbindir)/named-checkzone \
	      $(DESTDIR)$(sbindir)/named-compilezone

uninstall-hook:
	-rm -f $(DESTDIR)$(sbindir)/named-compilezone
