include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	-DRNDC_KEYFILE=\"${sysconfdir}/rndc.key\"

LDADD =				\
	libconfgen.la		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)

noinst_LTLIBRARIES = libconfgen.la

libconfgen_la_SOURCES =		\
	include/confgen/os.h	\
	keygen.h		\
	keygen.c		\
	util.h			\
	util.c			\
	unix/os.c

sbin_PROGRAMS = ddns-confgen rndc-confgen

install-exec-hook:
	ln -f $(DESTDIR)$(sbindir)/ddns-confgen \
	      $(DESTDIR)$(sbindir)/tsig-confgen

uninstall-hook:
	-rm -f $(DESTDIR)$(sbindir)/tsig-confgen
