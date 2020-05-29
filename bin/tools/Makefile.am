include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)

LDADD =				\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)

bin_PROGRAMS =			\
	arpaname		\
	named-rrchecker		\
	mdig

sbin_PROGRAMS =			\
	named-journalprint	\
	nsec3hash

arpaname_LDADD =		\
	$(LIBISC_LIBS)

mdig_CPPFLAGS =			\
	$(AM_CPPFLAGS)		\
	$(LIBBIND9_CFLAGS)

mdig_LDADD =			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBBIND9_LIBS)

if HAVE_DNSTAP
bin_PROGRAMS +=			\
	dnstap-read

dnstap_read_CPPFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(DNSTAP_CFLAGS)	\
	-I$(top_builddir)/lib/dns

dnstap_read_LDADD =		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(DNSTAP_LIBS)
endif

if HAVE_LMDB
sbin_PROGRAMS +=			\
	named-nzd2nzf

named_nzd2nzf_CFLAGS =		\
	$(AM_CPPFLAGS)		\
	$(LMDB_CFLAGS)

named_nzd2nzf_LDADD =		\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LMDB_LIBS)

endif
