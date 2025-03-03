include $(top_srcdir)/Makefile.top

AM_CPPFLAGS +=			\
	$(LIBISC_CFLAGS)	\
	$(LIBDNS_CFLAGS)	\
	$(LIBISCCFG_CFLAGS)	\
	$(GSSAPI_CFLAGS)	\
	$(KRB5_CFLAGS)		\
	$(LIBEDIT_CFLAGS)

AM_CPPFLAGS +=			\
	-DSESSION_KEYFILE=\"${localstatedir}/run/named/session.key\"

LDADD +=			\
	$(LIBISC_LIBS)		\
	$(LIBDNS_LIBS)		\
	$(LIBISCCFG_LIBS)	\
	$(GSSAPI_LIBS)		\
	$(KRB5_LIBS)		\
	$(LIBEDIT_LIBS)

bin_PROGRAMS = nsupdate
