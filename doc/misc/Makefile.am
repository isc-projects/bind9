include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.docs

noinst_PROGRAMS = cfg_test

cfg_test_CFLAGS =			\
	$(AM_CFLAGS)			\
	$(LIBISC_CFLAGS)		\
	$(LIBDNS_CFLAGS)		\
	$(LIBISCCFG_CFLAGS)

cfg_test_LDADD =			\
	$(LIBISC_LIBS)			\
	$(LIBDNS_LIBS)			\
	$(LIBISCCFG_LIBS)

BUILT_SOURCES =				\
	options				\
	options.active			\
	master.zoneopt			\
	slave.zoneopt			\
	mirror.zoneopt			\
	forward.zoneopt			\
	hint.zoneopt			\
	stub.zoneopt			\
	static-stub.zoneopt		\
	redirect.zoneopt		\
	delegation-only.zoneopt		\
	in-view.zoneopt			\
	../../bin/named/named.conf.rst	\
	master.zoneopt.rst		\
	slave.zoneopt.rst		\
	mirror.zoneopt.rst		\
	forward.zoneopt.rst		\
	hint.zoneopt.rst		\
	stub.zoneopt.rst		\
	static-stub.zoneopt.rst		\
	redirect.zoneopt.rst		\
	delegation-only.zoneopt.rst	\
	in-view.zoneopt.rst		\
	acl.grammar.rst			\
	controls.grammar.rst		\
	dnssec-policy.grammar.rst	\
	key.grammar.rst			\
	logging.grammar.rst		\
	masters.grammar.rst		\
	options.grammar.rst		\
	server.grammar.rst		\
	statistics-channels.grammar.rst	\
	trust-anchors.grammar.rst	\
	managed-keys.grammar.rst	\
	trusted-keys.grammar.rst

EXTRA_DIST = $(BUILT_SOURCES)
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

options: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --named --grammar | $(PERL) $(srcdir)/sort-options.pl | $(PERL) $(srcdir)/format-options.pl > $@

options.active: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --named --grammar --active | $(PERL) $(srcdir)/sort-options.pl | $(PERL) $(srcdir)/format-options.pl --strip-not-configured > $@

master.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar master --active > $@

slave.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar slave --active > $@

mirror.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar mirror --active > $@

forward.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar forward --active > $@

hint.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar hint --active > $@

stub.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar stub --active > $@

static-stub.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar static-stub --active > $@

redirect.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar redirect --active > $@

delegation-only.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar delegation-only --active > $@

in-view.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar in-view --active > $@

../../bin/named/named.conf.rst: options.active
	$(AM_V_RST_OPTIONS)$(PERL) $(srcdir)/rst-options.pl options.active > $@

master.zoneopt.rst: master.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl master.zoneopt > $@

slave.zoneopt.rst: slave.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl slave.zoneopt > $@

mirror.zoneopt.rst: mirror.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl mirror.zoneopt > $@

forward.zoneopt.rst: forward.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl forward.zoneopt > $@

hint.zoneopt.rst: hint.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl hint.zoneopt > $@

stub.zoneopt.rst: stub.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl stub.zoneopt > $@

static-stub.zoneopt.rst: static-stub.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl static-stub.zoneopt > $@

redirect.zoneopt.rst: redirect.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl redirect.zoneopt > $@

delegation-only.zoneopt.rst: delegation-only.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl delegation-only.zoneopt > $@

in-view.zoneopt.rst: in-view.zoneopt
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl in-view.zoneopt > $@

acl.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active acl > $@

controls.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active controls > $@

dnssec-policy.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active dnssec-policy > $@

key.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active key > $@

logging.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active logging > $@

masters.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active masters > $@

options.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active options > $@

server.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active server > $@

statistics-channels.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active statistics-channels > $@

trust-anchors.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active trust-anchors > $@

managed-keys.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active managed-keys > $@

trusted-keys.grammar.rst: options.active
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active trusted-keys > $@
