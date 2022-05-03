include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.docs

OPTIONS_FILES =				\
	rndc.grammar			\
	options				\
	options.active			\
	primary.zoneopt			\
	secondary.zoneopt			\
	mirror.zoneopt			\
	forward.zoneopt			\
	hint.zoneopt			\
	stub.zoneopt			\
	static-stub.zoneopt		\
	redirect.zoneopt		\
	delegation-only.zoneopt		\
	in-view.zoneopt			\
	../../bin/named/named.conf.rst	\
	primary.zoneopt.rst		\
	secondary.zoneopt.rst		\
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
	primaries.grammar.rst		\
	options.grammar.rst		\
	server.grammar.rst		\
	statistics-channels.grammar.rst	\
	tls.grammar.rst			\
	trust-anchors.grammar.rst	\
	managed-keys.grammar.rst	\
	trusted-keys.grammar.rst	\
	http.grammar.rst		\
	parental-agents.grammar.rst

EXTRA_DIST =			\
	$(OPTIONS_FILES)	\
	format-options.pl	\
	parsegrammar.py		\
	rst-grammars.pl		\
	rst-options.pl		\
	rst-zoneopt.pl		\
	sort-options.pl

if MAINTAINER_MODE

MAINTAINERCLEANFILES = $(OPTIONS_FILES)

noinst_PROGRAMS = cfg_test

cfg_test_CPPFLAGS =			\
	$(AM_CPPFLAGS)			\
	$(LIBISC_CFLAGS)		\
	$(LIBDNS_CFLAGS)		\
	$(LIBISCCFG_CFLAGS)

cfg_test_LDADD =			\
	$(LIBISC_LIBS)			\
	$(LIBDNS_LIBS)			\
	$(LIBISCCFG_LIBS)

BUILT_SOURCES =				\
	$(OPTIONS_FILES)

rndc.grammar: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --rndc --grammar | $(PERL) $(srcdir)/sort-options.pl > $@

options: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --named --grammar | $(PERL) $(srcdir)/sort-options.pl > $@

options.active: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --named --grammar --active | $(PERL) $(srcdir)/sort-options.pl > $@

primary.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar primary --active > $@

secondary.zoneopt: cfg_test
	$(AM_V_CFG_TEST)$(builddir)/cfg_test --zonegrammar secondary --active > $@

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

../../bin/named/named.conf.rst: options.active rst-options.pl delegation-only.zoneopt.rst forward.zoneopt.rst hint.zoneopt.rst in-view.zoneopt.rst mirror.zoneopt.rst primary.zoneopt.rst redirect.zoneopt.rst secondary.zoneopt.rst static-stub.zoneopt.rst stub.zoneopt.rst
	$(AM_V_RST_OPTIONS)$(PERL) $(srcdir)/rst-options.pl options.active > $@

primary.zoneopt.rst: primary.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl primary.zoneopt > $@

secondary.zoneopt.rst: secondary.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl secondary.zoneopt > $@

mirror.zoneopt.rst: mirror.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl mirror.zoneopt > $@

forward.zoneopt.rst: forward.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl forward.zoneopt > $@

hint.zoneopt.rst: hint.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl hint.zoneopt > $@

stub.zoneopt.rst: stub.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl stub.zoneopt > $@

static-stub.zoneopt.rst: static-stub.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl static-stub.zoneopt > $@

redirect.zoneopt.rst: redirect.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl redirect.zoneopt > $@

delegation-only.zoneopt.rst: delegation-only.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl delegation-only.zoneopt > $@

in-view.zoneopt.rst: in-view.zoneopt rst-zoneopt.pl
	$(AM_V_RST_ZONEOPT)$(PERL) $(srcdir)/rst-zoneopt.pl in-view.zoneopt > $@

acl.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active acl > $@

controls.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active controls > $@

dnssec-policy.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active dnssec-policy > $@

key.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active key > $@

logging.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active logging > $@

primaries.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active primaries > $@

options.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active options > $@

server.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active server > $@

statistics-channels.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active statistics-channels > $@

tls.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active tls > $@

trust-anchors.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active trust-anchors > $@

managed-keys.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active managed-keys > $@

trusted-keys.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active trusted-keys > $@

http.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active http > $@

parental-agents.grammar.rst: options.active rst-grammars.pl
	$(AM_V_RST_GRAMMARS)$(PERL) $(srcdir)/rst-grammars.pl options.active parental-agents > $@

endif
