include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.docs

EXTRA_DIST =					\
	conf.py					\
	advanced.rst				\
	catz.rst				\
	configuration.rst			\
	dlz.rst					\
	dnssec-guide.rst			\
	dnssec.rst				\
	dyndb.rst				\
	general.rst				\
	history.rst				\
	index.rst				\
	introduction.rst			\
	logging-categories.rst			\
	managed-keys.rst			\
	manpages.rst				\
	notes.rst				\
	pkcs11.rst				\
	plugins.rst				\
	reference.rst				\
	requirements.rst			\
	security.rst				\
	troubleshooting.rst			\
	../dnssec-guide				\
	../misc/acl.grammar.rst			\
	../misc/controls.grammar.rst		\
	../misc/delegation-only.zoneopt.rst	\
	../misc/forward.zoneopt.rst		\
	../misc/hint.zoneopt.rst		\
	../misc/in-view.zoneopt.rst		\
	../misc/key.grammar.rst			\
	../misc/logging.grammar.rst		\
	../misc/managed-keys.grammar.rst	\
	../misc/master.zoneopt.rst		\
	../misc/mirror.zoneopt.rst		\
	../misc/options.grammar.rst		\
	../misc/primaries.grammar.rst		\
	../misc/redirect.zoneopt.rst		\
	../misc/server.grammar.rst		\
	../misc/slave.zoneopt.rst		\
	../misc/static-stub.zoneopt.rst		\
	../misc/statistics-channels.grammar.rst	\
	../misc/stub.zoneopt.rst		\
	../misc/trusted-keys.grammar.rst	\
	../notes/*.rst

html-local:
	$(AM_V_SPHINX)$(SPHINX_BUILD) -b html -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html

install-html-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL) -D $(SPHINXBUILDDIR)/html/*.html $(DESTDIR)/$(docdir)/
	cp -R $(SPHINXBUILDDIR)/html/_static/ $(DESTDIR)/$(docdir)/_static/

singlehtml:
	$(AM_V_SPHINX)$(SPHINX_BUILD) -b singlehtml -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/singlehtml

install-singlehtml: singlehtml
	$(INSTALL) -d $(DESTDIR)/$(docdir) $(DESTDIR)/$(docdir)/_static
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/singlehtml/*.html $(DESTDIR)/$(docdir)/
	cp -R $(SPHINXBUILDDIR)/singlehtml/_static/* $(DESTDIR)/$(docdir)/_static/

epub:
	$(AM_V_SPHINX)$(SPHINX_BUILD) -b epub -A today=$(RELEASE_DATE) -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/epub

install-epub:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/epub/*.epub $(DESTDIR)/$(docdir)/

if HAVE_XELATEX
pdf-local:
	$(AM_V_SPHINX)$(SPHINX_BUILD) -b latex -d $(SPHINXBUILDDIR)/doctrees $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/latex
	$(MAKE) -C $(SPHINXBUILDDIR)/latex all-pdf

install-pdf-local:
	$(INSTALL) -d $(DESTDIR)/$(docdir)
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/latex/*.pdf $(DESTDIR)/$(docdir)/
endif

clean-local:
	-rm -rf $(SPHINXBUILDDIR)

doc-local: html singlehtml pdf epub
