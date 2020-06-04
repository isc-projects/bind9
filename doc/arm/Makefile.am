include $(top_srcdir)/Makefile.top
include $(top_srcdir)/Makefile.docs

EXTRA_DIST =				\
	conf.py				\
	acl.grammar.rst			\
	advanced.rst			\
	catz.rst			\
	configuration.rst		\
	controls.grammar.rst		\
	delegation-only.zoneopt.rst	\
	dlz.rst				\
	dnssec-keys.grammar.rst		\
	dnssec.rst			\
	dyndb.rst			\
	forward.zoneopt.rst		\
	general.rst			\
	hint.zoneopt.rst		\
	history.rst			\
	in-view.zoneopt.rst		\
	index.rst			\
	introduction.rst		\
	key.grammar.rst			\
	logging-categories.rst		\
	logging.grammar.rst		\
	managed-keys.grammar.rst	\
	managed-keys.rst		\
	manpages.rst			\
	master.zoneopt.rst		\
	masters.grammar.rst		\
	mirror.zoneopt.rst		\
	notes.rst			\
	options.grammar.rst		\
	pkcs11.rst			\
	plugins.rst			\
	redirect.zoneopt.rst		\
	reference.rst			\
	requirements.rst		\
	security.rst			\
	server.grammar.rst		\
	slave.zoneopt.rst		\
	static-stub.zoneopt.rst		\
	statistics-channels.grammar.rst	\
	stub.zoneopt.rst		\
	troubleshooting.rst		\
	trusted-keys.grammar.rst

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
	$(INSTALL_DATA) $(SPHINXBUILDDIR)/epub/KnotDNS.epub $(DESTDIR)/$(docdir)/

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
