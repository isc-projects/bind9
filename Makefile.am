ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . lib # bin unit doc

BUILT_SOURCES = bind.keys.h
CLEANFILES = bind.keys.h

bin_SCRIPTS = isc-config.sh
MANPAGES = isc-config.sh.1

#isc-config.sh.1: isc-config.sh.docbook
#	# Rules to build isc-config.sh.1 from the docbook

bind.keys.h: bind.keys Makefile
	${PERL} ${top_srcdir}/util/bindkeys.pl < ${top_srcdir}/bind.keys > $@

README: README.md
	${PANDOC} --email-obfuscation=none -s -t html README.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

HISTORY: HISTORY.md
	${PANDOC} --email-obfuscation=none -s -t html HISTORY.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

OPTIONS: OPTIONS.md
	${PANDOC} --email-obfuscation=none -s -t html OPTIONS.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

CONTRIBUTING: CONTRIBUTING.md
	${PANDOC} --email-obfuscation=none -s -t html CONTRIBUTING.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

PLATFORMS: PLATFORMS.md
	${PANDOC} --email-obfuscation=none -s -t html PLATFORMS.md | \
		${W3M} -dump -cols 75 -O ascii -T text/html | \
		sed -e '$${/^$$/d;}' > $@

unit:
	sh ${top_builddir}/unit/unittest.sh

.PHONY: unit
