SUBDIRS = .

if HAVE_PERL
SUBDIRS += misc
endif

# Do not change this line to "SUBDIRS = man" at the top of this file: in
# maintainer mode, the "man" subdirectory depends on the "misc" subdirectory.
SUBDIRS += man

if HAVE_SPHINX_BUILD
SUBDIRS += arm
endif HAVE_SPHINX_BUILD
