
#
# makefile to configure, build and test bind9
# this is run by cron (user wpk) on aa, sol, irix, hp and aix
# $PLATFORM is set in the environment by cron
#

BASE	= $(HOME)/b9t
SDIR	= $(BASE)/src
PDIR	= $(BASE)/hosts/$(PLATFORM)
BDIR	= $(PDIR)/build

all:	clean config build test

shuffle:
	@if test -f $(PDIR)/.clean; then mv $(PDIR)/.clean $(PDIR)/.clean-last; fi
	@if test -f $(PDIR)/.build; then mv $(PDIR)/.build $(PDIR)/.build-last; fi
	@if test -f $(PDIR)/.test; then mv $(PDIR)/.test $(PDIR)/.test-last; fi

clean:	shuffle
	-@( cd $(BDIR); if test -f Makefile ; then $(MAKE) distclean ; fi ) > $(PDIR)/.clean 2>&1
 
config:
	@( cd $(BDIR); $(SDIR)/bind9/configure ) > $(PDIR)/.configure 2>&1

build:
	@( cd $(BDIR); $(MAKE) -k all ) > $(PDIR)/.build 2>&1

test:
	-@( cd $(BDIR); $(MAKE) test ) > $(PDIR)/.test 2>&1

