
#
# makefile to configure, build and test bind9
# this is run by cron (user wpk) on aa, sol, irix, hp and aix
# $PLATFORM is set in the environment by cron
#

BASE	= /build
BDIR	= $(BASE)
MODULE	= bind9

# as it says
CVSROOT	= /proj/cvs/isc

# where the config, build and test output g oes
RDIR	= /proj/build-reports/$(MODULE)/hosts/$(PLATFORM)

all:	clobber checkout config build test

clobber:
	@if test ! -d $(BDIR) ; then mkdir -p $(BDIR) > /dev/null 2>&1 ; fi
	@echo "CLOBBBER `date`"
	( cd $(BDIR) && rm -fr $(MODULE) )
	@echo "DONE `date`"

checkout:
	@echo "CHECKOUT `date`"
	@( cd $(BDIR) && cvs -d $(CVSROOT) checkout $(MODULE) )
	@echo "DONE `date`"

config:
	@echo "CONFIG `date`"
	@( cd $(BDIR)/$(MODULE) && ./configure ) > $(RDIR)/.config 2>&1
	@echo "DONE `date`"

build:
	@echo "BUILD `date`"
	@( cd $(BDIR)/$(MODULE) && $(MAKE) -k all ) > $(RDIR)/.build 2>&1
	@echo "DONE `date`"

test:
	@echo "TEST `date`"
	-@( cd $(BDIR)/$(MODULE)/bin/tests && $(MAKE) test ) > $(RDIR)/.test 2>&1
	@echo "DONE `date`"

