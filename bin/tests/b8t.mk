#
# bind 8 multi-host make
# PLATFORM set in the environment by cron
#

MODULE	= bind
BASE	= /build
BDIR	= $(BASE)/$(MODULE)
DDIR	= $(BASE)/$(MODULE)/dst
RDIR	= /proj/build-reports/bind8/hosts/$(PLATFORM)
CVSROOT	= /proj/cvs/isc

all:	clobber checkout config build

clobber:
	@if test ! -d $(BASE) ; then mkdir -p $(BASE) ; fi 
	@echo "CLOBBBER `date`"
	@( cd $(BASE) && rm -fr $(MODULE) )
	@echo "DONE `date`"

checkout:
	@echo "CHECKOUT `date`"
	@( cd $(BASE) && cvs -d $(CVSROOT) checkout $(MODULE) )
	@echo "DONE `date`"

config:
	@echo "CONFIG `date`"
	@( cd $(BDIR)/src && make SRC=$(BDIR)/src DST=$(BDIR)/dst links ) > $(RDIR)/.config 2>&1
	@echo "DONE `date`"

build:
	@echo "BUILD `date`"
	@( cd $(BDIR)/dst && make -k clean depend all ) > $(RDIR)/.build 2>&1
	@echo "DONE `date`"

test:
	@echo "TEST `date`"
	@touch $(RDIR)/.test
	@echo "DONE `date`"
