#
# bind 8 multi-host make
# PLATFORM set in the environment by cron
#

MODULE	= bind
BASE	= /build
BDIR	= $(BASE)/$(MODULE)
RDIR	= /proj/build-reports/bind8/hosts/$(PLATFORM)
SDIR	= $(HOME)/b8t/src
CVSROOT	= /proj/cvs/isc

all:	clobber populate config build

clobber:
	@echo "CLOBBBER `date`"
	@if test ! -d $(BASE) ; then mkdir -p $(BASE) ; fi 
	@rm -fr $(BDIR)
	@echo "DONE `date`"

populate:
	@echo "POPULATE `date`"
	@( cd $(BASE) && tar -xvf $(SDIR)/$(MODULE).tar ) > $(RDIR)/.populate 2>&1
	@echo "DONE `date`"

tarsrc:
	@echo "TARSRC `date`"
	@rm -fr $(SDIR)/$(MODULE)
	@( cd $(SDIR) && cvs -d $(CVSROOT) checkout $(MODULE) )
	@( cd $(SDIR) && tar -cvf $(MODULE).tar $(MODULE) )
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
