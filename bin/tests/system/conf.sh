# 
# Common configuration data for system tests, to be sourced into
# other shell scripts.
#

TOP="`cd ../../..; pwd`"

NAMED=$TOP/bin/named/named
KEYGEN=$TOP/bin/tests/keygen
SIGNER=$TOP/bin/tests/signer
KEYSETTOOL=$TOP/bin/tests/keysettool

SUBDIRS="xfer dnssec xferquota"

export NAMED KEYGEN SIGNER KEYSETTOOL
