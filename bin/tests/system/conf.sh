# 
# Common configuration data for system tests, to be sourced into
# other shell scripts.
#

TOP="`cd ../../..; pwd`"

NAMED=$TOP/bin/named/named
KEYGEN=$TOP/bin/tests/keygen
SIGNER=$TOP/bin/tests/signer
KEYSIGNER=$TOP/bin/tests/keysigner
KEYSETTOOL=$TOP/bin/tests/keysettool

SUBDIRS="xfer dnssec xferquota"

export NAMED KEYGEN SIGNER KEYSIGNER KEYSETTOOL
