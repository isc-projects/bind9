# 
# Common configuration data for system tests, to be sourced into
# other shell scripts.
#

TOP="`cd ../../..; pwd`"

NAMED=$TOP/bin/named/named
KEYGEN=$TOP/bin/dnssec/dnssec-keygen
SIGNER=$TOP/bin/dnssec/dnssec-signzone
KEYSIGNER=$TOP/bin/dnssec/dnssec-signkey
KEYSETTOOL=$TOP/bin/dnssec/dnssec-makekeyset

SUBDIRS="xfer dnssec xferquota"

export NAMED KEYGEN SIGNER KEYSIGNER KEYSETTOOL
