#!/bin/sh

TOP=${SYSTEMTESTTOP:=.}/../../../..

# enable the tsiggss test only if gssapi was enabled
$TOP/bin/named/named -V | grep with.gssapi | grep -v with-gssapi=no > /dev/null || {
    echo "I:BIND9 was not built with --with-gssapi"
    exit 1
}

exit 0
