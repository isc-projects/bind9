#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2010, 2012, 2014-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Run a system test.
#

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

stopservers=true
clean=true
baseport=5300
dateargs="-R"

while getopts "knp:d:" flag; do
    case "$flag" in
	k) stopservers=false ;;
	n) clean=false ;;
	p) baseport=$OPTARG ;;
	d) dateargs=$OPTARG ;;
	*) exit 1 ;;
    esac
done
shift $(($OPTIND - 1))
OPTIND=1

test $# -gt 0 || { echo "usage: $0 [-k|-n|-p <PORT>] test-directory" >&2; exit 1; }

test=$1
shift

test -d $test || { echofail "$0: $test: no such test" >&2; exit 1; }

# Validate the port number and obtain other port numbers.
. $SYSTEMTESTTOP/getopts.sh -p "$baseport"

echoinfo "S:$test:`date $dateargs`" >&2
echoinfo "T:$test:1:A" >&2
echoinfo "A:$test:System test $test" >&2
echoinfo "I:$test:PORTRANGE:${portlow} - ${porthigh}"

if [ x${PERL:+set} = x ]
then
    echowarn "I:$test:Perl not available.  Skipping test." >&2
    echowarn "R:$test:UNTESTED" >&2
    echoinfo "E:$test:`date $dateargs`" >&2
    exit 0;
fi

# Check for test-specific prerequisites.
test ! -f $test/prereq.sh || ( cd $test && $SHELL prereq.sh -p "$port" -- "$@" )
result=$?

if [ $result -eq 0 ]; then
    : prereqs ok
else
    echowarn "I:$test:Prerequisites missing, skipping test." >&2
    [ $result -eq 255 ] && echowarn "R:$test:SKIPPED" || echowarn "R:$test:UNTESTED"
    echoinfo "E:$test:`date $dateargs`" >&2
    exit 0
fi

# Test sockets after the prerequisites has been setup
$PERL testsock.pl -p "${port}" || {
    echowarn "I:$test:Network interface aliases not set up.  Skipping test." >&2;
    echowarn "R:$test:UNTESTED" >&2;
    echoinfo "E:$test:`date $dateargs`" >&2;
    exit 0;
}

# Check for PKCS#11 support
if
    test ! -f $test/usepkcs11 || $SHELL cleanpkcs11.sh
then
    : pkcs11 ok
else
    echowarn "I:$test:Need PKCS#11, skipping test." >&2
    echowarn "R:$test:PKCS11ONLY" >&2
    echoinfo "E:$test:`date $dateargs`" >&2
    exit 0
fi

# Set up any dynamically generated test data
if test -f $test/setup.sh
then
   ( cd $test && $SHELL setup.sh -p "$port" -- "$@" )
fi

# Start name servers running
$PERL start.pl --port $port $test || { echofail "R:$test:FAIL"; echoinfo "E:$test:`date $dateargs`"; exit 1; }

# Run the tests
( cd $test ; $SHELL tests.sh -p "$port" -- "$@" )
status=$?

if $stopservers
then
    :
else
    exit $status
fi

# Shutdown
$PERL stop.pl $test

status=`expr $status + $?`

if [ $status != 0 ]; then
	echofail "R:$test:FAIL"
	# Don't clean up - we need the evidence.
	find . -name core -exec chmod 0644 '{}' \;
else
	echopass "R:$test:PASS"
    if $clean
    then
        rm -f $SYSTEMTESTTOP/random.data
        if test -f $test/clean.sh
        then
			( cd $test && $SHELL clean.sh "-p" "$port" -- "$@" )
        fi
        if test -d ../../../.git
        then
            git status -su --ignored $test |
            sed -n -e 's|^?? \(.*\)|I:file \1 not removed|p' \
            -e 's|^!! \(.*/named.run\)$|I:file \1 not removed|p' \
            -e 's|^!! \(.*/named.memstats\)$|I:file \1 not removed|p'
		fi
    fi
fi

echoinfo "E:$test:`date $dateargs`"

exit $status
