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

while getopts "rnp:d:" flag; do
    case "$flag" in
	k) stopservers=false ;;
	n) clean=false ;;
	p) baseport=$OPTARG ;;
	d) dateargs=$OPTARG ;;
	r) runall="-r" ;;
	*) exit 1 ;;
    esac
done
shift `expr $OPTIND - 1`

if [ $# -eq 0 ]; then
    echofail "Usage: $0 [-k] [-n] [-p <PORT>] [-r] test-directory [test-options]" >&2;
    exit 1
fi

test=$1
shift

if [ ! -d test ]; then
    echofail "$0: $test: no such test" >&2
    exit 1
fi

# Define the number of ports allocated for each test, and the lowest and
# highest valid values for the "-p" option.
#
# The lowest valid value is one more than the highest privileged port number
# (1024).
#
# The highest valid value is calculated by noting that the value passed on the
# command line is the lowest port number in a block of "numports" consecutive
# ports and that the highest valid port number is 65,535.
numport=100
minvalid=`expr 1024 + 1`
maxvalid=`expr 65535 - $numport + 1`

test "$baseport" -eq "$baseport" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echofail "$0: $test: must specify a numeric value for the port" >&2
    exit 1
elif [ $baseport -lt $minvalid -o $baseport -gt $maxvalid  ]; then
    echofail "$0: $test: the specified port must be in the range $minvalid to $maxvalid" >&2
    exit 1
fi

# Name the first 10 ports in the set (it is assumed that each test has access
# to ten or more ports): the query port, the control port and eight extra
# ports.  Since the lowest numbered port (specified in the command line)
# will usually be a multiple of 10, the names are chosen so that if this is
# true, the last digit of EXTRAPORTn is "n".
export PORT=$baseport
export EXTRAPORT1=`expr $baseport + 1`
export EXTRAPORT2=`expr $baseport + 2`
export EXTRAPORT3=`expr $baseport + 3`
export EXTRAPORT4=`expr $baseport + 4`
export EXTRAPORT5=`expr $baseport + 5`
export EXTRAPORT6=`expr $baseport + 6`
export EXTRAPORT7=`expr $baseport + 7`
export EXTRAPORT8=`expr $baseport + 8`
export CONTROLPORT=`expr $baseport + 9`

export LOWPORT=$baseport
export HIGHPORT=`expr $baseport + $numport - 1`


echostart "S:$test:`date $dateargs`"
echoinfo  "T:$test:1:A"
echoinfo  "A:$test:System test $test"
echoinfo  "I:$test:PORTRANGE:${LOWPORT} - ${HIGHPORT}"

if [ x${PERL:+set} = x ]
then
    echowarn "I:$test:Perl not available.  Skipping test."
    echowarn "R:$test:UNTESTED"
    echoend  "E:$test:`date $dateargs`"
    exit 0;
fi

$PERL testsock.pl -p $PORT  || {
    echowarn "I:$test:Network interface aliases not set up.  Skipping test."
    echowarn "R:$test:UNTESTED"
    echoend  "E:$test:`date $dateargs`"
    exit 0;
}

# Check for test-specific prerequisites.
test ! -f $test/prereq.sh || ( cd $test && $SHELL prereq.sh "$@" )
result=$?

if [ $result -eq 0 ]; then
    : prereqs ok
else
    echowarn "I:$test:Prerequisites missing, skipping test."
    [ $result -eq 255 ] && echowarn "R:$test:SKIPPED" || echowarn "R:$test:UNTESTED"
    echoend "E:$test:`date $dateargs`"
    exit 0
fi

# Check for PKCS#11 support
if
    test ! -f $test/usepkcs11 || $SHELL cleanpkcs11.sh
then
    : pkcs11 ok
else
    echowarn "I:$test:Need PKCS#11, skipping test."
    echowarn "R:$test:PKCS11ONLY"
    echoend  "E:$test:`date $dateargs`"
    exit 0
fi

# Set up any dynamically generated test data
if test -f $test/setup.sh
then
   ( cd $test && $SHELL setup.sh "$@" )
fi

# Start name servers running
$PERL start.pl --port $PORT $test || { echofail "R:$test:FAIL"; echoend "E:$test:`date $dateargs`"; exit 1; }

# Run the tests
( cd $test ; $SHELL tests.sh "$@" )
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
    # Do not clean up - we need the evidence.
    find . -name core -exec chmod 0644 '{}' \;
else
    echopass "R:$test:PASS"
    if $clean
    then
        rm -f $SYSTEMTESTTOP/random.data
	$SHELL clean.sh $runall $test "$@"
        if test -d ../../../.git
        then
            git status -su --ignored $test | \
            sed -n -e 's|^?? \(.*\)|I:file \1 not removed|p' \
            -e 's|^!! \(.*/named.run\)$|I:file \1 not removed|p' \
            -e 's|^!! \(.*/named.memstats\)$|I:file \1 not removed|p'
	fi
    fi
fi

echoend "E:$test:`date $dateargs`"

exit $status
