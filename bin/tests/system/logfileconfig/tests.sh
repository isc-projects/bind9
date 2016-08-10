#!/bin/sh
#
# Copyright (C) 2011-2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: tests.sh,v 1.4 2011/03/22 16:51:50 smann Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh
THISDIR=`pwd`
CONFDIR="ns1"
PLAINCONF="${THISDIR}/${CONFDIR}/named.plain"
DIRCONF="${THISDIR}/${CONFDIR}/named.dirconf"
PIPECONF="${THISDIR}/${CONFDIR}/named.pipeconf"
SYMCONF="${THISDIR}/${CONFDIR}/named.symconf"
PLAINCONF="${THISDIR}/${CONFDIR}/named.plainconf"
PLAINFILE="named_log"
DIRFILE="named_dir"
PIPEFILE="named_pipe"
SYMFILE="named_sym"
DLFILE="named_deflog"
PIDFILE="${THISDIR}/${CONFDIR}/named.pid"
myRNDC="$RNDC -c ${THISDIR}/${CONFDIR}/rndc.conf"
myNAMED="$NAMED -c ${THISDIR}/${CONFDIR}/named.conf -m record,size,mctx -T clienttest -T nosyslog -d 99 -X named.lock -U 4"

waitforpidfile() {
	for _w in 1 2 3 4 5 6 7 8 9 10
	do
		test -f $PIDFILE && break
		sleep 1
	done
}

status=0
n=0

cd $CONFDIR

n=`expr $n + 1`
echo "I:testing log file validity (named -g + only plain files allowed) ($n)"

# First run with a known good config.
echo > $PLAINFILE
cp $PLAINCONF named.conf
$myRNDC reconfig > rndc.out.test$n 2>&1
grep "reloading configuration failed" named.run > /dev/null 2>&1
if [ $? -ne 0 ]
then
	echo "I: testing plain file succeeded"
else
	echo "I: testing plain file failed (unexpected)"
	echo "I:exit status: 1"
	exit 1 
fi

# Now try directory, expect failure
n=`expr $n + 1`
echo "I: testing directory as log file (named -g) ($n)"
echo > named.run
rm -rf $DIRFILE
mkdir -p $DIRFILE >/dev/null 2>&1
if [ $? -eq 0 ]
then
	cp $DIRCONF named.conf
	echo > named.run
	$myRNDC reconfig > rndc.out.test$n 2>&1
	grep "checking logging configuration failed: invalid file" named.run > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "I: testing directory as file succeeded (UNEXPECTED)"
		echo "I:exit status: 1"
		exit 1
	else
		echo "I: testing directory as log file failed (expected)"
	fi
else
	echo "I: skipping directory test (unable to create directory)"
fi

# Now try pipe file, expect failure
n=`expr $n + 1`
echo "I: testing pipe file as log file (named -g) ($n)"
echo > named.run
rm -f $PIPEFILE
mkfifo $PIPEFILE >/dev/null 2>&1
if [ $? -eq 0 ]
then
	cp $PIPECONF named.conf
	echo > named.run
	$myRNDC reconfig > rndc.out.test$n 2>&1
	grep "checking logging configuration failed: invalid file" named.run  > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "I: testing pipe file as log file succeeded (UNEXPECTED)"
		echo "I:exit status: 1"
		exit 1
	else
		echo "I: testing pipe file as log file failed (expected)"
	fi
else
	echo "I: skipping pipe test (unable to create pipe)"
fi

# Now try symlink file to plain file, expect success 
n=`expr $n + 1`
echo "I: testing symlink to plain file as log file (named -g) ($n)"
# Assume success
echo > named.run
echo > $PLAINFILE
rm -f  $SYMFILE  $SYMFILE
ln -s $PLAINFILE $SYMFILE >/dev/null 2>&1
if [ $? -eq 0 ]
then
	cp $SYMCONF named.conf
	$myRNDC reconfig > rndc.out.test$n 2>&1
	echo > named.run
	grep "reloading configuration failed" named.run > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "I: testing symlink to plain file succeeded"
	else
		echo "I: testing symlink to plain file failed (unexpected)"
		echo "I:exit status: 1"
		exit 1
	fi
else
	echo "I: skipping symlink test (unable to create symlink)"
fi
# Stop the server and run through a series of tests with various config
# files while controlling the stop/start of the server.
# Have to stop the stock server because it uses "-g"
#
$PERL ../../stop.pl .. ns1

$myNAMED > /dev/null 2>&1

if [ $? -ne 0 ]
then
	echo "I:failed to start $myNAMED"
	echo "I:exit status: $status"
	exit $status
fi

status=0

n=`expr $n + 1`
echo "I:testing log file validity (only plain files allowed) ($n)"

# First run with a known good config.
echo > $PLAINFILE
cp $PLAINCONF named.conf
$myRNDC reconfig > rndc.out.test$n 2>&1
grep "reloading configuration failed" named.run > /dev/null 2>&1
if [ $? -ne 0 ]
then
	echo "I: testing plain file succeeded"
else
	echo "I: testing plain file failed (unexpected)"
	echo "I:exit status: 1"
	exit 1 
fi

# Now try directory, expect failure
n=`expr $n + 1`
echo "I: testing directory as log file ($n)"
echo > named.run
rm -rf $DIRFILE
mkdir -p $DIRFILE >/dev/null 2>&1
if [ $? -eq 0 ]
then
	cp $DIRCONF named.conf
	echo > named.run
	$myRNDC reconfig > rndc.out.test$n 2>&1
	grep "configuring logging: invalid file" named.run > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "I: testing directory as file succeeded (UNEXPECTED)"
		echo "I:exit status: 1"
		exit 1
	else
		echo "I: testing directory as log file failed (expected)"
	fi
else
	echo "I: skipping directory test (unable to create directory)"
fi

# Now try pipe file, expect failure
n=`expr $n + 1`
echo "I: testing pipe file as log file ($n)"
echo > named.run
rm -f $PIPEFILE
mkfifo $PIPEFILE >/dev/null 2>&1
if [ $? -eq 0 ]
then
	cp $PIPECONF named.conf
	echo > named.run
	$myRNDC reconfig > rndc.out.test$n 2>&1
	grep "configuring logging: invalid file" named.run  > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "I: testing pipe file as log file succeeded (UNEXPECTED)"
		echo "I:exit status: 1"
		exit 1
	else
		echo "I: testing pipe file as log file failed (expected)"
	fi
else
	echo "I: skipping pipe test (unable to create pipe)"
fi

# Now try symlink file to plain file, expect success 
n=`expr $n + 1`
echo "I: testing symlink to plain file as log file ($n)"
# Assume success
status=0
echo > named.run
echo > $PLAINFILE
rm -f $SYMFILE
ln -s $PLAINFILE $SYMFILE >/dev/null 2>&1
if [ $? -eq 0 ]
then
	cp $SYMCONF named.conf
	$myRNDC reconfig > rndc.out.test$n 2>&1
	echo > named.run
	grep "reloading configuration failed" named.run > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "I: testing symlink to plain file succeeded"
	else
		echo "I: testing symlink to plain file failed (unexpected)"
		echo "I:exit status: 1"
		exit 1
	fi
else
	echo "I: skipping symlink test (unable to create symlink)"
fi

status=0

n=`expr $n + 1`
echo "I:testing default logfile using named -L file ($n)"
# Now stop the server again and test the -L option
rm -f $DLFILE
$PERL ../../stop.pl .. ns1
if ! test -f $PIDFILE; then
	cp $PLAINCONF named.conf
	$myNAMED -L $DLFILE > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		echo "I:failed to start $myNAMED"
		echo "I:exit status: $status"
		exit $status
	fi

	waitforpidfile

	sleep 1
	if [ -f "$DLFILE" ]; then
		echo "I: testing default logfile using named -L succeeded"
	else
		echo "I: testing default logfile using named -L failed"
		echo "I:exit status: 1"
		exit 1
	fi
else
	echo "I:failed to cleanly stop $myNAMED"
	echo "I:exit status: 1"
	exit 1
fi

echo "I:exit status: $status"
[ $status -eq 0 ] || exit 1
