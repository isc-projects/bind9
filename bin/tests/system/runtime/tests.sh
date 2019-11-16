#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
SYSTEMTESTTOP=..
. "$SYSTEMTESTTOP/conf.sh"

set -e

RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

kill_named() {
	pidfile="${1}"
	if [ ! -r "${pidfile}" ]; then
		return 1
	fi

	pid=`cat "${pidfile}" 2>/dev/null`
	if test "${pid:+set}" = "set"; then
		$KILL -15 "${pid}" >/dev/null 2>&1
		retries=10
		while [ "$retries" -gt 0 ]; do
			if ! $KILL -0 "${pid}" >/dev/null 2>&1; then
				break
			fi
			sleep 1
			retries=$((retries-1))
		done
		# Timed-out
		if [ "$retries" -eq 0 ]; then
			echo_i "failed to kill named ($pidfile)"
			return 1
		fi
	fi
	rm -f "${pidfile}"
	return 0
}

status=0
n=0

n=$((n+1))
echo_i "verifying that named started normally ($n)"
ret=0
[ -s ns2/named.pid ] || ret=1
grep "unable to listen on any configured interface" ns2/named.run > /dev/null && ret=1
grep "another named process" ns2/named.run > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

if [ ! "$CYGWIN" ]; then
    n=$((n+1))
    echo_i "verifying that named checks for conflicting listeners ($n)"
    ret=0
    (cd ns2 && $NAMED -c named-alt1.conf -D ns2-extra-1 -X other.lock -m record,size,mctx -d 99 -g -U 4 >> named2.run 2>&1 & )
    for i in 1 2 3 4 5 6 7 8 9
    do
        grep "unable to listen on any configured interface" ns2/named2.run > /dev/null && break
        sleep 1
    done
    grep "unable to listen on any configured interface" ns2/named2.run > /dev/null || ret=1
    for i in 1 2 3 4 5 6 7 8 9
    do
	grep "exiting (due to fatal error)" ns2/named2.run > /dev/null && break
	sleep 1
    done
    kill_named named.pid && ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))
fi

n=$((n+1))
echo_i "verifying that named checks for conflicting named processes ($n)"
ret=0
(cd ns2 && $NAMED -c named-alt2.conf -D runtime-ns2-extra-2 -X named.lock -m record,size,mctx -d 99 -g -U 4 >> named3.run 2>&1 & )
sleep 2
grep "another named process" ns2/named3.run > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "verifying that 'lock-file none' disables process check ($n)"
ret=0
(cd ns2 && $NAMED -c named-alt3.conf -D runtime-ns2-extra-3 -m record,size,mctx -d 99 -g -U 4 >> named4.run 2>&1 & )
sleep 2
grep "another named process" ns2/named4.run > /dev/null && ret=1
kill_named ns2/named-alt3.pid || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

if $SHELL ../testcrypto.sh -q
then
    n=$((n+1))
    echo_i "checking that named refuses to reconfigure if managed-keys-directory is set and not writable ($n)"
    ret=0
    copy_setports ns2/named-alt4.conf.in ns2/named.conf
    $RNDCCMD 10.53.0.2 reconfig > rndc.out.$n 2>&1 && ret=1
    grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 || ret=1
    sleep 1
    grep "managed-keys-directory '.*' is not writable" ns2/named.run > /dev/null 2>&1 || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named refuses to reconfigure if managed-keys-directory is unset and working directory is not writable ($n)"
    ret=0
    copy_setports ns2/named-alt5.conf.in ns2/named.conf
    $RNDCCMD 10.53.0.2 reconfig > rndc.out.$n 2>&1 && ret=1
    grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 || ret=1
    sleep 1
    grep "working directory '.*' is not writable" ns2/named.run > /dev/null 2>&1 || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named reconfigures if working directory is not writable but managed-keys-directory is ($n)"
    ret=0
    copy_setports ns2/named-alt6.conf.in ns2/named.conf
    $RNDCCMD 10.53.0.2 reconfig > rndc.out.$n 2>&1 || ret=1
    grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 && ret=1
    kill_named ns2/named.pid || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=$((status+ret))
fi

n=$((n+1))
echo_i "checking that named refuses to start if managed-keys-directory is set and not writable ($n)"
ret=0
(cd ns2 && $NAMED -c named-alt4.conf -D runtime-ns2-extra-4 -d 99 -g > named4.run 2>&1 &)
sleep 2
grep "managed-keys-directory '.*' is not writable" ns2/named4.run > /dev/null 2>&1 || ret=1
grep "exiting (due to fatal error)" ns2/named4.run > /dev/null || ret=1
kill_named ns2/named.pid && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "checking that named refuses to start if managed-keys-directory is unset and working directory is not writable ($n)"
ret=0
(cd ns2 && $NAMED -c named-alt5.conf -D runtime-ns2-extra-5 -d 99 -g > named5.run 2>&1 &)
sleep 2
grep "working directory '.*' is not writable" ns2/named5.run > /dev/null 2>&1 || ret=1
grep "exiting (due to fatal error)" ns2/named5.run > /dev/null || ret=1
kill_named ns2/named.pid && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "checking that named starts if managed-keys-directory is writable and working directory is not writable ($n)"
ret=0
(cd ns2/nope && $NAMED -c ../named-alt6.conf -D runtime-ns2-extra-6 -d 99 -g > ../named6.run 2>&1 &)
sleep 2
kill_named ns2/named.pid || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))

n=`expr $n + 1`
echo_i "verifying that named switches UID ($n)"
if [ "`id -u`" = 0 ] && [ ! "$CYGWIN" ]; then
    ret=0
    TEMP_NAMED_DIR=`mktemp -d`
    if [ -d "${TEMP_NAMED_DIR}" ]; then
        copy_setports ns2/named-alt9.conf.in "${TEMP_NAMED_DIR}/named-alt9.conf"
        export SOFTHSM2_CONF="${TEMP_NAMED_DIR}/softhsm2.conf"
        sh -x "$TOP/bin/tests/prepare-softhsm2.sh"
        chown -R nobody "${TEMP_NAMED_DIR}"
        chmod 0700 "${TEMP_NAMED_DIR}"
        ( cd "${TEMP_NAMED_DIR}" && $NAMED -u nobody -c named-alt9.conf -d 99 -g -U 4 >> named9.run 2>&1 & )
        sleep 2
        [ -s "${TEMP_NAMED_DIR}/named9.pid" ] || ret=1
        grep "loading configuration: permission denied" "${TEMP_NAMED_DIR}/named9.run" > /dev/null && ret=1
        pid=`cat "${TEMP_NAMED_DIR}/named9.pid" 2>/dev/null`
        test "${pid:+set}" = set && $KILL -15 "${pid}" >/dev/null 2>&1
        mv "${TEMP_NAMED_DIR}" ns2/
    else
        echo_i "mktemp failed"
        ret=1
    fi
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
else
    echo_i "skipped, not running as root or running on Windows"
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
