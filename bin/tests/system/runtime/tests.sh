#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
SYSTEMTESTTOP=..
. "$SYSTEMTESTTOP/conf.sh"

set -e

RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"
NAMED_DEFAULT_ARGS="-m record,size,mctx -d 99 -g -U 4"

kill_named() {
	pidfile="${1}"
	if [ ! -r "${pidfile}" ]; then
		return 1
	fi

	pid=`cat "${pidfile}" 2>/dev/null`
	if [ "${pid:+set}" = "set" ]; then
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

check_named_log() {
	grep "$@" >/dev/null 2>&1
}

run_named() (
	dir="$1"
	shift
	run="$1"
	shift
	if cd "$dir" > /dev/null 2>&1
	then
		"${NAMED}" "$@" ${NAMED_DEFAULT_ARGS} >> "$run" 2>&1 &
		echo $!
	fi
)

check_pid() (
	return $(! $KILL -0 "${1}" >/dev/null 2>&1)
)

status=0
n=0

n=$((n+1))
echo_i "verifying that named started normally ($n)"
ret=0
[ -s ns2/named.pid ] || ret=1
grep "unable to listen on any configured interface" ns2/named.run > /dev/null && ret=1
grep "another named process" ns2/named.run > /dev/null && ret=1
if [ $ret -ne 0 ]; then echo_i "failed"; fi
status=$((status+ret))

if [ ! "$CYGWIN" ]; then
    n=$((n+1))
    echo_i "verifying that named checks for conflicting listeners ($n)"
    ret=0
    testpid=$(run_named ns2 named$n.run -c named-alt1.conf -D ns2-extra-1 -X other.lock)
    test -n "$testpid" || ret=1
    retry_quiet 10 check_named_log "unable to listen on any configured interface" ns2/named$n.run || ret=1
    retry_quiet 10 check_named_log "exiting (due to fatal error)" ns2/named$n.run || ret=1
    kill_named named.pid && ret=1
    test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))
fi

n=$((n+1))
echo_i "verifying that named checks for conflicting named processes ($n)"
ret=0
testpid=$(run_named ns2 named$n.run -c named-alt2.conf -D runtime-ns2-extra-2 -X named.lock)
test -n "$testpid" || ret=1
retry_quiet 10 check_named_log "another named process" ns2/named$n.run || ret=1
test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
test -n "$testpid" && $KILL -15 $testpid > kill$n.out 2>&1 && ret=1
test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
if [ $ret -ne 0 ]; then echo_i "failed"; fi
status=$((status+ret))

n=$((n+1))
echo_i "verifying that 'lock-file none' disables process check ($n)"
ret=0
testpid=$(run_named ns2 named$n.run -c named-alt3.conf -D runtime-ns2-extra-3)
test -n "$testpid" || ret=1
retry_quiet 10 check_named_log "running$" ns2/named$n.run || ret=1
grep "another named process" ns2/named$n.run > /dev/null && ret=1
kill_named ns2/named-alt3.pid || ret=1
test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
if [ $ret -ne 0 ]; then echo_i "failed"; fi
status=$((status+ret))

if $SHELL ../testcrypto.sh -q
then
    n=$((n+1))
    echo_i "checking that named refuses to reconfigure if managed-keys-directory is set and not writable ($n)"
    ret=0
    copy_setports ns2/named-alt4.conf.in ns2/named.conf
    $RNDCCMD 10.53.0.2 reconfig > rndc.out.$n 2>&1 && ret=1
    grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 || ret=1
    retry_quiet 10 check_named_log "managed-keys-directory '.*' is not writable" ns2/named.run || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named refuses to reconfigure if managed-keys-directory is unset and working directory is not writable ($n)"
    ret=0
    copy_setports ns2/named-alt5.conf.in ns2/named.conf
    $RNDCCMD 10.53.0.2 reconfig > rndc.out.$n 2>&1 && ret=1
    grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 || ret=1
    retry_quiet 10 check_named_log "working directory '.*' is not writable" ns2/named.run || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named reconfigures if working directory is not writable but managed-keys-directory is ($n)"
    ret=0
    copy_setports ns2/named-alt6.conf.in ns2/named.conf
    $RNDCCMD 10.53.0.2 reconfig > rndc.out.$n 2>&1 || ret=1
    grep "failed: permission denied" rndc.out.$n > /dev/null 2>&1 && ret=1
    kill_named ns2/named.pid || ret=1
    test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named refuses to start if managed-keys-directory is set and not writable ($n)"
    ret=0
    testpid=$(run_named ns2 named$n.run -c named-alt4.conf -D runtime-ns2-extra-4)
    retry_quiet 10 check_named_log "exiting (due to fatal error)" ns2/named$n.run || ret=1
    grep "managed-keys-directory '.*' is not writable" ns2/named$n.run > /dev/null 2>&1 || ret=1
    kill_named ns2/named.pid && ret=1
    test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named refuses to start if managed-keys-directory is unset and working directory is not writable ($n)"
    ret=0
    testpid=$(run_named ns2 named$n.run -c named-alt5.conf -D runtime-ns2-extra-5)
    test -n "$testpid" || ret=1
    retry_quiet 10 check_named_log "exiting (due to fatal error)" ns2/named$n.run || ret=1
    grep "working directory '.*' is not writable" ns2/named$n.run > /dev/null 2>&1 || ret=1
    kill_named ns2/named.pid && ret=1
    test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))

    n=$((n+1))
    echo_i "checking that named starts if managed-keys-directory is writable and working directory is not writable ($n)"
    ret=0
    testpid=$(run_named ns2/nope ../named$n.run -c ../named-alt6.conf -D runtime-ns2-extra-6)
    test -n "$testpid" || ret=1
    retry_quiet 10 check_named_log " running$" ns2/named$n.run || ret=1
    kill_named ns2/named.pid || ret=1
    test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))
fi

n=$((n+1))
echo_i "verifying that named switches UID ($n)"
if [ "`id -u`" -eq 0 ] && [ -z "$CYGWIN" ]; then
    ret=0
    CURRENT_DIR="`pwd`"
    TEMP_NAMED_DIR=`mktemp -d "${CURRENT_DIR}/ns2/tmp.XXXXXXXX"`
    if [ "$?" -eq 0 ]; then
        copy_setports ns2/named-alt9.conf.in "${TEMP_NAMED_DIR}/named-alt9.conf"
        export SOFTHSM2_CONF="${TEMP_NAMED_DIR}/softhsm2.conf"
        sh -x "$TOP/bin/tests/prepare-softhsm2.sh"
        chown -R nobody: "${TEMP_NAMED_DIR}"
        chmod 0700 "${TEMP_NAMED_DIR}"
        testpid=$(run_named "${TEMP_NAMED_DIR}" named$n.run -u nobody -c named-alt9.conf)
	test -n "$testpid" || ret=1
        retry_quiet 10 check_named_log "running$" "${TEMP_NAMED_DIR}/named$n.run" || ret=1
        [ -s "${TEMP_NAMED_DIR}/named9.pid" ] || ret=1
        grep "loading configuration: permission denied" "${TEMP_NAMED_DIR}/named$n.run" > /dev/null && ret=1
        kill_named "${TEMP_NAMED_DIR}/named9.pid" || ret=1
        test -n "$testpid" && retry_quiet 10 check_pid $testpid || ret=1
    else
        echo_i "mktemp failed"
        ret=1
    fi
    if [ $ret -ne 0 ]; then echo_i "failed"; fi
    status=$((status+ret))
else
    echo_i "skipped, not running as root or running on Windows"
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
