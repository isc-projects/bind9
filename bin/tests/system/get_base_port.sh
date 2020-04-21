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

# This script is a 'port' broker.  It keeps track of ports given to the
# individual system subtests, so every test is given a unique port range.

lockfile=get_base_port.lock
statefile=get_base_port.state

ephemeral_port_min=49152
ephemeral_port_max=65535

get_base_port() {
    if ( set -o noclobber; echo "$$" > "${lockfile}" ) 2> /dev/null; then
	trap 'rm -f "${lockfile}"; exit $?' INT TERM EXIT

	base_port=$(cat "${statefile}" 2>/dev/null)

	if [ -z "${base_port}" ]; then
	    base_port="${ephemeral_port_min}"
	fi

	if [ "$((base_port+100))" -gt "${ephemeral_port_max}" ]; then
	    base_port="${ephemeral_port_min}"
	fi

	echo $((base_port+100)) > get_base_port.state

	# clean up after yourself, and release your trap
	rm -f "${lockfile}"
	trap - INT TERM EXIT
	echo "${base_port}"
    else
	echo 0
    fi
}

tries=10

while [ "${tries}" -gt 0 ]; do
    base_port=$(get_base_port)
    if [ "${base_port}" -gt 0 ]; then
	echo "${base_port}"
	exit 0
    fi
    sleep 1
    tries=$((tries-1))
done

exit 1
