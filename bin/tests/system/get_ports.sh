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

# This script is a 'port' broker.  It keeps track of ports given to the
# individual system subtests, so every test is given a unique port range.

lockfile=get_ports.lock
statefile=get_ports.state

port_min=5001
port_max=32767

get_random() (
    # shellcheck disable=SC2005,SC2046
    echo $(dd if=/dev/urandom bs=1 count=2 2>/dev/null | od -tu2 -An) | sed -e 's/^0*//'
)

get_port() {
    tries=10
    port=0
    while [ "${tries}" -gt 0 ]; do
	if ( set -o noclobber; echo "$$" > "${lockfile}" ) 2> /dev/null; then
	    trap 'rm -f "${lockfile}"; exit $?' INT TERM EXIT

	    port=$(cat "${statefile}" 2>/dev/null)

	    if [ -z "${port}" ]; then
		if [ "$1" -gt 0 ]; then
		    port="$1"
		else
		    port_range=$((port_max-port_min))
		    port_random=$(get_random)
		    port=$((port_random%port_range+port_min))
		fi
	    fi

	    if [ "$((port+1))" -gt "${port_max}" ]; then
		port="${port_min}"
	    fi

	    echo $((port+1)) > get_ports.state

	    # clean up after yourself, and release your trap
	    rm -f "${lockfile}"
	    trap - INT TERM EXIT

	    # we have our port
	    break
	fi
	sleep 1
	tries=$((tries-1))
    done
    if [ "$port" -eq 0 ]; then
	exit 1
    fi
    echo "$port"
}

baseport=0
while getopts "p:-:" OPT; do
    if [ "$OPT" = "-" ] && [ -n "$OPTARG" ]; then
	OPT="${OPTARG%%=*}"
	OPTARG="${OPTARG#$OPT}"
	OPTARG="${OPTARG#=}"
    fi

    # shellcheck disable=SC2214
    case "$OPT" in
	p | port) baseport=$OPTARG ;;
	-) break ;;
	*) echo "invalid option" >&2; exit 1 ;;
    esac
done

echo "export PORT=$(get_port "$baseport")"
echo "export EXTRAPORT1=$(get_port)"
echo "export EXTRAPORT2=$(get_port)"
echo "export EXTRAPORT3=$(get_port)"
echo "export EXTRAPORT4=$(get_port)"
echo "export EXTRAPORT5=$(get_port)"
echo "export EXTRAPORT6=$(get_port)"
echo "export EXTRAPORT7=$(get_port)"
echo "export EXTRAPORT8=$(get_port)"
echo "export CONTROLPORT=$(get_port)"

# Local Variables:
# sh-basic-offset: 4
# End:
