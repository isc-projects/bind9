#!/bin/sh
# Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Shell script snippet, must be sourced.
#
# Most system tests require use of at least two ports: the nameserver query
# port and a port for RNDC access.  In addition, some tests require additional
# ports (e.g. for tests of transfers between nameservers).
#
# To allow tests to run in parallel, each test must be allocated a unique set
# ports to use.
#
# This script is used during testing to parse the "-p" option on the command
# line invoking scripts used during the test.  The option sets the base of
# a block of 10 ports used by the test.  A shell symbol is set for each port:
#
# port         Port used for queries (default to 5300)
# aport1       First additional port (set to $port + 1)
#   :
# aport8       Eighth additional port (set to $port + 8)
# controlport  Port used for RNDC (set to $port + 9)
#
# The fiule also defines a simple shell function to 

port=5300

while getopts ":p:" flag; do
    case "$flag" in
	p) port=$OPTARG ;;
	-) break ;;
	*) exit 1 ;;
    esac
done
shift $(($OPTIND - 1))
OPTIND=1

# Ensure port is numeric, above 1024 (limit of privileged port) and that
# the upper of the 10 ports notionally assigned does not exceed 65535.

if [ "$((${port}+0))" != "${port}" ] || [ "${port}" -le 1024 ] || [ "${port}" -gt 65520 ]; then
    echo "Specified port '$port' must be numeric and in the range 1025 to 65520" >&2
    exit 1
fi

aport1=$(($port + 1))
aport2=$(($port + 2))
aport3=$(($port + 3))
aport4=$(($port + 4))
aport5=$(($port + 5))
aport6=$(($port + 6))
aport7=$(($port + 7))
aport8=$(($port + 8))
controlport=$(($port + 9))


# copy_setports - Copy Configuration File and Replace Ports
#
# Convenience function to copy a configuration file, replacing the symbols
# PORT, CONTROLPORT and APORT[1-8] with the port numbers set by the "-p"
# option passed to the script.
#
# Usage:
#   copy_setports infile outfile

copy_setports() {
    sed -e "s/@PORT@/${port}/g" \
        -e "s/@APORT1@/${aport1}/g" \
        -e "s/@APORT2@/${aport1}/g" \
        -e "s/@APORT3@/${aport1}/g" \
        -e "s/@APORT4@/${aport1}/g" \
        -e "s/@APORT5@/${aport1}/g" \
        -e "s/@APORT6@/${aport1}/g" \
        -e "s/@APORT7@/${aport1}/g" \
        -e "s/@APORT8@/${aport1}/g" \
        -e "s/@CONTROLPORT@/${controlport}/g" < $1 > $2
}
