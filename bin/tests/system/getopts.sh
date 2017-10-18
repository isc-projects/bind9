#!/bin/sh
# Copyright (C) 2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# shell script snippet, must be sourced

port=5300
controlport=9953

while getopts ":p:c:" flag; do
    case "$flag" in
	p) port=$OPTARG ;;
	c) controlport=$OPTARG ;;
	-) break ;;
	*) exit 1 ;;
    esac
done
shift $(($OPTIND - 1))
OPTIND=1

SEDPORTS="sed -e s/@PORT@/${port}/g -e s/@CONTROLPORT@/${controlport}/g"
