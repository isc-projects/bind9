#!/bin/sh
#
# Copyright (C) 2012, 2013, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id$


while [ "$#" != 0 ]; do
    case $1 in
    +*) shift ;;
    -t) shift ;;
    DS|ds) ext=ds ; shift ;;
    DLV|dlv) ext=dlv ; shift ;;
    DNSKEY|dnskey) ext=dnskey ; shift ;;
    *) file=$1 ; shift ;;
    esac
done

cat ${file}.${ext}.db
