#!/bin/sh -e
#
# Copyright (C) 2010, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: setup.sh,v 1.2 2010/11/16 01:37:36 sar Exp $

. ../getopts.sh

sed -e "s/@PORT@/${port}/g;s/@CONTROLPORT@/${controlport}/g;" < ../common/controls.conf.in > ns2/controls.conf
sed -e "s/@PORT@/${port}/g;s/@CONTROLPORT@/${controlport}/g;" < ns2/named01.conf.in > ns2/named.conf
echo "${port}" > ns2/named.port
