#!/bin/sh
#
# Copyright (C) 2013, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$FEATURETEST --have-geoip || {
	echo "I:This test requires GeoIP support." >&2
	exit 255
}
exit 0
