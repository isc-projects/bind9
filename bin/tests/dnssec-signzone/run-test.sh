#!/bin/sh
#
# Copyright (C) 2009, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: run-test.sh,v 1.3 2009/06/04 02:56:47 tbox Exp $


sign="../../dnssec/dnssec-signzone -f signed.zone -o example.com."

signit() {
	rm -f signed.zone
	grep '^;' $zone
	$sign $zone
}

expect_success() {
	if ! test -f signed.zone ; then
		echo "Error: expected success, but sign failed for $zone."
	else
		echo "Success:  Sign succeeded for $zone."
	fi
}

expect_failure() {
	if test -f signed.zone ; then
		echo "Error: expected failure, but sign succeeded for $zone."
	else
		echo "Success:  Sign failed (expected) for $zone"
	fi
}

zone="test1.zone" ; signit ; expect_success
zone="test2.zone" ; signit ; expect_failure
zone="test3.zone" ; signit ; expect_failure
zone="test4.zone" ; signit ; expect_success
zone="test5.zone" ; signit ; expect_failure
zone="test6.zone" ; signit ; expect_failure
zone="test7.zone" ; signit ; expect_failure
zone="test8.zone" ; signit ; expect_failure
