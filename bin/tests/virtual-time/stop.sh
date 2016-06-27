#!/bin/sh
#
# Copyright (C) 2010, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: stop.sh,v 1.2 2010/06/17 05:38:05 marka Exp $

. ./conf.sh
$PERL ./stop.pl "$@"

