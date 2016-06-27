#!/bin/sh
#
# Copyright (C) 2000, 2001, 2004, 2007, 2012, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: stop.sh,v 1.25 2007/06/18 23:47:27 tbox Exp $

. ./conf.sh
$PERL ./stop.pl "$@"

