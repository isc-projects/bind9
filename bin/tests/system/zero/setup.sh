# Copyright (C) 2013, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

$SHELL ../genzone.sh 2 4 | sed -e 's/^$TTL 3600$/$TTL 0 ; force TTL to zero/' -e 's/86400.IN SOA/0 SOA/' > ns2/example.db
