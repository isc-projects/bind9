# Copyright (C) 2016, 2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

if [ -z "$NZD" ]; then
        echo_i "This test requires LMDB support (--with-lmdb)"
        exit 255
fi

exit 0
