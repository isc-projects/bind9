# Copyright (C) 2004, 2007, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: setup.sh,v 1.5 2007/06/19 23:47:01 tbox Exp $

cp ns1/ignore.example.db.in ns1/ignore.example.db
cp ns1/warn.example.db.in ns1/warn.example.db
cp ns1/fail.example.db.in ns1/fail.example.db

cp ns1/ignore.update.db.in ns1/ignore.update.db
cp ns1/warn.update.db.in ns1/warn.update.db
cp ns1/fail.update.db.in ns1/fail.update.db

cp ns4/master-ignore.update.db.in ns4/master-ignore.update.db
