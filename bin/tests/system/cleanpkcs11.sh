#!/bin/sh
#
# Copyright (C) 2010, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: cleanpkcs11.sh,v 1.3 2010/06/08 23:50:24 tbox Exp $

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

if [ ! -x ../../pkcs11/pkcs11-destroy ]; then exit 1; fi

$PK11DEL -w0 > /dev/null 2>&1
