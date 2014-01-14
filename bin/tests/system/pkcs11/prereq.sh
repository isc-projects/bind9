#!/bin/sh
#
# Copyright (C) 2010, 2012  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: prereq.sh,v 1.3 2010/06/08 23:50:24 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh
../../../tools/genrandom 400 random.data

rsafail=0 eccfail=0

$KEYGEN -q -r random.data foo > /dev/null 2>&1 || rsafail=1
rm -f Kfoo*

$KEYGEN -q -a ECDSAP256SHA256 -r random.data foo > /dev/null 2>&1 || eccfail=1
rm -f Kfoo*

if [ $rsafail = 0 -a $eccfail = 0 ]; then
	echo both > supported
elif [ $rsafail = 1 -a $eccfail = 1 ]; then
	echo "I:This test requires PKCS#11 support for either RSA or ECDSA cryptography." >&2
	exit 255
elif [ $rsafail = 0 ]; then
	echo rsaonly > supported
else
        echo ecconly > supported
fi
