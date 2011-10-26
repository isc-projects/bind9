#!/bin/sh
#
# Copyright (C) 2005, 2007, 2011  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: tests.sh,v 1.6 2011/10/26 23:46:14 tbox Exp $

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

israw () {
    cat $1 | perl -e '$input = <STDIN>;
                      ($style, $version) = unpack("NN", $input);
                      exit 1 if ($style != 2 || $version != 0);'
    return $?
}

DIGOPTS="+tcp +noauth +noadd +nosea +nostat +noquest +nocomm +nocmd"

status=0

echo "I:checking that master file in the raw format worked"
ret=0
for server in 1 2
do
	for name in ns mx a aaaa cname dname txt rrsig nsec dnskey ds
	do
		$DIG $DIGOPTS $name.example. $name @10.53.0.$server -p 5300
		echo
	done > dig.out.$server
done
$PERL ../digcomp.pl dig.out.1 dig.out.2 || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

echo "I:waiting for transfers to complete"
sleep 1

echo "I:checking that slave was saved in raw format by default"
ret=0
israw ns2/transfer.db.raw || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

echo "I:checking that slave was saved in text format when configured"
ret=0
israw ns2/transfer.db.txt && ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

echo "I:checking that slave formerly in text format is now raw"
ret=0
israw ns2/formerly-text.db || ret=1
[ $ret -eq 0 ] || echo "I:failed"
status=`expr $status + $ret`

echo "I:exit status: $status"
exit $status
