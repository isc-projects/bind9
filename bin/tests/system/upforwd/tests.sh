#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: tests.sh,v 1.4 2000/11/20 17:53:38 gson Exp $ 

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

echo "I:fetching first copy of zone before update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.1 axfr -p 5300 > dig.out.ns1 || status=1

echo "I:fetching second copy of zone before update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.2 axfr -p 5300 > dig.out.ns2 || status=1

echo "I:fetching third copy of zone before update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.3 axfr -p 5300 > dig.out.ns3 || status=1

echo "I:comparing pre-update copies to known good data"
$PERL ../digcomp.pl knowngood.before dig.out.ns1 || status=1
$PERL ../digcomp.pl knowngood.before dig.out.ns2 || status=1
$PERL ../digcomp.pl knowngood.before dig.out.ns3 || status=1

echo "I:updating zone (signed)"
# nsupdate will print a ">" prompt to stdout as it gets each input line.
$NSUPDATE -y update.example:c3Ryb25nIGVub3VnaCBmb3IgYSBtYW4gYnV0IG1hZGUgZm9yIGEgd29tYW4K < update.scp > /dev/null
echo "I:sleeping 15 seconds for server to incorporate changes"
sleep 15

echo "I:fetching first copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.1 axfr -p 5300 > dig.out.ns1 || status=1

echo "I:fetching second copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.2 axfr -p 5300 > dig.out.ns2 || status=1

echo "I:fetching third copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.3 axfr -p 5300 > dig.out.ns3 || status=1

echo "I:comparing post-update copies to known good data"
$PERL ../digcomp.pl knowngood.after1 dig.out.ns1 || status=1
$PERL ../digcomp.pl knowngood.after1 dig.out.ns2 || status=1
$PERL ../digcomp.pl knowngood.after1 dig.out.ns3 || status=1

echo "I:updating zone (unsigned)"
# nsupdate will print a ">" prompt to stdout as it gets each input line.
$NSUPDATE < update.scp2 > /dev/null
echo "I:sleeping 15 seconds for server to incorporate changes"
sleep 15

echo "I:fetching first copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.1 axfr -p 5300 > dig.out.ns1 || status=1

echo "I:fetching second copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.2 axfr -p 5300 > dig.out.ns2 || status=1

echo "I:fetching third copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.\
	@10.53.0.3 axfr -p 5300 > dig.out.ns3 || status=1

echo "I:comparing post-update copies to known good data"
$PERL ../digcomp.pl knowngood.after2 dig.out.ns1 || status=1
$PERL ../digcomp.pl knowngood.after2 dig.out.ns2 || status=1
$PERL ../digcomp.pl knowngood.after2 dig.out.ns3 || status=1

echo "I:exit status: $status"
exit $status
