#!/bin/sh
#
# Copyright (C) 2004, 2007, 2011-2013  Internet Systems Consortium, Inc. ("ISC")
# Copyright (C) 2000, 2001  Internet Software Consortium.
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

# $Id$

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0
n=0

ret=0
echo "I:fetching first copy of zone before update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil. \
	@10.53.0.1 axfr -p 5300 > dig.out.ns1 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:fetching second copy of zone before update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil.\
	@10.53.0.2 axfr -p 5300 > dig.out.ns2 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:comparing pre-update copies to known good data"
$PERL ../digcomp.pl knowngood.ns1.before dig.out.ns1 || ret=1
$PERL ../digcomp.pl knowngood.ns1.before dig.out.ns2 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:updating zone"
# nsupdate will print a ">" prompt to stdout as it gets each input line.
$NSUPDATE <<END > /dev/null || ret=1
server 10.53.0.1 5300
update add updated.example.nil. 600 A 10.10.10.1
update add updated.example.nil. 600 TXT Foo
update delete t.example.nil.

END
[ $ret = 0 ] || { echo I:failed; status=1; }
echo "I:sleeping 5 seconds for server to incorporate changes"
sleep 5

ret=0
echo "I:fetching first copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil.\
	@10.53.0.1 axfr -p 5300 > dig.out.ns1 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:fetching second copy of zone after update"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil.\
	@10.53.0.2 axfr -p 5300 > dig.out.ns2 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:comparing post-update copies to known good data"
$PERL ../digcomp.pl knowngood.ns1.after dig.out.ns1 || ret=1
$PERL ../digcomp.pl knowngood.ns1.after dig.out.ns2 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:check SIG(0) key is accepted"
key=`$KEYGEN -r random.data -a NSEC3RSASHA1 -b 512 -k -n ENTITY xxx 2> /dev/null`
echo "" | $NSUPDATE -k ${key}.private > /dev/null 2>&1 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
ret=0
echo "I:check TYPE=0 update is rejected by nsupdate ($n)"
$NSUPDATE <<END > nsupdate.out 2>&1 && ret=1
    server 10.53.0.1 5300
    ttl 300
    update add example.nil. in type0 ""
    send
END
grep "unknown class/type" nsupdate.out > /dev/null 2>&1 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
ret=0
echo "I:check TYPE=0 prerequisite is handled ($n)"
$NSUPDATE <<END > nsupdate.out 2>&1 || ret=1
    server 10.53.0.1 5300
    prereq nxrrset example.nil. type0
    send
END
$DIG +tcp version.bind txt ch @10.53.0.1 -p 5300 > dig.out.ns1.$n
grep "status: NOERROR" dig.out.ns1.$n > /dev/null || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
ret=0
echo "I:check that TYPE=0 update is handled ($n)"
echo "a0e4280000010000000100000000060001c00c000000fe000000000000" |
$PERL ../packet.pl -a 10.53.0.1 -p 5300 -t tcp > /dev/null
$DIG +tcp version.bind txt ch @10.53.0.1 -p 5300 > dig.out.ns1.$n
grep "status: NOERROR" dig.out.ns1.$n > /dev/null || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
echo "I:check that TYPE=0 additional data is handled ($n)"
echo "a0e4280000010000000000010000060001c00c000000fe000000000000" |
$PERL ../packet.pl -a 10.53.0.1 -p 5300 -t tcp > /dev/null
$DIG +tcp version.bind txt ch @10.53.0.1 -p 5300 > dig.out.ns1.$n
grep "status: NOERROR" dig.out.ns1.$n > /dev/null || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
echo "I:check that update to undefined class is handled ($n)"
echo "a0e4280000010001000000000000060101c00c000000fe000000000000" |
$PERL ../packet.pl -a 10.53.0.1 -p 5300 -t tcp > /dev/null
$DIG +tcp version.bind txt ch @10.53.0.1 -p 5300 > dig.out.ns1.$n
grep "status: NOERROR" dig.out.ns1.$n > /dev/null || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
echo "I:check that address family mismatch is handled ($n)"
$NSUPDATE <<END > /dev/null 2>&1 && ret=1
server ::1
local 127.0.0.1
update add 600 txt.example.nil in txt "test"
send
END
[ $ret = 0 ] || { echo I:failed; status=1; }

if $PERL -e 'use Net::DNS;' 2>/dev/null
then
    echo "I:running update.pl test"
    $PERL update_test.pl -s 10.53.0.1 -p 5300 update.nil. || status=1
else
    echo "I:The second part of this test requires the Net::DNS library." >&2
fi

ret=0
echo "I:fetching first copy of test zone"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil.\
	@10.53.0.1 axfr -p 5300 > dig.out.ns1 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

echo "I:fetching second copy of test zone"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil.\
	@10.53.0.2 axfr -p 5300 > dig.out.ns2 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:comparing zones"
$PERL ../digcomp.pl dig.out.ns1 dig.out.ns2 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

echo "I:SIGKILL and restart server ns1"
cd ns1
kill -KILL `cat named.pid`
rm named.pid
cd ..
sleep 10
if 
	$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns1
then
	echo "I:restarted server ns1"	
else
	echo "I:could not restart server ns1"
	exit 1
fi
sleep 10

ret=0
echo "I:fetching ns1 after hard restart"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd example.nil.\
	@10.53.0.1 axfr -p 5300 > dig.out.ns1.after || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

ret=0
echo "I:comparing zones"
$PERL ../digcomp.pl dig.out.ns1 dig.out.ns1.after || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

echo "I:begin RT #482 regression test"

ret=0
echo "I:update master"
$NSUPDATE <<END > /dev/null || ret=1
server 10.53.0.1 5300
update add updated2.example.nil. 600 A 10.10.10.2
update add updated2.example.nil. 600 TXT Bar
update delete c.example.nil.
send
END
[ $ret = 0 ] || { echo I:failed; status=1; }

sleep 5

echo "I:SIGHUP slave"
kill -HUP `cat ns2/named.pid`

sleep 5

ret=0
echo "I:update master again"
$NSUPDATE <<END > /dev/null || ret=1
server 10.53.0.1 5300
update add updated3.example.nil. 600 A 10.10.10.3
update add updated3.example.nil. 600 TXT Zap
update delete d.example.nil.
send
END
[ $ret = 0 ] || { echo I:failed; status=1; }

sleep 5

echo "I:SIGHUP slave again"
kill -HUP `cat ns2/named.pid`

sleep 5

echo "I:check to 'out of sync' message"
if grep "out of sync" ns2/named.run
then
	echo "I: failed (found 'out of sync')"
	status=1
fi

echo "I:end RT #482 regression test"

echo "I:testing that rndc stop updates the master file"
$NSUPDATE <<END > /dev/null || ret=1
server 10.53.0.1 5300
update add updated4.example.nil. 600 A 10.10.10.3
send
END
$PERL $SYSTEMTESTTOP/stop.pl --use-rndc . ns1
# Removing the journal file and restarting the server means
# that the data served by the new server process are exactly
# those dumped to the master file by "rndc stop".
rm -f ns1/*jnl
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart . ns1
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd updated4.example.nil.\
	@10.53.0.1 a -p 5300 > dig.out.ns1 || ret=1
$PERL ../digcomp.pl knowngood.ns1.afterstop dig.out.ns1 || ret=1
[ $ret = 0 ] || { echo I:failed; status=1; }

n=`expr $n + 1`
ret=0
echo "I:check that changes to the DNSKEY RRset TTL do not have side effects ($n)"
$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd dnskey.test. \
        @10.53.0.3 -p 5300 dnskey | \
	sed -n 's/\(.*\)10.IN/update add \1600 IN/p' |
	(echo server 10.53.0.3 5300; cat - ; echo send ) |
$NSUPDATE 

$DIG +tcp +noadd +nosea +nostat +noquest +nocomm +nocmd dnskey.test. \
	@10.53.0.3 -p 5300 any > dig.out.ns3.$n

grep "600.*DNSKEY" dig.out.ns3.$n > /dev/null || ret=1
grep TYPE65534 dig.out.ns3.$n > /dev/null && ret=1
if test $ret -ne 0
then
	echo "I:failed"; status=1
fi

n=`expr $n + 1`
ret=0
echo "I:check command list ($n)"
(
while read cmd 
do
    echo "$cmd" | $NSUPDATE  > /dev/null 2>&1
    if test $? -gt 1 ; then
	echo "I: failed ($cmd)"
	ret=1
    fi
    echo "$cmd " | $NSUPDATE  > /dev/null 2>&1
    if test $? -gt 1 ; then
	echo "I: failed ($cmd)"
	ret=1
    fi
done
exit $ret
) < commandlist || ret=1
if [ $ret -ne 0 ]; then
    status=1
fi

echo "I:exit status: $status"
exit $status
