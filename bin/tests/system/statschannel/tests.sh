#!/bin/sh
#
# Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
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

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGCMD="$DIG @10.53.0.2 -p 5300"

gettraffic() {
    $PERL -e 'use File::Fetch;
              use XML::Simple;
              use Data::Dumper;
              my $ff = File::Fetch->new(uri => "http://10.53.0.2:8853/xml/v3/traffic");
              my $file = $ff->fetch() or die $ff->error;
              my $ref = XMLin($file);

              my $udp = $ref->{traffic}->{udp}->{counters};
              foreach $group (@$udp) {
                  my $type = "udp " . $group->{type} . " ";
                  if (exists $group->{counter}->{name}) {
                      print $type . $group->{counter}->{name} . ": " . $group->{counter}->{content} . "\n";
                  } else {
                      foreach $key (keys $group->{counter}) {
                          print $type . $key . ": ". $group->{counter}->{$key}->{content} ."\n";
                      }
                 }
              }

              my $tcp = $ref->{traffic}->{tcp}->{counters};
              foreach $group (@$tcp) {
                  my $type = "tcp " . $group->{type} . " ";
                  if (exists $group->{counter}->{name}) {
                      print $type . $group->{counter}->{name} . ": " . $group->{counter}->{content} . "\n";
                  } else {
                      foreach $key (keys $group->{counter}) {
                          print $type . $key . ": ". $group->{counter}->{$key}->{content} ."\n";
                      }
                 }
              }' | sort > traffic.out.$1
    return $?
}

status=0
n=1
ret=0
echo "I:fetching traffic size data ($n)"
gettraffic $n || ret=1
cmp traffic.out.$n traffic.expect.$n || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:fetching traffic size data after small UDP query ($n)"
$DIGCMD short.example txt > dig.out.$n || ret=1
gettraffic $n || ret=1
cmp traffic.out.$n traffic.expect.$n || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
n=`expr $n + 1`
echo "I:fetching traffic size data after large UDP query ($n)"
$DIGCMD long.example txt > dig.out.$n || ret=1
gettraffic $n || ret=1
cmp traffic.out.$n traffic.expect.$n || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:fetching traffic size data after small TCP query ($n)"
$DIGCMD +tcp short.example txt > dig.out.$n || ret=1
gettraffic $n || ret=1
cmp traffic.out.$n traffic.expect.$n || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

ret=0
echo "I:fetching traffic size data after large TCP query ($n)"
$DIGCMD +tcp long.example txt > dig.out.$n || ret=1
gettraffic $n || ret=1
cmp traffic.out.$n traffic.expect.$n || ret=1
if [ $ret != 0 ]; then echo "I: failed"; fi
status=`expr $status + $ret`
n=`expr $n + 1`

echo "I:exit status: $status"
exit $status
