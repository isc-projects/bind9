# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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

status=0
n=0
# using dig insecure mode as not testing dnssec here
DIGOPTS="-i -p ${PORT}"
SENDCMD="$PERL $SYSTEMTESTTOP/send.pl 10.53.0.4 ${EXTRAPORT1}"

if [ -x ${DIG} ] ; then
  n=`expr $n + 1`
  echo_i "checking dig short form works ($n)"
  ret=0
  $DIG $DIGOPTS @10.53.0.3 +short a a.example > dig.out.test$n || ret=1
  if test `wc -l < dig.out.test$n` != 1 ; then ret=1 ; fi
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig split width works ($n)"
  ret=0
  $DIG $DIGOPTS @10.53.0.3 +split=4 -t sshfp foo.example > dig.out.test$n || ret=1
  grep " 9ABC DEF6 7890 " < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig with reverse lookup works ($n)"
  ret=0
  $DIG $DIGOPTS @10.53.0.3 -x 127.0.0.1 > dig.out.test$n 2>&1 || ret=1
  # doesn't matter if has answer
  grep -i "127\.in-addr\.arpa\." < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig over TCP works ($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 a a.example > dig.out.test$n || ret=1
  grep "10\.0\.0\.1$" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +multi +norrcomments works for dnskey (when default is rrcomments)($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +multi +norrcomments DNSKEY dnskey.example > dig.out.test$n || ret=1
  grep "; ZSK; alg = RSAMD5 ; key id = 30795" < dig.out.test$n > /dev/null && ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +multi +norrcomments works for soa (when default is rrcomments)($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +multi +norrcomments SOA example > dig.out.test$n || ret=1
  grep "; ZSK; alg = RSAMD5 ; key id = 30795" < dig.out.test$n > /dev/null && ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +rrcomments works for DNSKEY($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +rrcomments DNSKEY dnskey.example > dig.out.test$n || ret=1
  grep "; ZSK; alg = RSAMD5 ; key id = 30795" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +short +rrcomments works for DNSKEY ($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +short +rrcomments DNSKEY dnskey.example > dig.out.test$n || ret=1
  grep "; ZSK; alg = RSAMD5 ; key id = 30795" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +short +nosplit works($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +short +nosplit DNSKEY dnskey.example > dig.out.test$n || ret=1
  grep "Z8plc4Rb9VIE5x7KNHAYTvTO5d4S8M=$" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +short +rrcomments works($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +short +rrcomments DNSKEY dnskey.example > dig.out.test$n || ret=1
  grep "S8M=  ; ZSK; alg = RSAMD5 ; key id = 30795$" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +short +rrcomments works($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.3 +short +rrcomments DNSKEY dnskey.example > dig.out.test$n || ret=1
  grep "S8M=  ; ZSK; alg = RSAMD5 ; key id = 30795$" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

#  n=`expr $n + 1`
#  echo_i "checking dig +zflag works, and that BIND properly ignores it ($n)"
#  ret=0
#  $DIG $DIGOPTS +tcp @10.53.0.3 +zflag +qr A example > dig.out.test$n || ret=1
#  sed -n '/Sending:/,/Got answer:/p' dig.out.test$n | grep "^;; flags: rd ad; MBZ: 0x4;" > /dev/null || ret=1
#  sed -n '/Got answer:/,/AUTHORITY SECTION:/p' dig.out.test$n | grep "^;; flags: qr rd ra; QUERY: 1" > /dev/null || ret=1
#  if [ $ret != 0 ]; then echo_i "failed"; fi
#  status=`expr $status + $ret`

# n=`expr $n + 1`
# echo_i "checking dig +qr +ednsopt=08 does not cause an INSIST failure ($n)"
# ret=0
# $DIG $DIGOPTS @10.53.0.3 +ednsopt=08 +qr a a.example > dig.out.test$n || ret=1
# grep "INSIST" < dig.out.test$n > /dev/null && ret=1
# grep "FORMERR" < dig.out.test$n > /dev/null || ret=1
# if [ $ret != 0 ]; then echo_i "failed"; fi
# status=`expr $status + $ret`

# echo_i "checking dig +ttlunits works ($n)"
# ret=0
# $DIG $DIGOPTS +tcp @10.53.0.2 +ttlunits A weeks.example > dig.out.test$n || ret=1
# grep "^weeks.example.		3w" < dig.out.test$n > /dev/null || ret=1
# $DIG $DIGOPTS +tcp @10.53.0.2 +ttlunits A days.example > dig.out.test$n || ret=1
# grep "^days.example.		3d" < dig.out.test$n > /dev/null || ret=1
# $DIG $DIGOPTS +tcp @10.53.0.2 +ttlunits A hours.example > dig.out.test$n || ret=1
# grep "^hours.example.		3h" < dig.out.test$n > /dev/null || ret=1
# $DIG $DIGOPTS +tcp @10.53.0.2 +ttlunits A minutes.example > dig.out.test$n || ret=1
# grep "^minutes.example.	45m" < dig.out.test$n > /dev/null || ret=1
# $DIG $DIGOPTS +tcp @10.53.0.2 +ttlunits A seconds.example > dig.out.test$n || ret=1
# grep "^seconds.example.	45s" < dig.out.test$n > /dev/null || ret=1
# if [ $ret != 0 ]; then echo_i "failed"; fi
# status=`expr $status + $ret`

# n=`expr $n + 1`
# echo_i "checking dig respects precedence of options with +ttlunits ($n)"
# ret=0
# $DIG $DIGOPTS +tcp @10.53.0.2 +ttlunits +nottlid A weeks.example > dig.out.test$n || ret=1
# grep "^weeks.example.		IN" < dig.out.test$n > /dev/null || ret=1
# $DIG $DIGOPTS +tcp @10.53.0.2 +nottlid +ttlunits A weeks.example > dig.out.test$n || ret=1
# grep "^weeks.example.		3w" < dig.out.test$n > /dev/null || ret=1
# $DIG $DIGOPTS +tcp @10.53.0.2 +nottlid +nottlunits A weeks.example > dig.out.test$n || ret=1
# grep "^weeks.example.		1814400" < dig.out.test$n > /dev/null || ret=1
# if [ $ret != 0 ]; then echo_i "failed"; fi
# status=`expr $status + $ret`
  
  n=`expr $n + 1`
  echo_i "checking dig preserves origin on TCP retries ($n)"
  ret=0
  # Ask ans4 to still accept TCP connections, but not respond to queries
  echo "//" | $SENDCMD
  $DIG $DIGOPTS -d +tcp @10.53.0.4 +retry=1 +time=1 +domain=bar foo > dig.out.test$n 2>&1 && ret=1
  l=`grep "trying origin bar" dig.out.test$n | wc -l`
  [ ${l:-0} -eq 2 ] || ret=1
  grep "using root origin" < dig.out.test$n > /dev/null && ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig +ednsopt=8:00000000 (family=0, source=0, scope=0) ($n)"
  ret=0
  $DIG $DIGOPTS +tcp @10.53.0.2 -4 -6 A a.example > dig.out.test$n 2>&1 && ret=1
  grep "only one of -4 and -6 allowed" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`
  
  n=`expr $n + 1`
  echo_i "checking dig @IPv6addr -4 A a.example ($n)"
  if $TESTSOCK6 fd92:7065:b8e:ffff::2
  then
    ret=0
    $DIG $DIGOPTS +tcp @fd92:7065:b8e:ffff::2 -4 A a.example > dig.out.test$n 2>&1 && ret=1
    grep "address family not supported" < dig.out.test$n > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
  else
    echo_i "IPv6 unavailable; skipping"
  fi
  
  n=`expr $n + 1`
  echo_i "checking dig @IPv4addr -6 A a.example ($n)"
  if $TESTSOCK6 fd92:7065:b8e:ffff::2
  then
    ret=0
    if $FEATURETEST --ipv6only=no
    then
      $DIG $DIGOPTS +tcp @10.53.0.2 -6 A a.example > dig.out.test$n 2>&1 || ret=1
      grep "SERVER: ::ffff:10.53.0.2#${PORT}" < dig.out.test$n > /dev/null || ret=1
    else
      $DIG $DIGOPTS +tcp @10.53.0.2 -6 A a.example > dig.out.test$n 2>&1 && ret=1
      grep "::ffff:10.53.0.2" < dig.out.test$n > /dev/null || ret=1
    fi
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
  else
    echo_i "IPv6 unavailable; skipping"
  fi
  
  n=`expr $n + 1`
  echo_i "checking dig +sp works as an abbreviated form of split ($n)"
  ret=0
  $DIG $DIGOPTS @10.53.0.3 +sp=4 -t sshfp foo.example > dig.out.test$n || ret=1
  grep " 9ABC DEF6 7890 " < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  echo_i "checking dig -c works ($n)"
  ret=0
  $DIG $DIGOPTS @10.53.0.3 -c CHAOS -t txt version.bind > dig.out.test$n || ret=1
  grep "version.bind.		0	CH	TXT" < dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  n=`expr $n + 1`
  if $FEATURETEST --with-idn
  then
    echo_i "checking dig +idnout ($n)"
    ret=0
    $DIG $DIGOPTS @10.53.0.3 +noidnout xn--caf-dma.example. > dig.out.1.test$n 2>&1 || ret=1
    $DIG $DIGOPTS @10.53.0.3 +idnout xn--caf-dma.example. > dig.out.2.test$n 2>&1 || ret=1
    grep "^xn--caf-dma.example" dig.out.1.test$n > /dev/null || ret=1
    grep "^xn--caf-dma.example" dig.out.2.test$n > /dev/null && ret=1
    grep 10.1.2.3 dig.out.1.test$n > /dev/null || ret=1
    grep 10.1.2.3 dig.out.2.test$n > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
  else
    echo_i "skipping 'dig +idnout' as IDN support is not enabled ($n)"
  fi

  n=`expr $n + 1`
  echo_i "checking that dig warns about .local queries ($n)"
  ret=0
  $DIG $DIGOPTS @10.53.0.3 local soa > dig.out.test$n 2>&1 || ret=1
  grep ";; WARNING: .local is reserved for Multicast DNS" dig.out.test$n > /dev/null || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=`expr $status + $ret`

  #n=`expr $n + 1`
  #echo_i "check that dig processes +ednsopt=14 (key tag) and FORMERR is returned ($n)"
  #$DIG $DIGOPTS @10.53.0.3 +ednsopt=14 a.example +qr > dig.out.test$n 2>&1 || ret=1
  #grep "; KEY-TAG$" dig.out.test$n > /dev/null || ret=1
  #grep "status: FORMERR" dig.out.test$n > /dev/null || ret=1
  #if [ $ret != 0 ]; then echo_i "failed"; fi
  #status=`expr $status + $ret`

  #n=`expr $n + 1`
  #echo_i "check that dig processes +ednsopt=14:<value-list> (keytag) ($n)"
  #$DIG $DIGOPTS @10.53.0.3 +ednsopt=14:00010002 a.example +qr > dig.out.test$n 2>&1 || ret=1
  #grep "; KEY-TAG: 1, 2$" dig.out.test$n > /dev/null || ret=1
  #grep "status: FORMERR" dig.out.test$n > /dev/null && ret=1
  #if [ $ret != 0 ]; then echo_i "failed"; fi
  #status=`expr $status + $ret`

  #n=`expr $n + 1`
  #echo_i "check that dig processes +ednsopt=14:<malformed-value-list> (keytag) and FORMERR is returned ($n)"
  #ret=0
  #$DIG $DIGOPTS @10.53.0.3 +ednsopt=14:0001000201 a.example +qr > dig.out.test$n 2>&1 || ret=1
  #grep "; KEY-TAG: 00 01 00 02 01" dig.out.test$n > /dev/null || ret=1
  #grep "status: FORMERR" dig.out.test$n > /dev/null || ret=1
  #if [ $ret != 0 ]; then echo_i "failed"; fi
  #status=`expr $status + $ret`

else
  echo_i "$DIG is needed, so skipping these dig tests"
fi

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
