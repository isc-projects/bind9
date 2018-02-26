#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Test of allow-query statement.
# allow-query takes an address match list and can be included in either the
# options statement or in the zone statement.  This test assumes that the
# acl tests cover the details of the address match list and uses a limited
# number of address match test cases to ensure that allow-query finds the
# expected match.
# Test list:
# In options:
# default (any), any, none, [localhost, localnets],
# allowed address, not allowed address, denied address,
# allowed key, not allowed key, denied key
# allowed acl, not allowed acl, denied acl (acls pointing to addresses)
#
# Each of these tests requires changing to a new configuration
# file and using rndc to update the server
#
# In view, with nothing in options (default to any)
# default (any), any, none, [localhost, localnets],
# allowed address, not allowed address, denied address,
# allowed key, not allowed key, denied key
# allowed acl, not allowed acl, denied acl (acls pointing to addresses)
#
# In view, with options set to none, view set to any
# In view, with options set to any, view set to none
#
# In zone, with nothing in options (default to any)
# any, none, [localhost, localnets],
# allowed address, denied address,
# allowed key, not allowed key, denied key
# allowed acl, not allowed acl, denied acl (acls pointing to addresses),
#
# In zone, with options set to none, zone set to any
# In zone, with options set to any, zone set to none
# In zone, with view set to none, zone set to any
# In zone, with view set to any, zone set to none
#
# zone types of master, slave and stub can be tested in parallel by using
# multiple instances (ns2 as master, ns3 as slave, ns4 as stub) and querying
# as necessary.
#

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

DIGOPTS="+tcp +nosea +nostat +nocmd +norec +noques +noauth +noadd +nostats +dnssec -p ${PORT}"

rndc_reload() {
    echo_i "`$RNDC -c ../common/rndc.conf -s 10.53.0.2 -p ${CONTROLPORT} reload 2>&1 | sed 's/^/ns2 /'`"
}

status=0
n=0

n=`expr $n + 1`
echo_i "test $n: default - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.1 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: explicit any - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.2 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: none - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.3 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: address allowed - query allowed by explicit IP"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.4 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: address not allowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.5 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: address disallowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.6 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: acl allowed - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.7 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: acl not allowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.1 -b 10.53.0.8 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: acl disallowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.1 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: key allowed - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 -y one:1234abcd8765 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: key not allowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.3 -y two:1234efgh8765 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: key disallowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.4 -y one:1234abcd8765 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

# Tests for allow-query in the zone statements
n=`expr $n + 1`
echo_i "test $n: zone default - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone explicit any - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.any.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.any.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone none - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.none.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.none.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone address allowed - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.addrallow.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.addrallow.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone address not allowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.addrnotallow.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.addrnotallow.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone address disallowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.addrdisallow.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.addrdisallow.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone acl allowed - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.aclallow.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.aclallow.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone acl not allowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.aclnotallow.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.aclnotallow.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone acl disallowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 a.acldisallow.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.acldisallow.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone key allowed - query allowed"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 -y one:1234abcd8765 a.keyallow.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.keyallow.example' dig.out.ns2.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone key not allowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 -y two:1234efgh8765 a.keyallow.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.keyallow.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "test $n: zone key disallowed - query refused"
ret=0
$DIG $DIGOPTS @10.53.0.3 -b 10.53.0.2 -y one:1234abcd8765 a.keydisallow.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.keydisallow.example' dig.out.ns2.$n > /dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
