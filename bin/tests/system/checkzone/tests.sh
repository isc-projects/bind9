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
n=1

for db in zones/good*.db
do
	echo_i "checking $db ($n)"
	ret=0
	case $db in
	zones/good-gc-msdcs.db)
		$CHECKZONE -k fail -i local example $db > test.out.$n 2>&1 || ret=1
		;;
	zones/good-dns-sd-reverse.db)
		$CHECKZONE -k fail -i local 0.0.0.0.in-addr.arpa $db > test.out.$n 2>&1 || ret=1
		;;
	*)
		$CHECKZONE -i local example $db > test.out.$n 2>&1 || ret=1
		;;
	esac
	n=`expr $n + 1`
	if [ $ret != 0 ]; then echo_i "failed"; fi
	status=`expr $status + $ret`
done

for db in zones/bad*.db
do
	echo_i "checking $db ($n)"
	ret=0
	case $db in
	zones/bad-dns-sd-reverse.db)
		$CHECKZONE -k fail -i local 0.0.0.0.in-addr.arpa $db > test.out.$n 2>&1 && ret=1
		;;
	*)
                $CHECKZONE -i local example $db > test.out.$n 2>&1 && ret=1
		;;
	esac
	n=`expr $n + 1`
	if [ $ret != 0 ]; then echo_i "failed"; fi
	status=`expr $status + $ret`
done

echo_i "checking with spf warnings ($n)"
ret=0
$CHECKZONE example zones/spf.db > test.out1.$n 2>&1 || ret=1
$CHECKZONE -T ignore example zones/spf.db > test.out2.$n 2>&1 || ret=1
grep "'x.example' found type SPF" test.out1.$n > /dev/null && ret=1
grep "'y.example' found type SPF" test.out1.$n > /dev/null || ret=1
grep "'example' found type SPF" test.out1.$n > /dev/null && ret=1
grep "'x.example' found type SPF" test.out2.$n > /dev/null && ret=1
grep "'y.example' found type SPF" test.out2.$n > /dev/null && ret=1
grep "'example' found type SPF" test.out2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking for no 'inherited owner' warning on '\$INCLUDE file' with no new \$ORIGIN ($n)"
ret=0
$CHECKZONE example zones/nowarn.inherited.owner.db > test.out1.$n 2>&1 || ret=1
grep "inherited.owner" test.out1.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking for 'inherited owner' warning on '\$ORIGIN + \$INCLUDE file' ($n)"
ret=0
$CHECKZONE example zones/warn.inherit.origin.db > test.out1.$n 2>&1 || ret=1
grep "inherited.owner" test.out1.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking for 'inherited owner' warning on '\$INCLUDE file origin' ($n)"
ret=0
$CHECKZONE example zones/warn.inherited.owner.db > test.out1.$n 2>&1 || ret=1
grep "inherited.owner" test.out1.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking that raw zone with bad class is handled ($n)"
ret=0
$CHECKZONE -f raw example zones/bad-badclass.raw > test.out.$n 2>&1 && ret=1
grep "failed: bad class" test.out.$n >/dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking that expirations that loop using serial arithmetic are handled ($n)"
ret=0
q=-q
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
test $ret -eq 1 || $CHECKZONE $q dyn.example.net zones/crashzone.db || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking that nameserver below DNAME is reported even with occulted address record present ($n)"
ret=0
$CHECKZONE example.com zones/ns-address-below-dname.db > test.out.$n 2>&1 && ret=1
grep "is below a DNAME" test.out.$n >/dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking that delegating nameserver below DNAME is reported even with occulted address record present ($n)"
ret=0
$CHECKZONE example.com zones/delegating-ns-address-below-dname.db > test.out.$n 2>&1 || ret=1
grep "is below a DNAME" test.out.$n >/dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
