# Copyright

status=0
n=0

n=`expr $n + 1`
echo "I:Checking that reconfiguring empty zones is silent ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reconfig
ret=0
grep "automatic empty zone" ns1/named.run > /dev/null || ret=1
grep "received control channel command 'reconfig'" ns1/named.run > /dev/null || ret=1
grep "reloading configuration succeeded" ns1/named.run > /dev/null || ret=1
sleep 1
grep "zone serial (0) unchanged." ns1/named.run > /dev/null && ret=1
if [ $ret != 0 ] ; then echo I:failed; status=`expr $status + $ret`; fi

n=`expr $n + 1`
echo "I:Checking that reloading empty zones is silent ($n)"
$RNDC -c ../common/rndc.conf -s 10.53.0.1 -p 9953 reload > /dev/null
ret=0
grep "automatic empty zone" ns1/named.run > /dev/null || ret=1
grep "received control channel command 'reload'" ns1/named.run > /dev/null || ret=1
grep "reloading configuration succeeded" ns1/named.run > /dev/null || ret=1
sleep 1
grep "zone serial (0) unchanged." ns1/named.run > /dev/null && ret=1
if [ $ret != 0 ] ; then echo I:failed; status=`expr $status + $ret`; fi

exit $status
