#!/bin/sh
# tests for TSIG-GSS updates

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

status=0

DIGOPTS="@10.53.0.1 -p 5300"

# we don't want a KRB5_CONFIG setting breaking the tests
unset KRB5_CONFIG

test_update() {
    host="$1"
    type="$2"
    cmd="$3"
    digout="$4"

    cat <<EOF > ns1/update.txt
server 10.53.0.1 5300
update add $host $cmd
send
EOF
    echo "I:testing update for $host $type $cmd"
    $NSUPDATE -g ns1/update.txt || {
	echo "I:update failed for $host $type $cmd"
	return 1
    }

    out="$($DIG $DIGOPTS -t $type -q $host | egrep ^$host)"
    [ $(echo "$out" | grep "$digout" | wc -l) -eq 1 ] || {
	echo "I:dig output incorrect for $host $type $cmd: $out"
	return 1
    }
    return 0
}

echo "I:testing updates as administrator"
KRB5CCNAME=$(pwd)/ns1/administrator.ccache
export KRB5CCNAME

test_update testdc1.example.nil. A "86400 A 10.53.0.10" "10.53.0.10" || status=1
test_update testdc2.example.nil. A "86400 A 10.53.0.11" "10.53.0.11" || status=1
test_update denied.example.nil. TXT "86400 TXT helloworld" "helloworld" && status=1

echo "I:testing updates as a user"
KRB5CCNAME=$(pwd)/ns1/testdenied.ccache
export KRB5CCNAME

test_update testdenied.example.nil. A "86400 A 10.53.0.12" "10.53.0.12" && status=1
test_update testdenied.example.nil. TXT "86400 TXT helloworld" "helloworld" || status=1

[ $status -eq 0 ] && echo "I:tsiggss tests all OK"

exit $status
