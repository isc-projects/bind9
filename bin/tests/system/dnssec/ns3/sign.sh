#!/bin/sh

zone=secure.example.
infile=secure.example.db.in
zonefile=secure.example.db

rm -f K$zone*.key
rm -f K$zone*.private
rm -f $zone*.keyset

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

tag=`echo $keykname | sed -n 's/^.*\+\([0-9][0-9]*\)$/\1/p'`

echo "key=$keyname, tag=$tag"

pubkeyfile="$keyname.key"

$KEYSETTOOL $zone $tag/001

cat $infile $pubkeyfile >$zonefile

$SIGNER -v 1 -o $zone $zonefile

