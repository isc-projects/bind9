#!/bin/sh

zone=secure.example.
infile=secure.example.db.in
zonefile=secure.example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

tag=`echo $keyname | sed -n 's/^.*\+\([0-9][0-9]*\)$/\1/p'`

echo "key=$keyname, tag=$tag"

$KEYSETTOOL $keyname.key

cat $infile $keyname.key >$zonefile

$SIGNER -v 1 -o $zone $zonefile

