#!/bin/sh

zone=secure.example.
infile=secure.example.db.in
zonefile=secure.example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

$KEYSETTOOL $keyname.key

cat $infile $keyname.key >$zonefile

$SIGNER -v 1 -o $zone $zonefile

