#!/bin/sh

zone=secure.example.
infile=secure.example.db.in
zonefile=secure.example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

$KEYSETTOOL -t 3600 $keyname.key

cat $infile $keyname.key >$zonefile

$SIGNER -o $zone $zonefile

zone=bogus.example.
infile=bogus.example.db.in
zonefile=bogus.example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

$KEYSETTOOL -t 3600 $keyname.key

cat $infile $keyname.key >$zonefile

$SIGNER -o $zone $zonefile
