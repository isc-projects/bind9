#!/bin/sh

zone=secure.example.
infile=secure.example.db.in
zonefile=secure.example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

echo $KEYSETTOOL $keyname.key
$KEYSETTOOL $keyname.key

cat $infile $keyname.key >$zonefile

echo $SIGNER -o $zone $zonefile
$SIGNER -o $zone $zonefile

zone=bogus.example.
infile=bogus.example.db.in
zonefile=bogus.example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

echo $KEYSETTOOL $keyname.key
$KEYSETTOOL $keyname.key

cat $infile $keyname.key >$zonefile

echo $SIGNER -o $zone $zonefile
$SIGNER -o $zone $zonefile
