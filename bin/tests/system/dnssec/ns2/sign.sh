#!/bin/sh

zone=example.
infile=example.db.in
zonefile=example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

# Have the child generate a zone key and pass it to us,
# sign it, and pass it back

( cd ../ns3 && sh sign.sh )

cp ../ns3/secure.example.keyset .

echo $KEYSIGNER secure.example.keyset $keyname
$KEYSIGNER secure.example.keyset $keyname

# This will leave two copies of the child's zone key in the signed db file;
# that shouldn't cause any problems.
cat secure.example.signedkey >>../ns3/secure.example.db.signed

cp ../ns3/bogus.example.keyset .

echo $KEYSIGNER bogus.example.keyset $keyname
$KEYSIGNER bogus.example.keyset $keyname

# This will leave two copies of the child's zone key in the signed db file;
# that shouldn't cause any problems.
cat bogus.example.signedkey >>../ns3/bogus.example.db.signed

echo $KEYSETTOOL $keyname
$KEYSETTOOL $keyname

cat $infile $keyname.key >$zonefile

echo $SIGNER -o $zone $zonefile
$SIGNER -o $zone $zonefile


