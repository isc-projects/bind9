#!/bin/sh

zone=example.
infile=example.db.in
zonefile=example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

# Have the child generate a zone key and pass it to us,
# sign it, and pass it back

( cd ../ns3 && sh sign.sh )

cp ../ns3/secure.example.keyset .

$KEYSIGNER secure.example.keyset $keyname

# This will leave two copies of the child's zone key in the signed db file;
# that shouldn't cause any problems.
cat secure.example.signedkey >>../ns3/secure.example.db.signed

cp ../ns3/bogus.example.keyset .

$KEYSIGNER bogus.example.keyset $keyname

# This will leave two copies of the child's zone key in the signed db file;
# that shouldn't cause any problems.
cat bogus.example.signedkey >>../ns3/bogus.example.db.signed

$KEYSETTOOL -t 3600 $keyname

cat $infile $keyname.key >$zonefile

$SIGNER -o $zone $zonefile


