#!/bin/sh

zone=example.
infile=example.db.in
zonefile=example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

tag=`echo $keykname | sed -n 's/^.*\+\([0-9][0-9]*\)$/\1/p'`

echo "key=$keyname, tag=$tag"

# Have the child generate a zone key and pass it to us,
# sign it, and pass it back

( cd ../ns3 && sh sign.sh )
cp ../ns3/secure.example.keyset .
/local/bind9/bin/tests/keysigner -v 9 secure.example.keyset example./$tag/001
# This will leave two copies of the child's zone key in the signed db file;
# that shouldn't cause any problems.
cat secure.example.signedkey >>../ns3/secure.example.db.signed

pubkeyfile="$keyname.key"

$KEYSETTOOL $zone $tag/001

cat $infile $pubkeyfile >$zonefile

$SIGNER -v 1 -o $zone $zonefile

# Configure the resolving server with a trusted key.

cat $pubkeyfile | perl -n -e '
my ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
my $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' >../ns4/trusted.conf

