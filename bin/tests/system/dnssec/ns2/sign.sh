#!/bin/sh

zone=example.
infile=example.db.in
zonefile=example.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

# Have the child generate a zone key and pass it to us,
# sign it, and pass it back

( cd ../ns3 && sh sign.sh )

cp ../ns3/secure.example.keyset .

$KEYSIGNER -v 9 secure.example.keyset $keyname

# This will leave two copies of the child's zone key in the signed db file;
# that shouldn't cause any problems.
cat secure.example.signedkey >>../ns3/secure.example.db.signed

$KEYSETTOOL $keyname

cat $infile $keyname.key >$zonefile

$SIGNER -v 1 -o $zone $zonefile

# Configure the resolving server with a trusted key.

cat $keyname.key | perl -n -e '
my ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
my $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' >../ns4/trusted.conf

