#!/bin/sh

zone=.
infile=root.db.in
zonefile=root.db

keyname=`$KEYGEN -a RSA -b 768 -n zone $zone`

(cd ../ns2 && sh sign.sh )

cp ../ns2/example.keyset .

echo $KEYSIGNER example.keyset $keyname
$KEYSIGNER example.keyset $keyname

cat example.signedkey >> ../ns2/example.db.signed

echo $KEYSETTOOL $keyname
$KEYSETTOOL $keyname

cat $infile $keyname.key > $zonefile

echo $SIGNER -o $zone $zonefile
$SIGNER -o $zone $zonefile

# Configure the resolving server with a trusted key.

cat $keyname.key | perl -n -e '
my ($dn, $class, $type, $flags, $proto, $alg, @rest) = split;
my $key = join("", @rest);
print <<EOF
trusted-keys {
    "$dn" $flags $proto $alg "$key";
};
EOF
' > trusted.conf
cp trusted.conf ../ns2/trusted.conf
cp trusted.conf ../ns3/trusted.conf
cp trusted.conf ../ns4/trusted.conf
