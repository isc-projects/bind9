SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

test -f clean.sh && $SHELL clean.sh

test -r $RANDFILE || $GENRANDOM 800 $RANDFILE

copy_setports ns1/named.conf.in ns1/named.conf

cp -f ns1/signing.test.db.in ns1/signing.test.db
(cd ns1; $SHELL ./reset_keys.sh)
