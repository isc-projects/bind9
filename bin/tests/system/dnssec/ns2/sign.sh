#!/bin/sh
#
# Copyright (C) 2000  Internet Software Consortium.
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
# CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
# PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.

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


