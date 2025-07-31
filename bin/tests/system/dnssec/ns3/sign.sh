#!/bin/sh -e

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. ../../conf.sh

set -e

echo_i "ns3/sign.sh"

infile=key.db.in
for tld in managed trusted; do
  # A secure zone to test.
  zone=secure.${tld}
  zonefile=${zone}.db

  keyname1=$("$KEYGEN" -f KSK -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
  cat "$infile" "$keyname1.key" >"$zonefile"
  "$SIGNER" -z -P -3 - -o "$zone" -O full -f ${zonefile}.signed "$zonefile" >/dev/null

  # Zone to test trust anchor that matches disabled algorithm.
  zone=disabled.${tld}
  zonefile=${zone}.db

  keyname2=$("$KEYGEN" -f KSK -q -a "$DISABLED_ALGORITHM" -b "$DISABLED_BITS" "$zone")
  cat "$infile" "$keyname2.key" >"$zonefile"
  "$SIGNER" -z -P -3 - -o "$zone" -O full -f ${zonefile}.signed "$zonefile" >/dev/null

  # Zone to test trust anchor that has disabled algorithm for other domain.
  zone=enabled.${tld}
  zonefile=${zone}.db

  keyname3=$("$KEYGEN" -f KSK -q -a "$DISABLED_ALGORITHM" -b "$DISABLED_BITS" "$zone")
  cat "$infile" "$keyname3.key" >"$zonefile"
  "$SIGNER" -z -P -3 - -o "$zone" -O full -f ${zonefile}.signed "$zonefile" >/dev/null

  # Zone to test trust anchor with unsupported algorithm.
  zone=unsupported.${tld}
  zonefile=${zone}.db

  keyname4=$("$KEYGEN" -f KSK -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
  cat "$infile" "$keyname4.key" >"$zonefile"
  "$SIGNER" -z -3 - -o "$zone" -O full -f ${zonefile}.tmp "$zonefile" >/dev/null
  awk '$4 == "DNSKEY" { $7 = 255 } $4 == "RRSIG" { $6 = 255 } { print }' ${zonefile}.tmp >${zonefile}.signed

  # Make trusted-keys and managed keys conf sections for ns5/many_anchors.
  mv ${keyname4}.key ${keyname4}.tmp
  awk '$1 == "unsupported.'"${tld}"'." { $6 = 255 } { print }' ${keyname4}.tmp >${keyname4}.key

  # Zone to test trust anchor that is revoked.
  zone=revoked.${tld}
  zonefile=${zone}.db

  keyname5=$("$KEYGEN" -f KSK -f REVOKE -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
  cat "$infile" "$keyname5.key" >"$zonefile"
  "$SIGNER" -z -P -3 - -o "$zone" -O full -f ${zonefile}.signed "$zonefile" >/dev/null

  case $tld in
    "managed")
      keyfile_to_initial_keys $keyname1 $keyname2 $keyname3 $keyname4 $keyname5 >../ns5/many-managed.conf
      ;;
    "trusted")
      keyfile_to_static_keys $keyname1 $keyname2 $keyname3 $keyname4 $keyname5 >../ns5/many-trusted.conf
      ;;
  esac
done

echo_i "ns3/sign.sh: example zones"

# first set up some insecure zones:
cp template.db.in insecure.example.db
cp template.db.in insecure.below-cname.example.db
cp template.db.in insecure.nsec3.example.db
cp template.db.in insecure.optout.example.db
cp extrakey.example.db.in extrakey.example.db

# now the signed zones:
zone=secure.example.
infile=secure.example.db.in
zonefile=secure.example.db

cnameandkey=$("$KEYGEN" -T KEY -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "cnameandkey.$zone")
dnameandkey=$("$KEYGEN" -T KEY -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "dnameandkey.$zone")
keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$cnameandkey.key" "$dnameandkey.key" "$keyname.key" >"$zonefile"

"$SIGNER" -z -D -o "$zone" "$zonefile" >/dev/null
cat "$zonefile" "$zonefile".signed >"$zonefile".tmp
mv "$zonefile".tmp "$zonefile".signed

zone=bogus.example.
infile=template.db.in
zonefile=bogus.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

zone=dynamic.example.
infile=template.db.in
zonefile=dynamic.example.db

keyname1=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
keyname2=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")

cat "$infile" "$keyname1.key" "$keyname2.key" >"$zonefile"

"$SIGNER" -o "$zone" "$zonefile" >/dev/null

zone=keyless.example.
infile=template.db.in
zonefile=keyless.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

# Change the signer field of the a.b.keyless.example RRSIG A
# to point to a provably nonexistent DNSKEY record.
zonefiletmp=$(mktemp "$zonefile.XXXXXX") || exit 1
mv "$zonefile.signed" "$zonefiletmp"
"$PERL" <"$zonefiletmp" -p -e 's/ keyless.example/ b.keyless.example/
    if /^a.b.keyless.example/../A RRSIG NSEC/;' >"$zonefile.signed"
rm -f "$zonefiletmp"

#
#  NSEC3/NSEC test zone
#
zone=secure.nsec3.example.
infile=template.db.in
zonefile=secure.nsec3.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

#
#  NSEC3/NSEC3 test zone
#
zone=nsec3.nsec3.example.
infile=template.db.in
zonefile=nsec3.nsec3.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -o "$zone" "$zonefile" >/dev/null

#
#  OPTOUT/NSEC3 test zone
#
zone=optout.nsec3.example.
infile=template.db.in
zonefile=optout.nsec3.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -A -o "$zone" "$zonefile" >/dev/null

#
# A nsec3 zone (non-optout).
#
zone=nsec3.example.
infile=nsec3.example.db.in
zonefile=nsec3.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -g -3 - -o "$zone" "$zonefile" >/dev/null

#
#  OPTOUT/NSEC test zone
#
zone=secure.optout.example.
infile=template.db.in
zonefile=secure.optout.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

#
#  OPTOUT/NSEC3 test zone
#
zone=nsec3.optout.example.
infile=template.db.in
zonefile=nsec3.optout.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -o "$zone" "$zonefile" >/dev/null

#
#  OPTOUT/OPTOUT test zone
#
zone=optout.optout.example.
infile=template.db.in
zonefile=optout.optout.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -A -o "$zone" "$zonefile" >/dev/null

#
# A optout nsec3 zone.
#
zone=optout.example.
infile=optout.example.db.in
zonefile=optout.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -g -3 - -A -o "$zone" "$zonefile" >/dev/null

#
# A nsec3 zone (non-optout) with unknown nsec3 hash algorithm (-U).
#
zone=nsec3-unknown.example.
infile=template.db.in
zonefile=nsec3-unknown.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -PU -o "$zone" "$zonefile" >/dev/null

#
# A optout nsec3 zone with a unknown nsec3 hash algorithm (-U).
#
zone=optout-unknown.example.
infile=template.db.in
zonefile=optout-unknown.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -PU -A -o "$zone" "$zonefile" >/dev/null

#
# A zone that is signed with an unknown DNSKEY algorithm.
# Algorithm 7 is replaced by 100 in the zone and dsset.
#
zone=dnskey-unknown.example
infile=template.db.in
zonefile=dnskey-unknown.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -o "$zone" -O full -f ${zonefile}.tmp "$zonefile" >/dev/null

awk '$4 == "DNSKEY" { $7 = 100 } $4 == "RRSIG" { $6 = 100 } { print }' ${zonefile}.tmp >${zonefile}.signed

DSFILE="dsset-${zone}."
$DSFROMKEY -A -f ${zonefile}.signed "$zone" >"$DSFILE"

#
# A zone that is signed with an unsupported DNSKEY algorithm (3).
# Algorithm 7 is replaced by 255 in the zone and dsset.
#
zone=dnskey-unsupported.example
infile=template.db.in
zonefile=dnskey-unsupported.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -o "$zone" -O full -f ${zonefile}.tmp "$zonefile" >/dev/null

awk '$4 == "DNSKEY" { $7 = 255 } $4 == "RRSIG" { $6 = 255 } { print }' ${zonefile}.tmp >${zonefile}.signed

DSFILE="dsset-${zone}."
$DSFROMKEY -A -f ${zonefile}.signed "$zone" >"$DSFILE"

#
# A zone which uses an unsupported algorithm for a DNSKEY and an unsupported
# digest for another DNSKEY
#
zone=digest-alg-unsupported.example.
infile=template.db.in
zonefile=digest-alg-unsupported.example.db

cnameandkey=$("$KEYGEN" -T KEY -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "cnameandkey.$zone")
dnameandkey=$("$KEYGEN" -T KEY -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "dnameandkey.$zone")
keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
keyname2=$("$KEYGEN" -q -a ECDSAP384SHA384 -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$cnameandkey.key" "$dnameandkey.key" "$keyname.key" "$keyname2.key" >"$zonefile"

"$SIGNER" -z -D -o "$zone" "$zonefile" >/dev/null
cat "$zonefile" "$zonefile".signed >"$zonefile".tmp
mv "$zonefile".tmp "$zonefile".signed

# override generated DS record file so we can set different digest to each keys
DSFILE="dsset-${zone}"
$DSFROMKEY -a SHA-384 -A -f ${zonefile}.signed "$zone" | head -n 1 >"$DSFILE"
$DSFROMKEY -2 -A -f ${zonefile}.signed "$zone" | tail -1 >>"$DSFILE"

#
# A zone which is fine by itself (supported algorithm) but that is used
# to mimic unsupported DS digest (see ns5/many_anchors).
#
zone=ds-unsupported.example.
infile=template.db.in
zonefile=ds-unsupported.example.db

cnameandkey=$("$KEYGEN" -T KEY -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "cnameandkey.$zone")
dnameandkey=$("$KEYGEN" -T KEY -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "dnameandkey.$zone")
keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$cnameandkey.key" "$dnameandkey.key" "$keyname.key" >"$zonefile"

"$SIGNER" -z -D -o "$zone" "$zonefile" >/dev/null
cat "$zonefile" "$zonefile".signed >"$zonefile".tmp
mv "$zonefile".tmp "$zonefile".signed

#
# A zone with a published unsupported DNSKEY algorithm (Reserved).
# Different from above because this key is not intended for signing.
#
zone=dnskey-unsupported-2.example
infile=template.db.in
zonefile=dnskey-unsupported-2.example.db

ksk=$("$KEYGEN" -f KSK -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
zsk=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$ksk.key" "$zsk.key" unsupported-algorithm.key.in >"$zonefile"

"$SIGNER" -3 - -o "$zone" -f ${zonefile}.signed "$zonefile" >/dev/null

#
# A zone with a unknown DNSKEY algorithm + unknown NSEC3 hash algorithm (-U).
# Algorithm 7 is replaced by 100 in the zone and dsset.
#
zone=dnskey-nsec3-unknown.example
infile=template.db.in
zonefile=dnskey-nsec3-unknown.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -3 - -o "$zone" -PU -O full -f ${zonefile}.tmp "$zonefile" >/dev/null

awk '$4 == "DNSKEY" { $7 = 100; print } $4 == "RRSIG" { $6 = 100; print } { print }' ${zonefile}.tmp >${zonefile}.signed

DSFILE="dsset-${zone}."
$DSFROMKEY -A -f ${zonefile}.signed "$zone" >"$DSFILE"

#
# A multiple parameter nsec3 zone.
#
zone=multiple.example.
infile=template.db.in
zonefile=multiple.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -O full -o "$zone" "$zonefile" >/dev/null
awk '$4 == "NSEC" || ( $4 == "RRSIG" && $5 == "NSEC" ) { print }' "$zonefile".signed >NSEC.db
"$SIGNER" -z -O full -u3 - -o "$zone" "$zonefile" >/dev/null
awk '$4 == "NSEC3" || ( $4 == "RRSIG" && $5 == "NSEC3" ) { print }' "$zonefile".signed >NSEC3.db
"$SIGNER" -z -O full -u3 AAAA -o "$zone" "$zonefile" >/dev/null
awk '$4 == "NSEC3" || ( $4 == "RRSIG" && $5 == "NSEC3" ) { print }' "$zonefile".signed >>NSEC3.db
"$SIGNER" -z -O full -u3 BBBB -o "$zone" "$zonefile" >/dev/null
awk '$4 == "NSEC3" || ( $4 == "RRSIG" && $5 == "NSEC3" ) { print }' "$zonefile".signed >>NSEC3.db
"$SIGNER" -z -O full -u3 CCCC -o "$zone" "$zonefile" >/dev/null
awk '$4 == "NSEC3" || ( $4 == "RRSIG" && $5 == "NSEC3" ) { print }' "$zonefile".signed >>NSEC3.db
"$SIGNER" -z -O full -u3 DDDD -o "$zone" "$zonefile" >/dev/null
cat NSEC.db NSEC3.db >>"$zonefile".signed

#
# A RSASHA256 zone.
#
zone=rsasha256.example.
infile=template.db.in
zonefile=rsasha256.example.db

keyname=$("$KEYGEN" -q -a RSASHA256 "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null

#
# A RSASHA512 zone.
#
zone=rsasha512.example.
infile=template.db.in
zonefile=rsasha512.example.db

keyname=$("$KEYGEN" -q -a RSASHA512 "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null

#
# A RSASHA256OID zone.
#
zone=rsasha256oid.example.
infile=template.db.in
zonefile=rsasha256oid.example.db

keyname=$("$KEYGEN" -q -a RSASHA256OID "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

#
# A RSASHA512OID zone.
#
zone=rsasha512oid.example.
infile=template.db.in
zonefile=rsasha512oid.example.db

keyname=$("$KEYGEN" -q -a RSASHA512OID "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

#
# A UNKNOWNOID zone.  Sign the zone using RSASHA512OID then
# update the OID in the DNSKEY and RRSIGS to the unknown OID
# 1.2.840.113549.1.1.14
#
zone=unknownoid.example
infile=template.db.in
zonefile=unknownoid.example.db

keyname=$("$KEYGEN" -q -a RSASHA512OID "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

# Sign with known OID RSASHA512OID
"$SIGNER" -z -o "$zone" -f "${zonefile}.stage1" "$zonefile" >/dev/null

# Change OID from 1.2.840.113549.1.1.13 to 1.2.840.113549.1.1.14
sed 's/CwYJKoZIhvcN/CwYJKoZIhvcO/' <"${zonefile}.stage1" >"${zonefile}.stage2"

"$DSFROMKEY" -2A -f "${zonefile}.stage2" "$zone" >"dsset-${zone}."

# extract the updated DNSKEY's tag
tag=$(awk '{print $4}' "dsset-${zone}.")

# Update RRSIG tags
sed "s/\(2[0-9]* 2[0-9]*\) [1-9][0-9]* unknownoid.example./\1 ${tag} unknownoid.example./" <"${zonefile}.stage2" >"${zonefile}.signed"

#
# A PRIVATEOID zone with a extra DS record for a non-existent DNSKEY.
#
zone=extradsoid.example.
infile=template.db.in
zonefile=extradsoid.example.db

keyname=$("$KEYGEN" -q -a RSASHA512OID "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -z -o "$zone" "$zonefile" >/dev/null

# add a DS for a second key with the same algorithm
keyname=$("$KEYGEN" -q -a RSASHA512OID "$zone")

"$DSFROMKEY" -2A "$keyname.key" >>"dsset-$zone"

#
# A UNKNOWNOID with an extra DS zone.  Sign the zone using RSASHA512OID
# then update the OID in the DNSKEY and RRSIGS to the unknown OID
# 1.2.840.113549.1.1.14.  Add an additional DS which does not match
# the DNSKEY RRset with using this unknown OID.
#
zone=extradsunknownoid.example
infile=template.db.in
zonefile=extradsunknownoid.example.db

keyname=$("$KEYGEN" -q -a RSASHA512OID "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

# Sign with known OID RSASHA512OID
"$SIGNER" -z -o "$zone" -f "${zonefile}.stage1" "$zonefile" >/dev/null

# Change OID from 1.2.840.113549.1.1.13 to 1.2.840.113549.1.1.14
sed 's/CwYJKoZIhvcN/CwYJKoZIhvcO/' <"${zonefile}.stage1" >"${zonefile}.stage2"

"$DSFROMKEY" -2A -f "${zonefile}.stage2" "$zone" >"dsset-${zone}."
tag=$(awk '{print $4}' "dsset-${zone}.")

# Update RRSIG tags
sed "s/\(2[0-9]* 2[0-9]*\) [1-9][0-9]* extradsunknownoid.example./\1 ${tag} extradsunknownoid.example./" <"${zonefile}.stage2" >"${zonefile}.signed"

# add a DS for a second key with the same algorithm
keyname=$("$KEYGEN" -L 300 -q -a RSASHA512OID "$zone")

# Change OID from 1.2.840.113549.1.1.13 to 1.2.840.113549.1.1.14 and
# add the resulting DS to the dsset.
sed 's/CwYJKoZIhvcN/CwYJKoZIhvcO/' <"$keyname.key" | "$DSFROMKEY" -2A -f - "$zone" >>"dsset-${zone}."

#
# A UNKNOWNOID with an extra DS zone.  Sign the zone using RSASHA512OID
# then update the OID in the DNSKEY and RRSIGS to the unknown OID
# 1.2.840.113549.1.1.14.  Add an additional DS with an extended digest
# type that encoded the DNSKEY's private type identifier which does not
# match the DNSKEY RRset with using this unknown OID.
#
zone=extended-ds-unknown-oid.example
infile=template.db.in
zonefile=extended-ds-unknown-oid.example.db

keyname=$("$KEYGEN" -q -a RSASHA512OID "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

# Sign with known OID RSASHA512OID
"$SIGNER" -z -o "$zone" -f "${zonefile}.stage1" "$zonefile" >/dev/null

# Change OID from 1.2.840.113549.1.1.13 to 1.2.840.113549.1.1.14
sed 's/CwYJKoZIhvcN/CwYJKoZIhvcO/' <"${zonefile}.stage1" >"${zonefile}.stage2"

"$DSFROMKEY" -2A -f "${zonefile}.stage2" "$zone" >"dsset-${zone}."
tag=$(awk '{print $4}' "dsset-${zone}.")

# Update RRSIG tags
sed "s/\(2[0-9]* 2[0-9]*\) [1-9][0-9]* ${zone}./\1 ${tag} ${zone}./" <"${zonefile}.stage2" >"${zonefile}.signed"

if $FEATURETEST --extended-ds-digest; then
  # add a DS for a second key with the same algorithm
  keyname=$("$KEYGEN" -L 300 -q -a RSASHA512OID "$zone")

  # Change OID from 1.2.840.113549.1.1.13 to 1.2.840.113549.1.1.14 and
  # add the resulting DS using digest type SHA-256-PRIVATE to the dsset.
  sed 's/CwYJKoZIhvcN/CwYJKoZIhvcO/' <"$keyname.key" | "$DSFROMKEY" -a SHA-256-PRIVATE -A -f - "$zone" >>"dsset-${zone}."
fi

#
# A zone with the DNSKEY set only signed by the KSK
#
zone=kskonly.example.
infile=template.db.in
zonefile=kskonly.example.db

kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -x -o "$zone" "$zonefile" >/dev/null

#
# A zone with the expired signatures
#
zone=expired.example.
infile=template.db.in
zonefile=expired.example.db

kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -fk "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -P -o "$zone" -s -1d -e +1h "$zonefile" >/dev/null
rm -f "$kskname.*" "$zskname.*"

#
# A NSEC3 signed zone that will have a DNSKEY added to it via UPDATE.
#
zone=update-nsec3.example.
infile=template.db.in
zonefile=update-nsec3.example.db

kskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -fk "$zone")
zskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -P -3 - -o "$zone" "$zonefile" >/dev/null

#
# A NSEC signed zone that will have dnssec-policy enabled and
# extra keys not in the initial signed zone.
#
zone=auto-nsec.example.
infile=template.db.in
zonefile=auto-nsec.example.db

kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -fk "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
"$KEYGEN" -q -a "$ALTERNATIVE_ALGORITHM" -b "$ALTERNATIVE_BITS" -fk "$zone" >/dev/null
"$KEYGEN" -q -a "$ALTERNATIVE_ALGORITHM" -b "$ALTERNATIVE_BITS" "$zone" >/dev/null
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null

#
# A NSEC3 signed zone that will have dnssec-policy enabled and
# extra keys not in the initial signed zone.
#
zone=auto-nsec3.example.
infile=template.db.in
zonefile=auto-nsec3.example.db

kskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -fk "$zone")
zskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
"$KEYGEN" -q -a "$ALTERNATIVE_ALGORITHM" -b "$ALTERNATIVE_BITS" -fk "$zone" >/dev/null
"$KEYGEN" -q -a "$ALTERNATIVE_ALGORITHM" -b "$ALTERNATIVE_BITS" "$zone" >/dev/null
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -P -3 - -o "$zone" "$zonefile" >/dev/null

#
# Secure below cname test zone.
#
zone=secure.below-cname.example.
infile=template.db.in
zonefile=secure.below-cname.example.db
keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$keyname.key" >"$zonefile"
"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null

#
# Patched TTL test zone.
#
zone=ttlpatch.example.
infile=template.db.in
zonefile=ttlpatch.example.db
signedfile=ttlpatch.example.db.signed
patchedfile=ttlpatch.example.db.patched

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -P -f $signedfile -o "$zone" "$zonefile" >/dev/null
$CHECKZONE -D -s full "$zone" $signedfile 2>/dev/null \
  | awk '{$2 = "3600"; print}' >$patchedfile

#
# Separate DNSSEC records.
#
zone=split-dnssec.example.
infile=template.db.in
zonefile=split-dnssec.example.db
signedfile=split-dnssec.example.db.signed

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$keyname.key" >"$zonefile"
echo "\$INCLUDE \"$signedfile\"" >>"$zonefile"
: >"$signedfile"
"$SIGNER" -P -D -o "$zone" "$zonefile" >/dev/null

#
# Separate DNSSEC records smart signing.
#
zone=split-smart.example.
infile=template.db.in
zonefile=split-smart.example.db
signedfile=split-smart.example.db.signed

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cp "$infile" "$zonefile"
# shellcheck disable=SC2016
echo "\$INCLUDE \"$signedfile\"" >>"$zonefile"
: >"$signedfile"
"$SIGNER" -P -S -D -o "$zone" "$zonefile" >/dev/null

#
# Zone with signatures about to expire, but no private key to replace them
#
zone="expiring.example."
infile="template.db.in"
zonefile="expiring.example.db"
signedfile="expiring.example.db.signed"
kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
cp "$infile" "$zonefile"
"$SIGNER" -S -e now+1mi -o "$zone" "$zonefile" >/dev/null
mv -f "${zskname}.private" "${zskname}.private.moved"
mv -f "${kskname}.private" "${kskname}.private.moved"

#
# A zone where the signer's name has been forced to uppercase.
#
zone="upper.example."
infile="template.db.in"
zonefile="upper.example.db"
lower="upper.example.db.lower"
signedfile="upper.example.db.signed"
kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
cp "$infile" "$zonefile"
"$SIGNER" -P -S -o "$zone" -f "$lower" "$zonefile" >/dev/null
$CHECKZONE -D upper.example "$lower" 2>/dev/null \
  | sed '/RRSIG/s/ upper.example. / UPPER.EXAMPLE. /' >$signedfile

#
# Check that the signer's name is in lower case when zone name is in
# upper case.
#
zone="LOWER.EXAMPLE."
infile="template.db.in"
zonefile="lower.example.db"
signedfile="lower.example.db.signed"
sed -e 's/ns3/NS3/' -e 's/mname1/MNAME1/' "$infile" >"$zonefile"
kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
"$SIGNER" -P -S -o "$zone" "$zonefile" >/dev/null

#
# An inline signing zone
#
zone=inline.example.
cp template.db.in inline.example.db
kskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -fk "$zone")
zskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

#
# A zone which will change its signatures-validity
#
zone=siginterval.example
infile=template.db.in
zonefile=siginterval.example.db
kskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -fk "$zone")
zskname=$("$KEYGEN" -q -3 -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cp "$infile" "$zonefile"

#
# A zone with a bad DS in the parent
#
zone=badds.example.
infile=template.db.in
zonefile=badds.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null
sed -e 's/bogus/badds/g' <dsset-bogus.example. >dsset-badds.example.

#
# Same as badds, but locally trusted by the forwarder
#
zone=localkey.example.
infile=template.db.in
zonefile=localkey.example.db

keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

cat "$infile" "$keyname.key" >"$zonefile"

"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null
sed -e 's/bogus/localkey/g' <dsset-bogus.example. >dsset-localkey.example.
keyfile_to_static_keys $keyname >../ns9/trusted-localkey.conf

#
# A zone with future signatures.
#
zone=future.example
infile=template.db.in
zonefile=future.example.db
kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -P -s +3600 -o "$zone" "$zonefile" >/dev/null
cp -f "$kskname.key" trusted-future.key

#
# A zone with future signatures.
#
zone=managed-future.example
infile=template.db.in
zonefile=managed-future.example.db
kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$kskname.key" "$zskname.key" >"$zonefile"
"$SIGNER" -P -s +3600 -o "$zone" "$zonefile" >/dev/null

#
# A zone with a revoked key
#
zone=revkey.example.
infile=template.db.in
zonefile=revkey.example.db

ksk1=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -3fk "$zone")
ksk1=$("$REVOKE" "$ksk1")
ksk2=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -3fk "$zone")
zsk1=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -3 "$zone")

cat "$infile" "${ksk1}.key" "${ksk2}.key" "${zsk1}.key" >"$zonefile"
"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null

#
# Check that NSEC3 are correctly signed and returned from below a DNAME
#
zone=dname-at-apex-nsec3.example
infile=dname-at-apex-nsec3.example.db.in
zonefile=dname-at-apex-nsec3.example.db

kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -3fk "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -3 "$zone")
cat "$infile" "${kskname}.key" "${zskname}.key" >"$zonefile"
"$SIGNER" -P -3 - -o "$zone" "$zonefile" >/dev/null

#
# A NSEC zone with occluded data at the delegation
#
zone=occluded.example
infile=occluded.example.db.in
zonefile=occluded.example.db
kskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -fk "$zone")
zskname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" "$zone")
dnskeyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -fk "delegation.$zone")
keyname=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -T KEY "delegation.$zone")
$DSFROMKEY "$dnskeyname.key" >"dsset-delegation.${zone}."
cat "$infile" "${kskname}.key" "${zskname}.key" "${keyname}.key" \
  "${dnskeyname}.key" "dsset-delegation.${zone}." >"$zonefile"
"$SIGNER" -P -o "$zone" "$zonefile" >/dev/null

#
# Pre-signed zone for FIPS validation of RSASHA1 signed zones
# See sign-rsasha1.sh for how to regenerate rsasha1.example.db
# with non-FIPS compliant instance.
#
# We only need to generate the dsset.
#
zone=rsasha1.example
infile=rsasha1.example.db.in
zonefile=rsasha1.example.db
cp $infile $zonefile
awk '$4 == "DNSKEY" && $5 == 257 { print }' "$zonefile" \
  | $DSFROMKEY -f - "$zone" >"dsset-${zone}."

zone=rsasha1-1024.example
infile=rsasha1-1024.example.db.in
zonefile=rsasha1-1024.example.db
cp $infile $zonefile
awk '$4 == "DNSKEY" && $5 == 257 { print }' "$zonefile" \
  | $DSFROMKEY -f - "$zone" >"dsset-${zone}."

#
#
#
zone=target.peer-ns-spoof
infile=target.peer-ns-spoof.db.in
zonefile=target.peer-ns-spoof.db
ksk=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" -f KSK "$zone")
zsk=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$ksk.key" "$zsk.key" >"$zonefile"
"$SIGNER" -g -o "$zone" "$zonefile" >/dev/null 2>&1
